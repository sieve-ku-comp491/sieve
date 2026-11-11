from decimal import Decimal

import pytest

from app.llm.budget import Budget, BudgetExceeded
from app.llm.cache import InMemoryResponseCache
from app.llm.call_log import InMemoryCallLog
from app.llm.catalog import Catalog, ModelInfo, Price, load_catalog
from app.llm.client import LLMClient, load_provider_class, providers_from_env
from app.llm.fake import FakeProvider
from app.llm.provider import ProviderError
from app.llm.templates import PromptTemplate
from app.llm.types import Attempt, CodeBlock, Message, StopReason, Usage

TEMPLATE = PromptTemplate(name="check", version="v1", text="Decide whether the finding is real.")
CODE = [CodeBlock("app/views.py", 52, 59, "cursor.execute(query % name)")]
JOB_ID = "5b3f6a3e-0000-4000-8000-000000000000"
PRICE = Price(
    input=Decimal("1.00"),
    output=Decimal("2.00"),
    cache_read=Decimal("0.10"),
    cache_write=Decimal("1.25"),
)


def make_client(
    provider: FakeProvider | None = None, budget: str = "1.00", temperature: bool = False
) -> tuple[LLMClient, FakeProvider, InMemoryCallLog]:
    provider = provider or FakeProvider()
    model = ModelInfo("fake-model", "fake", PRICE, temperature=temperature)
    log = InMemoryCallLog()
    client = LLMClient(
        providers={"fake": provider},
        catalog=Catalog({"fake-model": model}, checked_on="test"),
        budget=Budget(budget),
        call_log=log,
        cache=InMemoryResponseCache(),
        job_id=JOB_ID,
    )
    return client, provider, log


def ask(client: LLMClient, rule: str = "python.sqli", **kwargs):
    return client.ask(TEMPLATE, {"rule": rule}, CODE, model="fake-model", max_tokens=1000, **kwargs)


def test_a_call_is_logged_with_its_prompt_response_model_tokens_and_cost():
    provider = FakeProvider(
        replies=["true positive"], usage=Usage(input_tokens=1000, output_tokens=500)
    )
    client, provider, log = make_client(provider)

    response = ask(client)

    assert response.text == "true positive"
    assert response.cost_usd == (1000 * Decimal(1) + 500 * Decimal(2)) / 1_000_000
    [record] = log.records
    assert record.id == response.call_id
    assert record.messages == provider.requests[0].messages
    assert record.response_text == "true positive"
    assert record.model_version == "fake-model-fake"
    assert record.usage == Usage(input_tokens=1000, output_tokens=500)
    assert record.cost_usd == response.cost_usd
    assert record.cached is False
    assert record.duration_ms >= 0
    assert (record.template_name, record.template_version) == ("check", "v1")
    assert record.job_id == JOB_ID


def test_a_repeated_request_is_answered_from_the_cache():
    client, provider, log = make_client()

    first = ask(client)
    second = ask(client)

    assert len(provider.requests) == 1
    assert second.text == first.text
    assert second.cached is True and second.cost_usd == 0
    assert [record.cached for record in log.records] == [False, True]
    assert log.records[1].usage == Usage()
    assert client.budget.spent_usd == first.cost_usd


def test_a_different_finding_is_not_a_cache_hit():
    client, provider, _ = make_client()

    ask(client, rule="python.sqli")
    ask(client, rule="python.xss")

    assert len(provider.requests) == 2


@pytest.mark.parametrize("stop_reason", [StopReason.MAX_TOKENS, StopReason.REFUSAL])
def test_incomplete_answers_are_not_cached(stop_reason):
    client, provider, log = make_client(FakeProvider(stop_reason=stop_reason))

    ask(client)
    ask(client)

    assert len(provider.requests) == 2
    assert not any(record.cached for record in log.records)


def test_a_complete_answer_without_text_is_not_cached():
    client, provider, log = make_client(FakeProvider(replies=["", " \n"]))

    ask(client)
    ask(client)

    assert len(provider.requests) == 2
    assert not any(record.cached for record in log.records)


def test_nothing_is_sent_when_the_worst_case_does_not_fit():
    client, provider, log = make_client(budget="0.0001")

    with pytest.raises(BudgetExceeded):
        ask(client)

    assert provider.requests == []
    assert log.records == []
    assert client.budget.spent_usd == 0


def test_the_run_stops_when_the_next_call_would_go_over_the_budget():
    provider = FakeProvider(usage=Usage(input_tokens=200, output_tokens=1000))
    client, provider, _ = make_client(provider)
    request = client.build_request(
        TEMPLATE, {"rule": "a"}, CODE, model="fake-model", max_tokens=1000
    )
    worst = client.catalog.worst_case_cost(client.catalog.get("fake-model"), request)
    cost = client.catalog.cost("fake", (Attempt("fake-model", provider.usage),))
    # Room for one call and a little more, but not for a second worst case.
    client.budget = Budget(cost + worst - Decimal("0.000001"))

    ask(client, rule="a")
    with pytest.raises(BudgetExceeded):
        ask(client, rule="b")

    assert len(provider.requests) == 1
    assert client.budget.spent_usd == cost
    assert client.budget.spent_usd <= client.budget.limit_usd


def test_temperature_is_zero_only_for_models_that_accept_it():
    client, provider, _ = make_client(temperature=True)
    ask(client)
    assert provider.requests[0].temperature == 0.0

    client, provider, _ = make_client(temperature=False)
    ask(client)
    assert provider.requests[0].temperature is None


def test_a_failed_call_is_logged_and_costs_nothing():
    error = ProviderError("Anthropic API error 529: overloaded", retryable=True)
    client, _, log = make_client(FakeProvider(error=error))

    with pytest.raises(ProviderError):
        ask(client)

    assert client.budget.spent_usd == 0
    assert client.budget.remaining_usd == Decimal("1.00")
    [record] = log.records
    assert record.error == "ProviderError: Anthropic API error 529: overloaded"
    assert record.response_text is None


class BrokenCallLog:
    def record(self, record):
        raise RuntimeError("the database is down")


def test_a_paid_answer_is_returned_when_the_call_log_cannot_be_written(caplog):
    client, provider, _ = make_client(FakeProvider(replies=["true positive"]))
    client.call_log = BrokenCallLog()

    response = ask(client)

    assert response.text == "true positive"
    assert client.budget.spent_usd == response.cost_usd > 0
    assert "the database is down" in caplog.text
    assert f"could not write call {response.call_id}" in caplog.text
    assert "true positive" in caplog.text


def test_a_failed_call_keeps_its_own_error_when_the_call_log_cannot_be_written(caplog):
    error = ProviderError("Anthropic API error 529: overloaded", retryable=True)
    client, _, _ = make_client(FakeProvider(error=error))
    client.call_log = BrokenCallLog()

    with pytest.raises(ProviderError) as raised:
        ask(client)

    assert raised.value is error
    assert raised.value.retryable is True
    assert "the database is down" in caplog.text


def test_a_model_without_a_provider_gives_a_clear_error():
    client, _, _ = make_client()
    client.providers = {}

    with pytest.raises(ProviderError, match="no fake provider"):
        ask(client)


def test_history_goes_between_the_instructions_and_the_new_data():
    client, provider, _ = make_client()
    earlier = (Message("user", "the first data block"), Message("assistant", "I need the caller."))

    ask(client, history=earlier)

    assert [m.role for m in provider.requests[0].messages] == [
        "system",
        "user",
        "assistant",
        "user",
    ]


def test_a_provider_is_set_up_only_when_its_api_key_is_set(monkeypatch):
    catalog = Catalog({}, checked_on="test", providers={"fake": "app.llm.fake:FakeProvider"})

    monkeypatch.delenv("FAKE_API_KEY", raising=False)
    assert providers_from_env(catalog) == {}

    monkeypatch.setenv("FAKE_API_KEY", "test-key")
    assert isinstance(providers_from_env(catalog)["fake"], FakeProvider)


def test_a_provider_listed_under_the_wrong_name_is_refused():
    catalog = Catalog({}, checked_on="test", providers={"other": "app.llm.fake:FakeProvider"})

    with pytest.raises(ValueError, match="its name is fake"):
        providers_from_env(catalog)


def test_every_provider_in_models_json_can_be_set_up(monkeypatch):
    catalog = load_catalog()
    for target in catalog.providers.values():
        monkeypatch.setenv(load_provider_class(target).api_key_variable, "test-key")

    assert set(providers_from_env(catalog)) == set(catalog.providers)
