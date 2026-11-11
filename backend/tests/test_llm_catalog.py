import json
from decimal import Decimal

import pytest

from app.llm.catalog import UnknownModel, input_token_upper_bound, load_catalog
from app.llm.types import Attempt, LLMRequest, Message, Usage

MILLION = 1_000_000
PRICE = {"input": "1.00", "output": "2.00", "cache_read": "0.10", "cache_write": "1.25"}


def request(model: str, *, text: str = "x" * 1000, fallbacks: bool = False) -> LLMRequest:
    return LLMRequest(
        model=model,
        messages=(Message("system", "rules"), Message("user", text)),
        max_tokens=1000,
        server_fallbacks=fallbacks,
    )


def write_models(tmp_path, models: dict, providers: dict | None = None):
    path = tmp_path / "models.json"
    data = {
        "checked_on": "test",
        "providers": {"fake": "app.llm.fake:FakeProvider"} if providers is None else providers,
        "models": models,
    }
    path.write_text(json.dumps(data))
    return path


def test_every_model_in_models_json_has_a_listed_provider_and_prices():
    catalog = load_catalog()

    assert catalog.checked_on
    assert {"claude-opus-5-5", "claude-haiku-5-5"} <= set(catalog.names())
    for name in catalog.names():
        info = catalog.get(name)
        assert info.provider in catalog.providers
        assert info.price.input > 0 and info.price.output > 0


def test_a_model_of_an_unlisted_provider_is_refused(tmp_path):
    path = write_models(tmp_path, {"m": {"provider": "other", "price": PRICE}})

    with pytest.raises(ValueError, match='not listed under "providers"'):
        load_catalog(path)


def test_a_model_without_all_four_prices_is_refused(tmp_path):
    price = {"input": "1.00", "output": "2.00"}
    path = write_models(tmp_path, {"m": {"provider": "fake", "price": price}})

    with pytest.raises(ValueError, match="m in models.json has no cache_read or cache_write price"):
        load_catalog(path)


def test_cost_counts_input_output_cache_reads_and_cache_writes():
    opus = load_catalog().get("claude-opus-5-5")
    usage = Usage(
        input_tokens=MILLION,
        output_tokens=MILLION,
        cache_read_tokens=MILLION,
        cache_write_tokens=MILLION,
    )

    expected = Decimal("4.00") + Decimal("20.00") + Decimal("0.20") + Decimal("5.00")
    assert opus.cost(usage) == expected


def test_haiku_charges_more_once_the_prompt_passes_100k_tokens():
    haiku = load_catalog().get("claude-haiku-5-5")

    at_limit = haiku.cost(Usage(input_tokens=100_000))
    # Cache reads count toward the prompt length too.
    over_limit = haiku.cost(Usage(input_tokens=90_000, cache_read_tokens=10_001))

    assert at_limit == Decimal("0.01")
    assert over_limit == (90_000 * Decimal("0.50") + 10_001 * Decimal("0.05")) / MILLION


def test_an_unknown_model_says_where_to_add_it():
    with pytest.raises(UnknownModel, match="models.json"):
        load_catalog().get("claude-99")


def test_each_attempt_is_charged_at_its_own_model_price():
    attempts = (
        Attempt("claude-opus-5-5", Usage(input_tokens=1000)),
        Attempt("claude-opus-4-8", Usage(input_tokens=1000, output_tokens=500)),
    )

    expected = (1000 * Decimal(4) + 1000 * Decimal(5) + 500 * Decimal(25)) / MILLION
    assert load_catalog().cost("anthropic", attempts) == expected


def test_a_model_without_a_price_is_charged_at_the_highest_price():
    attempt = Attempt("claude-not-in-the-catalog", Usage(output_tokens=MILLION))

    assert load_catalog().cost("anthropic", (attempt,)) == Decimal("25.00")


def test_the_input_bound_counts_bytes_not_characters():
    # "é" is one character and two bytes in UTF-8.
    accented = request("claude-haiku-5-5", text="é" * 10)

    assert input_token_upper_bound(accented) >= len("rules") + 2 * 10


def test_the_worst_case_covers_a_full_answer():
    catalog = load_catalog()
    info = catalog.get("claude-sonnet-5-5")
    req = request("claude-sonnet-5-5")

    full_answer = Usage(input_tokens=input_token_upper_bound(req), output_tokens=req.max_tokens)
    assert catalog.worst_case_cost(info, req) >= info.cost(full_answer)


def test_fallbacks_add_a_second_attempt_to_the_worst_case():
    catalog = load_catalog()
    info = catalog.get("claude-opus-5-5")

    single = catalog.worst_case_cost(info, request("claude-opus-5-5"))
    with_fallbacks = catalog.worst_case_cost(info, request("claude-opus-5-5", fallbacks=True))

    assert with_fallbacks >= 2 * single


def test_the_worst_case_covers_a_decline_partway_through_the_answer():
    catalog = load_catalog()
    info = catalog.get("claude-opus-5-5")
    req = request("claude-opus-5-5", fallbacks=True)
    prompt = input_token_upper_bound(req)

    declined = info.cost(Usage(input_tokens=prompt, output_tokens=req.max_tokens))
    # The substitute model reads the prompt and the partial answer, then writes a full answer.
    substitute = catalog.ceiling_price("anthropic").cost(
        Usage(input_tokens=prompt + req.max_tokens, output_tokens=req.max_tokens)
    )
    assert catalog.worst_case_cost(info, req) >= declined + substitute
