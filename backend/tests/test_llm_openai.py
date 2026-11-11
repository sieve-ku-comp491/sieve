import json
from dataclasses import replace
from decimal import Decimal

import httpx2
import openai
import pytest

from app.llm.catalog import load_catalog
from app.llm.openai_provider import OPENAI_SDK_VARIABLES, OpenAIProvider
from app.llm.provider import MissingAPIKey, ProviderError
from app.llm.types import Attempt, LLMRequest, Message, StopReason, Usage

REQUEST = LLMRequest(
    model="gpt-5.4-mini",
    messages=(Message("system", "Decide."), Message("user", '<data id="1">...</data id="1">')),
    max_tokens=1000,
    effort="low",
)
ANSWER = {
    "type": "message",
    "id": "msg_1",
    "status": "completed",
    "role": "assistant",
    "content": [{"type": "output_text", "text": "true positive", "annotations": []}],
}


def response(**fields) -> dict:
    body = {
        "id": "resp_1",
        "object": "response",
        "created_at": 1_800_000_000,
        "model": "gpt-5.4-mini-2026-03-17",
        "status": "completed",
        "incomplete_details": None,
        "error": None,
        "output": [{"type": "reasoning", "id": "rs_1", "summary": []}, ANSWER],
        "usage": {
            "input_tokens": 1500,
            "input_tokens_details": {"cached_tokens": 1000, "cache_write_tokens": 300},
            "output_tokens": 400,
            "output_tokens_details": {"reasoning_tokens": 250},
            "total_tokens": 1900,
        },
        "parallel_tool_calls": True,
        "tool_choice": "auto",
        "tools": [],
    }
    return body | fields


def provider_answering(status: int, body: dict, sent: list[httpx2.Request]) -> OpenAIProvider:
    def handler(request: httpx2.Request) -> httpx2.Response:
        sent.append(request)
        return httpx2.Response(status, json=body, headers={"x-request-id": "req_456"})

    client = openai.OpenAI(
        api_key="test-key",
        max_retries=0,
        http_client=openai.DefaultHttpx2Client(transport=httpx2.MockTransport(handler)),
    )
    return OpenAIProvider(client)


def test_the_request_uses_instructions_effort_and_store_false():
    sent: list[httpx2.Request] = []

    provider_answering(200, response(), sent).complete(REQUEST)

    body = json.loads(sent[0].content)
    assert body["model"] == "gpt-5.4-mini"
    assert body["instructions"] == "Decide."
    assert body["input"] == [{"role": "user", "content": REQUEST.messages[1].content}]
    assert body["max_output_tokens"] == 1000
    assert body["reasoning"] == {"effort": "low"}
    assert body["store"] is False
    assert "temperature" not in body


def test_temperature_is_sent_when_the_request_has_one():
    sent: list[httpx2.Request] = []

    provider_answering(200, response(), sent).complete(replace(REQUEST, temperature=0.0))

    assert json.loads(sent[0].content)["temperature"] == 0.0


def test_the_response_gives_text_snapshot_and_usage_split_by_price():
    result = provider_answering(200, response(), []).complete(REQUEST)

    assert result.text == "true positive"
    assert result.model_version == "gpt-5.4-mini-2026-03-17"
    assert result.stop_reason is StopReason.COMPLETE
    # input_tokens (1500) already includes the 1000 cache reads and the 300 cache writes.
    assert result.attempts == (
        Attempt(
            "gpt-5.4-mini-2026-03-17",
            Usage(
                input_tokens=200, output_tokens=400, cache_read_tokens=1000, cache_write_tokens=300
            ),
        ),
    )
    assert result.request_id == "req_456"


@pytest.mark.parametrize(
    ("fields", "stop_reason"),
    [
        (
            {"status": "incomplete", "incomplete_details": {"reason": "max_output_tokens"}},
            StopReason.MAX_TOKENS,
        ),
        (
            {"status": "incomplete", "incomplete_details": {"reason": "content_filter"}},
            StopReason.REFUSAL,
        ),
        (
            {"output": [ANSWER | {"content": [{"type": "refusal", "refusal": "I can't help."}]}]},
            StopReason.REFUSAL,
        ),
    ],
)
def test_cut_off_and_refused_answers_are_reported(fields, stop_reason):
    result = provider_answering(200, response(**fields), []).complete(REQUEST)

    assert result.stop_reason is stop_reason


@pytest.mark.parametrize(
    ("status", "retryable"), [(400, False), (401, False), (429, True), (500, True)]
)
def test_api_errors_say_whether_a_retry_can_help(status, retryable):
    error = {"error": {"message": "no", "type": "some_error", "code": None, "param": None}}

    with pytest.raises(ProviderError) as raised:
        provider_answering(status, error, []).complete(REQUEST)

    assert raised.value.retryable is retryable


def test_the_key_comes_only_from_the_environment(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(MissingAPIKey, match="OPENAI_API_KEY"):
        OpenAIProvider()

    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    assert OpenAIProvider().name == "openai"


def test_requests_go_to_the_openai_api_whatever_openai_base_url_says(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://proxy.example/v1")

    client = OpenAIProvider()._client

    assert str(client.base_url).rstrip("/") == "https://api.openai.com/v1"


@pytest.mark.parametrize("variable", OPENAI_SDK_VARIABLES)
def test_the_provider_refuses_to_start_while_an_sdk_header_variable_is_set(variable, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv(variable, "Authorization: Bearer another-key")

    with pytest.raises(ProviderError, match=f"unset {variable}") as raised:
        OpenAIProvider()

    assert raised.value.retryable is False


def test_the_gpt_models_are_in_models_json():
    catalog = load_catalog()

    assert {"gpt-5.5", "gpt-5.4-mini"} <= set(catalog.names())
    assert catalog.get("gpt-5.4-mini").provider == "openai"


def test_gpt_5_5_charges_more_once_the_prompt_passes_272k_tokens():
    gpt = load_catalog().get("gpt-5.5")

    assert gpt.cost(Usage(input_tokens=272_000)) == Decimal("1.36")
    assert gpt.cost(Usage(input_tokens=272_001)) == 272_001 * Decimal("10.00") / 1_000_000


def test_gpt_models_charge_cache_writes_at_the_input_price():
    # Only GPT-5.6 and later charge extra for cache writes.
    for name in ("gpt-5.5", "gpt-5.4-mini"):
        info = load_catalog().get(name)
        written = info.cost(Usage(cache_write_tokens=100_000))
        assert written == info.cost(Usage(input_tokens=100_000))


def test_an_answer_from_a_snapshot_is_charged_at_its_model_price():
    catalog = load_catalog()
    result = provider_answering(200, response(), []).complete(REQUEST)

    # The answer names gpt-5.4-mini-2026-03-17, which is priced as gpt-5.4-mini.
    expected = catalog.get("gpt-5.4-mini").cost(result.usage)
    assert catalog.cost("openai", result.attempts) == expected


def test_an_account_without_credit_is_not_a_rate_limit():
    message = "You exceeded your current quota, please check your plan and billing details."
    error = {
        "error": {"message": message, "type": "insufficient_quota", "code": None, "param": None}
    }

    with pytest.raises(ProviderError, match="out of credit") as raised:
        provider_answering(429, error, []).complete(REQUEST)

    assert raised.value.retryable is False
