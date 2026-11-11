import json
from dataclasses import replace

import anthropic
import httpx2
import pytest

from app.llm.anthropic_provider import FALLBACK_BETA, AnthropicProvider
from app.llm.provider import MissingAPIKey, ProviderError
from app.llm.types import Attempt, LLMRequest, Message, StopReason, Usage

REQUEST = LLMRequest(
    model="claude-opus-5-5",
    messages=(Message("system", "Decide."), Message("user", '<data id="1">...</data id="1">')),
    max_tokens=1000,
    effort="medium",
)
USAGE = {
    "input_tokens": 1200,
    "output_tokens": 300,
    "cache_creation_input_tokens": 0,
    "cache_read_input_tokens": 0,
}


def message(**fields) -> dict:
    body = {
        "id": "msg_01",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-5-5",
        "content": [
            {"type": "thinking", "thinking": "", "signature": "sig"},
            {"type": "text", "text": "true positive"},
        ],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": USAGE,
    }
    return body | fields


def provider_answering(status: int, body: dict, sent: list[httpx2.Request]) -> AnthropicProvider:
    def handler(request: httpx2.Request) -> httpx2.Response:
        sent.append(request)
        return httpx2.Response(status, json=body, headers={"request-id": "req_123"})

    client = anthropic.Anthropic(
        api_key="test-key",
        max_retries=0,
        http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(handler)),
    )
    return AnthropicProvider(client)


def test_the_request_has_the_system_prompt_and_effort_and_no_temperature():
    sent: list[httpx2.Request] = []

    provider_answering(200, message(), sent).complete(REQUEST)

    body = json.loads(sent[0].content)
    assert body["model"] == "claude-opus-5-5"
    assert body["system"] == "Decide."
    assert body["messages"] == [{"role": "user", "content": REQUEST.messages[1].content}]
    assert body["max_tokens"] == 1000
    assert body["output_config"] == {"effort": "medium"}
    assert "temperature" not in body
    assert "fallbacks" not in body


def test_the_response_gives_text_model_version_and_usage():
    response = provider_answering(200, message(), []).complete(REQUEST)

    assert response.text == "true positive"
    assert response.model_version == "claude-opus-5-5"
    assert response.stop_reason is StopReason.COMPLETE
    assert response.attempts == (Attempt("claude-opus-5-5", Usage(1200, 300)),)
    assert response.request_id == "req_123"


def test_fallbacks_are_requested_and_every_attempt_is_reported():
    sent: list[httpx2.Request] = []
    declined = USAGE | {"type": "message", "model": "claude-opus-5-5", "output_tokens": 0}
    served = USAGE | {"type": "fallback_message", "model": "claude-opus-4-8"}
    body = message(
        model="claude-opus-4-8",
        content=[
            {
                "type": "fallback",
                "from": {"model": "claude-opus-5-5"},
                "to": {"model": "claude-opus-4-8"},
                "trigger": {"type": "refusal", "category": "cyber"},
            },
            {"type": "text", "text": "true positive"},
        ],
        usage=USAGE | {"iterations": [declined, served]},
    )

    response = provider_answering(200, body, sent).complete(replace(REQUEST, server_fallbacks=True))

    assert json.loads(sent[0].content)["fallbacks"] == "default"
    assert FALLBACK_BETA in sent[0].headers["anthropic-beta"]
    assert response.text == "true positive"
    assert response.model_version == "claude-opus-4-8"
    assert response.attempts == (
        Attempt("claude-opus-5-5", Usage(1200, 0)),
        Attempt("claude-opus-4-8", Usage(1200, 300)),
    )


def test_a_refusal_is_reported_as_one():
    body = message(
        content=[],
        stop_reason="refusal",
        stop_details={"type": "refusal", "category": "cyber", "explanation": "declined"},
    )

    response = provider_answering(200, body, []).complete(REQUEST)

    assert response.stop_reason is StopReason.REFUSAL
    assert response.text == ""


@pytest.mark.parametrize(
    ("status", "retryable"), [(400, False), (401, False), (429, True), (529, True)]
)
def test_api_errors_say_whether_a_retry_can_help(status, retryable):
    error = {"type": "error", "error": {"type": "some_error", "message": "no"}}

    with pytest.raises(ProviderError) as raised:
        provider_answering(status, error, []).complete(REQUEST)

    assert raised.value.retryable is retryable


def test_the_key_comes_only_from_the_environment(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(MissingAPIKey, match="ANTHROPIC_API_KEY"):
        AnthropicProvider()

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    assert AnthropicProvider().name == "anthropic"


def test_requests_go_to_the_anthropic_api_whatever_anthropic_base_url_says(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://proxy.example")

    client = AnthropicProvider()._client

    assert str(client.base_url).rstrip("/") == "https://api.anthropic.com"


def test_the_provider_refuses_to_start_while_custom_headers_are_set(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ANTHROPIC_CUSTOM_HEADERS", "x-api-key: another-key")

    with pytest.raises(ProviderError, match="unset ANTHROPIC_CUSTOM_HEADERS") as raised:
        AnthropicProvider()

    assert raised.value.retryable is False


def test_an_account_without_credit_says_so():
    message = "Your credit balance is too low to access the Anthropic API."
    error = {"type": "error", "error": {"type": "invalid_request_error", "message": message}}

    with pytest.raises(ProviderError, match="out of credit") as raised:
        provider_answering(400, error, []).complete(REQUEST)

    assert raised.value.retryable is False
