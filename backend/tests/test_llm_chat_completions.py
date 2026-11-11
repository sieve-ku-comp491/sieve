import json
from dataclasses import replace
from decimal import Decimal

import httpx2
import openai
import pytest

from app.llm.catalog import load_catalog
from app.llm.deepseek_provider import DeepSeekProvider
from app.llm.glm_provider import GLMProvider
from app.llm.kimi_provider import KimiProvider
from app.llm.provider import MissingAPIKey, ProviderError
from app.llm.qwen_provider import QwenProvider
from app.llm.types import Attempt, LLMRequest, Message, StopReason, Usage

PROVIDERS = [DeepSeekProvider, QwenProvider, GLMProvider, KimiProvider]
MODELS = {
    DeepSeekProvider: "deepseek-v4-pro",
    QwenProvider: "qwen3.8-max",
    GLMProvider: "glm-5.3",
    KimiProvider: "kimi-k3.1-pro",
}
DATA = '<data id="1">...</data id="1">'


def request_for(provider_class, **fields) -> LLMRequest:
    request = LLMRequest(
        model=MODELS[provider_class],
        messages=(Message("system", "Decide."), Message("user", DATA)),
        max_tokens=1000,
    )
    return replace(request, **fields)


def completion(model: str = "deepseek-v4-pro", **fields) -> dict:
    body = {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 1_800_000_000,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "true positive"},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 1500,
            "completion_tokens": 400,
            "total_tokens": 1900,
            "prompt_tokens_details": {"cached_tokens": 1000},
            "completion_tokens_details": {"reasoning_tokens": 250},
        },
    }
    return body | fields


def answering(provider_class, status: int, body: dict, sent: list[httpx2.Request]):
    def handler(request: httpx2.Request) -> httpx2.Response:
        sent.append(request)
        return httpx2.Response(status, json=body, headers={"x-request-id": "req_789"})

    client = openai.OpenAI(
        api_key="test-key",
        base_url=provider_class.resolved_base_url(),
        max_retries=0,
        http_client=openai.DefaultHttpx2Client(transport=httpx2.MockTransport(handler)),
    )
    return provider_class(client)


def sent_body(provider_class, **fields) -> dict:
    sent: list[httpx2.Request] = []
    model = MODELS[provider_class]
    answering(provider_class, 200, completion(model), sent).complete(
        request_for(provider_class, **fields)
    )
    return json.loads(sent[0].content)


@pytest.mark.parametrize("provider_class", PROVIDERS)
def test_the_instructions_go_first_as_a_system_message(provider_class):
    body = sent_body(provider_class)

    assert body["model"] == MODELS[provider_class]
    assert body["messages"] == [
        {"role": "system", "content": "Decide."},
        {"role": "user", "content": DATA},
    ]
    # Thinking and answer together stay within the request's max_tokens.
    assert body[provider_class.max_tokens_field] + body.get("thinking_budget", 0) == 1000


@pytest.mark.parametrize(
    ("provider_class", "url"),
    [
        (DeepSeekProvider, "https://api.deepseek.com/chat/completions"),
        (QwenProvider, "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions"),
        (GLMProvider, "https://api.z.ai/api/paas/v4/chat/completions"),
        (KimiProvider, "https://api.moonshot.ai/v1/chat/completions"),
    ],
)
def test_each_provider_calls_its_own_api(provider_class, url, monkeypatch):
    monkeypatch.delenv("DASHSCOPE_BASE_URL", raising=False)
    sent: list[httpx2.Request] = []

    answering(provider_class, 200, completion(), sent).complete(request_for(provider_class))

    assert str(sent[0].url) == url


@pytest.mark.parametrize("provider_class", PROVIDERS)
def test_the_answer_gives_text_model_and_usage_split_by_price(provider_class):
    model = MODELS[provider_class]

    response = answering(provider_class, 200, completion(model), []).complete(
        request_for(provider_class)
    )

    assert response.text == "true positive"
    assert response.model_version == model
    assert response.stop_reason is StopReason.COMPLETE
    # prompt_tokens (1500) already includes the 1000 tokens read from the cache.
    assert response.attempts == (
        Attempt(model, Usage(input_tokens=500, output_tokens=400, cache_read_tokens=1000)),
    )
    assert response.request_id == "req_789"


# Usage as each API reports it: DeepSeek and Qwen from real calls, GLM and Kimi from their API
# references, and the top-level fields that DeepSeek and Kimi also have.
REPORTED_USAGE = [
    (
        DeepSeekProvider,
        {
            "prompt_tokens": 3117,
            "completion_tokens": 16,
            "total_tokens": 3133,
            "completion_tokens_details": {"reasoning_tokens": 16},
            "prompt_tokens_details": {"cached_tokens": 2944},
            "prompt_cache_hit_tokens": 2944,
            "prompt_cache_miss_tokens": 173,
        },
        Usage(input_tokens=173, output_tokens=16, cache_read_tokens=2944),
    ),
    (
        DeepSeekProvider,
        {
            "prompt_tokens": 3117,
            "completion_tokens": 16,
            "total_tokens": 3133,
            "prompt_cache_hit_tokens": 2944,
            "prompt_cache_miss_tokens": 173,
        },
        Usage(input_tokens=173, output_tokens=16, cache_read_tokens=2944),
    ),
    (
        QwenProvider,
        {
            "prompt_tokens": 3434,
            "completion_tokens": 1,
            "total_tokens": 3435,
            "prompt_tokens_details": {"cached_tokens": 3072, "text_tokens": 3434},
        },
        Usage(input_tokens=362, output_tokens=1, cache_read_tokens=3072),
    ),
    (
        GLMProvider,
        {
            "prompt_tokens": 1500,
            "completion_tokens": 400,
            "total_tokens": 1900,
            "prompt_tokens_details": {"cached_tokens": 1000},
        },
        Usage(input_tokens=500, output_tokens=400, cache_read_tokens=1000),
    ),
    (
        KimiProvider,
        {
            "prompt_tokens": 1500,
            "completion_tokens": 400,
            "total_tokens": 1900,
            "cached_tokens": 1000,
            "prompt_tokens_details": {"cached_tokens": 1000, "cache_write_tokens": 300},
        },
        Usage(input_tokens=200, output_tokens=400, cache_read_tokens=1000, cache_write_tokens=300),
    ),
    (
        KimiProvider,
        {
            "prompt_tokens": 1500,
            "completion_tokens": 400,
            "total_tokens": 1900,
            "cached_tokens": 1000,
        },
        Usage(input_tokens=500, output_tokens=400, cache_read_tokens=1000),
    ),
]


@pytest.mark.parametrize(("provider_class", "usage", "expected"), REPORTED_USAGE)
def test_cache_reads_are_found_where_each_api_reports_them(provider_class, usage, expected):
    body = completion(MODELS[provider_class], usage=usage)

    response = answering(provider_class, 200, body, []).complete(request_for(provider_class))

    assert response.usage == expected


def test_cache_writes_are_taken_out_of_the_prompt_tokens():
    usage = completion()["usage"] | {
        "prompt_tokens_details": {"cached_tokens": 1000, "cache_write_tokens": 300}
    }
    body = completion("kimi-k3.1-pro", usage=usage)

    response = answering(KimiProvider, 200, body, []).complete(request_for(KimiProvider))

    assert response.usage == Usage(
        input_tokens=200, output_tokens=400, cache_read_tokens=1000, cache_write_tokens=300
    )


@pytest.mark.parametrize(
    ("provider_class", "finish_reason", "stop_reason"),
    [
        (DeepSeekProvider, "length", StopReason.MAX_TOKENS),
        (DeepSeekProvider, "content_filter", StopReason.REFUSAL),
        (DeepSeekProvider, "insufficient_system_resource", StopReason.OTHER),
        (GLMProvider, "sensitive", StopReason.REFUSAL),
        (GLMProvider, "network_error", StopReason.OTHER),
    ],
)
def test_cut_off_filtered_and_failed_answers_are_reported(
    provider_class, finish_reason, stop_reason
):
    body = completion()
    body["choices"][0]["finish_reason"] = finish_reason

    response = answering(provider_class, 200, body, []).complete(request_for(provider_class))

    assert response.stop_reason is stop_reason
    assert response.raw_stop_reason == finish_reason


def test_a_refusal_message_is_reported_as_a_refusal():
    body = completion()
    body["choices"][0]["message"] = {"role": "assistant", "content": None, "refusal": "No."}

    response = answering(DeepSeekProvider, 200, body, []).complete(request_for(DeepSeekProvider))

    assert response.stop_reason is StopReason.REFUSAL
    assert response.text == ""


def test_an_answer_without_choices_is_an_error():
    with pytest.raises(ProviderError, match="no answer") as raised:
        answering(DeepSeekProvider, 200, completion(choices=[]), []).complete(
            request_for(DeepSeekProvider)
        )

    assert raised.value.retryable is True


def test_deepseek_gets_the_effort_and_temperature_as_given():
    body = sent_body(DeepSeekProvider, effort="high", temperature=0.0)

    assert body["reasoning_effort"] == "high"
    assert body["temperature"] == 0.0


@pytest.mark.parametrize("provider_class", [QwenProvider, KimiProvider])
def test_no_temperature_is_sent_when_the_request_has_none(provider_class):
    assert "temperature" not in sent_body(provider_class)


def test_glm_gets_greedy_decoding_instead_of_temperature_zero():
    body = sent_body(GLMProvider, temperature=0.0)

    assert body["do_sample"] is False
    assert "temperature" not in body
    assert sent_body(GLMProvider, temperature=0.5)["temperature"] == 0.5


@pytest.mark.parametrize(("effort", "sent"), [("low", "low"), ("medium", "high"), ("xhigh", "max")])
def test_glm_gets_thinking_and_the_nearest_effort_level_it_has(effort, sent):
    body = sent_body(GLMProvider, effort=effort)

    assert body["thinking"] == {"type": "enabled"}
    assert body["reasoning_effort"] == sent


def test_glm_is_asked_to_turn_thinking_off_for_effort_none():
    body = sent_body(GLMProvider, effort="none")

    assert body["thinking"] == {"type": "disabled"}
    assert "reasoning_effort" not in body


@pytest.mark.parametrize(("effort", "sent"), [("low", "low"), ("medium", "high"), ("xhigh", "max")])
def test_kimi_gets_the_nearest_effort_level_it_has(effort, sent):
    body = sent_body(KimiProvider, effort=effort)

    assert body["reasoning_effort"] == sent
    assert "max_tokens" not in body


@pytest.mark.parametrize(("effort", "enabled"), [("none", False), ("medium", True)])
def test_qwen_switches_thinking_with_the_effort(effort, enabled):
    assert sent_body(QwenProvider, effort=effort)["enable_thinking"] is enabled


@pytest.mark.parametrize("effort", [None, "medium"])
def test_qwen_splits_max_tokens_between_thinking_and_answer(effort):
    body = sent_body(QwenProvider, effort=effort, max_tokens=1001)

    assert (body["thinking_budget"], body["max_tokens"]) == (500, 501)


def test_qwen_gives_the_answer_all_of_max_tokens_when_it_does_not_think():
    body = sent_body(QwenProvider, effort="none", max_tokens=1001)

    assert body["max_tokens"] == 1001
    assert "thinking_budget" not in body


def test_qwen_can_use_a_workspace_endpoint(monkeypatch):
    workspace = "https://ws-1.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1"
    monkeypatch.setenv("DASHSCOPE_BASE_URL", workspace)

    assert QwenProvider.resolved_base_url() == workspace


@pytest.mark.parametrize(
    "url",
    [
        "http://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        "https://proxy.example/compatible-mode/v1",
        "https://dashscope-intl.aliyuncs.com.proxy.example/compatible-mode/v1",
        "https://dashscope-intl.aliyuncs.com@proxy.example/compatible-mode/v1",
        "https://proxy.example/#.aliyuncs.com",
        "not a url",
    ],
)
def test_qwen_sends_its_key_only_to_an_https_aliyuncs_com_host(url, monkeypatch):
    monkeypatch.setenv("DASHSCOPE_BASE_URL", url)

    with pytest.raises(ProviderError, match="DASHSCOPE_BASE_URL") as raised:
        QwenProvider.resolved_base_url()

    assert raised.value.retryable is False


@pytest.mark.parametrize(
    ("status", "retryable"), [(400, False), (401, False), (429, True), (503, True)]
)
def test_api_errors_say_whether_a_retry_can_help(status, retryable):
    error = {"error": {"message": "no", "type": "some_error", "code": None, "param": None}}

    with pytest.raises(ProviderError) as raised:
        answering(DeepSeekProvider, status, error, []).complete(request_for(DeepSeekProvider))

    assert raised.value.retryable is retryable


@pytest.mark.parametrize("provider_class", PROVIDERS)
def test_requests_go_to_the_providers_own_api_whatever_openai_base_url_says(
    provider_class, monkeypatch
):
    monkeypatch.setenv(provider_class.api_key_variable, "test-key")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://proxy.example/v1")
    monkeypatch.delenv("DASHSCOPE_BASE_URL", raising=False)

    client = provider_class()._client

    assert str(client.base_url).rstrip("/") == provider_class.base_url.rstrip("/")


@pytest.mark.parametrize("provider_class", PROVIDERS)
def test_a_provider_refuses_to_start_while_openai_custom_headers_are_set(
    provider_class, monkeypatch
):
    monkeypatch.setenv(provider_class.api_key_variable, "test-key")
    monkeypatch.setenv("OPENAI_CUSTOM_HEADERS", "Authorization: Bearer another-key")

    with pytest.raises(ProviderError, match="unset OPENAI_CUSTOM_HEADERS") as raised:
        provider_class()

    assert raised.value.retryable is False


@pytest.mark.parametrize("provider_class", PROVIDERS)
def test_each_key_comes_only_from_the_environment(provider_class, monkeypatch):
    monkeypatch.delenv(provider_class.api_key_variable, raising=False)
    with pytest.raises(MissingAPIKey, match=provider_class.api_key_variable):
        provider_class()

    monkeypatch.setenv(provider_class.api_key_variable, "test-key")
    assert provider_class().name == provider_class.name


def test_the_new_models_are_in_models_json():
    catalog = load_catalog()

    for provider_class, model in MODELS.items():
        assert catalog.get(model).provider == provider_class.name
    assert {"deepseek-flash", "qwen3.8-flash", "glm-5.3-flash"} <= set(catalog.names())


def test_deepseek_is_charged_at_the_peak_price():
    flash = load_catalog().get("deepseek-flash")

    assert flash.cost(Usage(output_tokens=1_000_000)) == Decimal("1.20")


def test_deepseek_v4_1_flash_is_the_default_model():
    catalog = load_catalog()

    assert catalog.default_model == "deepseek-flash"
    assert catalog.get(catalog.default_model).provider == "deepseek"


@pytest.mark.parametrize(
    ("provider_class", "status", "message"),
    [
        (GLMProvider, 429, "Insufficient balance or no resource package. Please recharge."),
        (
            KimiProvider,
            429,
            "Your account is suspended due to insufficient balance, please recharge",
        ),
        (DeepSeekProvider, 402, "Insufficient Balance"),
    ],
)
def test_an_account_without_credit_is_not_a_rate_limit(provider_class, status, message):
    error = {"error": {"message": message, "type": "error", "code": None, "param": None}}

    with pytest.raises(ProviderError, match="out of credit") as raised:
        answering(provider_class, status, error, []).complete(request_for(provider_class))

    assert raised.value.retryable is False
