"""GPT models through the OpenAI Responses API."""

from typing import Any

import openai

from app.llm.provider import (
    LLMProvider,
    ProviderError,
    api_key_from_env,
    refuse_sdk_variables,
    split_system,
    status_error,
)
from app.llm.types import Attempt, LLMRequest, LLMResponse, StopReason, Usage

# The openai SDK adds these to every request even when it is given a key and a base URL: the
# headers in OPENAI_CUSTOM_HEADERS, where an Authorization header replaces the key, and the
# OpenAI organization and project ids.
OPENAI_SDK_VARIABLES = ("OPENAI_CUSTOM_HEADERS", "OPENAI_ORG_ID", "OPENAI_PROJECT_ID")


class OpenAIProvider(LLMProvider):
    """Calls the Responses API.

    Responses are created with store=False, so OpenAI keeps no copy that can be fetched later.
    A temperature is sent only when the request has one, which LLMClient sets only for models
    marked in models.json as accepting it. The GPT-5 reasoning models reject it.
    """

    name = "openai"
    api_key_variable = "OPENAI_API_KEY"
    # Passed to the SDK, so that OPENAI_BASE_URL, which it would otherwise follow, can't send the
    # key and the prompt to another host.
    base_url = "https://api.openai.com/v1"
    refused_variables = OPENAI_SDK_VARIABLES

    def __init__(self, client: openai.OpenAI | None = None):
        if client is None:
            api_key = api_key_from_env(self.api_key_variable)
            refuse_sdk_variables("openai", self.refused_variables)
            client = openai.OpenAI(api_key=api_key, base_url=self.base_url)
        self._client = client

    def complete(self, request: LLMRequest) -> LLMResponse:
        instructions, conversation = split_system(request.messages)
        params: dict[str, Any] = {
            "model": request.model,
            "input": conversation,
            "max_output_tokens": request.max_tokens,
            "store": False,
        }
        if instructions:
            params["instructions"] = instructions
        if request.effort:
            params["reasoning"] = {"effort": request.effort}
        if request.temperature is not None:
            params["temperature"] = request.temperature
        try:
            response = self._client.responses.create(**params)
        except openai.AuthenticationError as error:
            raise ProviderError(
                f"the OpenAI API rejected the key in {self.api_key_variable}", retryable=False
            ) from error
        except openai.APIStatusError as error:
            raise status_error("OpenAI", error.status_code, error.message) from error
        except openai.APIConnectionError as error:
            raise ProviderError(
                f"could not reach the OpenAI API: {error}", retryable=True
            ) from error

        stop_reason, raw_stop_reason = _stop_reason(response)
        return LLMResponse(
            text=response.output_text,
            model_version=response.model,
            stop_reason=stop_reason,
            raw_stop_reason=raw_stop_reason,
            attempts=(Attempt(response.model, _usage(response.usage)),),
            request_id=response._request_id,
        )


def _usage(usage: Any) -> Usage:
    """OpenAI counts cache reads and cache writes inside input_tokens, so they are taken out here.

    Usage.input_tokens means tokens charged at the normal input price, as it does for Claude.
    """
    details = usage.input_tokens_details
    cached = (getattr(details, "cached_tokens", None) or 0) if details else 0
    written = (getattr(details, "cache_write_tokens", None) or 0) if details else 0
    return Usage(
        input_tokens=max(usage.input_tokens - cached - written, 0),
        output_tokens=usage.output_tokens,
        cache_read_tokens=cached,
        cache_write_tokens=written,
    )


def _stop_reason(response: Any) -> tuple[StopReason, str | None]:
    for item in response.output:
        if item.type == "message" and any(part.type == "refusal" for part in item.content):
            return StopReason.REFUSAL, "refusal"
    if response.status == "completed":
        return StopReason.COMPLETE, "completed"
    reason = response.incomplete_details.reason if response.incomplete_details else None
    if reason == "max_output_tokens":
        return StopReason.MAX_TOKENS, reason
    if reason == "content_filter":
        return StopReason.REFUSAL, reason
    return StopReason.OTHER, reason or response.status
