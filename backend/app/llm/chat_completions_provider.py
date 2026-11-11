"""Providers whose API follows the format of OpenAI's Chat Completions API.

DeepSeek, Qwen, GLM and Kimi each serve that format at their own base URL, so each of them is a
small subclass that sets its name, key variable and base URL, and says how its API takes effort
and temperature.
"""

import os
from typing import Any

import openai

from app.llm.openai_provider import OPENAI_SDK_VARIABLES
from app.llm.provider import (
    LLMProvider,
    ProviderError,
    api_key_from_env,
    refuse_sdk_variables,
    split_system,
    status_error,
)
from app.llm.types import Attempt, LLMRequest, LLMResponse, StopReason, Usage

STOP_REASONS = {
    "stop": StopReason.COMPLETE,
    "length": StopReason.MAX_TOKENS,
    "content_filter": StopReason.REFUSAL,
}

# For APIs whose reasoning_effort takes only low, high and max: the nearest of those.
NEAREST_LEVEL = {"low": "low", "medium": "high", "high": "high", "xhigh": "max", "max": "max"}


class ChatCompletionsProvider(LLMProvider):
    """Calls a Chat Completions API through the openai SDK at the provider's base URL.

    A subclass sets name, label, api_key_variable and base_url. When base_url_variable is set
    in the environment, its value replaces base_url. Effort and temperature go into the request
    body through effort_fields and sampling_fields, which a subclass overrides when its API
    takes them differently.
    """

    label: str
    base_url: str
    base_url_variable: str | None = None
    max_tokens_field = "max_tokens"
    stop_reasons: dict[str, StopReason] = STOP_REASONS
    # The openai SDK would send these to this provider's API too.
    refused_variables = OPENAI_SDK_VARIABLES

    def __init__(self, client: openai.OpenAI | None = None):
        if client is None:
            api_key = api_key_from_env(self.api_key_variable)
            refuse_sdk_variables("openai", self.refused_variables)
            client = openai.OpenAI(api_key=api_key, base_url=self.resolved_base_url())
        self._client = client

    @classmethod
    def resolved_base_url(cls) -> str:
        if cls.base_url_variable:
            return os.environ.get(cls.base_url_variable, "").strip() or cls.base_url
        return cls.base_url

    def effort_fields(self, effort: str) -> dict[str, Any]:
        return {"reasoning_effort": effort}

    def sampling_fields(self, temperature: float) -> dict[str, Any]:
        return {"temperature": temperature}

    def complete(self, request: LLMRequest) -> LLMResponse:
        system, conversation = split_system(request.messages)
        messages = [{"role": "system", "content": system}] if system else []
        params: dict[str, Any] = {
            "model": request.model,
            "messages": messages + conversation,
            self.max_tokens_field: request.max_tokens,
        }
        # Fields that the openai SDK doesn't know go into the body unchanged.
        extra: dict[str, Any] = {}
        if request.temperature is not None:
            extra |= self.sampling_fields(request.temperature)
        if request.effort:
            extra |= self.effort_fields(request.effort)
        if extra:
            params["extra_body"] = extra
        try:
            response = self._client.chat.completions.create(**params)
        except openai.AuthenticationError as error:
            raise ProviderError(
                f"the {self.label} API rejected the key in {self.api_key_variable}",
                retryable=False,
            ) from error
        except openai.APIStatusError as error:
            raise status_error(self.label, error.status_code, error.message) from error
        except openai.APIConnectionError as error:
            raise ProviderError(
                f"could not reach the {self.label} API: {error}", retryable=True
            ) from error

        if not response.choices:
            raise ProviderError(f"the {self.label} API sent no answer", retryable=True)
        choice = response.choices[0]
        stop_reason, raw_stop_reason = self._stop_reason(choice)
        return LLMResponse(
            text=choice.message.content or "",
            model_version=response.model,
            stop_reason=stop_reason,
            raw_stop_reason=raw_stop_reason,
            attempts=(Attempt(response.model, usage_from(response.usage)),),
            request_id=response._request_id,
        )

    def _stop_reason(self, choice: Any) -> tuple[StopReason, str | None]:
        if getattr(choice.message, "refusal", None):
            return StopReason.REFUSAL, "refusal"
        reason = choice.finish_reason
        return self.stop_reasons.get(reason or "", StopReason.OTHER), reason


def usage_from(usage: Any) -> Usage:
    """prompt_tokens includes the cache reads and writes, so they are taken out of it here."""
    details = usage.prompt_tokens_details
    cached = (getattr(details, "cached_tokens", None) or 0) if details else 0
    written = (getattr(details, "cache_write_tokens", None) or 0) if details else 0
    return Usage(
        input_tokens=max(usage.prompt_tokens - cached - written, 0),
        output_tokens=usage.completion_tokens,
        cache_read_tokens=cached,
        cache_write_tokens=written,
    )
