"""Claude models through the Anthropic Messages API."""

from typing import Any

import anthropic

from app.llm.provider import LLMProvider, ProviderError, api_key_from_env, split_system
from app.llm.types import Attempt, LLMRequest, LLMResponse, StopReason, Usage

FALLBACK_BETA = "server-side-fallback-2026-07-01"

STOP_REASONS = {
    "end_turn": StopReason.COMPLETE,
    "stop_sequence": StopReason.COMPLETE,
    "max_tokens": StopReason.MAX_TOKENS,
    "refusal": StopReason.REFUSAL,
}


class AnthropicProvider(LLMProvider):
    """Calls the Messages API.

    The SDK and current Claude models accept no temperature, so none is sent. When the request
    asks for server fallbacks, a request that the safety classifiers decline is run again on a
    substitute model inside the same call (fallbacks "default"). Each attempt is reported with its
    own model and tokens, so each is charged at its own price.
    """

    name = "anthropic"
    api_key_variable = "ANTHROPIC_API_KEY"

    def __init__(self, client: anthropic.Anthropic | None = None):
        if client is None:
            client = anthropic.Anthropic(api_key=api_key_from_env(self.api_key_variable))
        self._client = client

    def complete(self, request: LLMRequest) -> LLMResponse:
        system, conversation = split_system(request.messages)
        params: dict[str, Any] = {
            "model": request.model,
            "max_tokens": request.max_tokens,
            "messages": conversation,
        }
        if system:
            params["system"] = system
        if request.effort:
            params["output_config"] = {"effort": request.effort}
        try:
            if request.server_fallbacks:
                message = self._client.beta.messages.create(
                    **params, betas=[FALLBACK_BETA], fallbacks="default"
                )
            else:
                message = self._client.messages.create(**params)
        except anthropic.AuthenticationError as error:
            raise ProviderError(
                f"the Anthropic API rejected the key in {self.api_key_variable}", retryable=False
            ) from error
        except anthropic.RateLimitError as error:
            raise ProviderError(
                f"rate limited by the Anthropic API: {error.message}", retryable=True
            ) from error
        except anthropic.APIStatusError as error:
            raise ProviderError(
                f"Anthropic API error {error.status_code}: {error.message}",
                retryable=error.status_code >= 500,
            ) from error
        except anthropic.APIConnectionError as error:
            raise ProviderError(
                f"could not reach the Anthropic API: {error}", retryable=True
            ) from error

        return LLMResponse(
            text="".join(block.text for block in message.content if block.type == "text"),
            model_version=message.model,
            stop_reason=STOP_REASONS.get(message.stop_reason or "", StopReason.OTHER),
            raw_stop_reason=message.stop_reason,
            attempts=_attempts(message, request.model),
            request_id=message._request_id,
        )


def _attempts(message: Any, requested_model: str) -> tuple[Attempt, ...]:
    """One attempt per model run, from usage.iterations when the API reports it.

    With fallbacks, top-level usage covers only the attempt that produced the answer, and
    usage.iterations has every attempt, including a declined one that can still be billed.
    """
    iterations = getattr(message.usage, "iterations", None)
    if not iterations:
        return (Attempt(message.model, _usage(message.usage)),)
    return tuple(
        Attempt(getattr(entry, "model", None) or requested_model, _usage(entry))
        for entry in iterations
    )


def _usage(usage: Any) -> Usage:
    return Usage(
        input_tokens=usage.input_tokens or 0,
        output_tokens=usage.output_tokens or 0,
        cache_read_tokens=getattr(usage, "cache_read_input_tokens", None) or 0,
        cache_write_tokens=getattr(usage, "cache_creation_input_tokens", None) or 0,
    )
