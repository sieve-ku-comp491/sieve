"""The interface every LLM provider implements."""

import os
from abc import ABC, abstractmethod
from collections.abc import Sequence

from app.llm.types import LLMRequest, LLMResponse, Message


class ProviderError(Exception):
    """A call failed. `retryable` says whether trying again later can help."""

    def __init__(self, message: str, *, retryable: bool):
        super().__init__(message)
        self.retryable = retryable


class MissingAPIKey(ProviderError):
    def __init__(self, variable: str):
        super().__init__(
            f"{variable} is not set, add it to .env (see .env.example)", retryable=False
        )
        self.variable = variable


def api_key_from_env(variable: str) -> str:
    """API keys come only from the environment, never from a file in the repo (N4)."""
    value = os.environ.get(variable, "").strip()
    if not value:
        raise MissingAPIKey(variable)
    return value


def refuse_sdk_variables(sdk: str, variables: Sequence[str]) -> None:
    """Stops when the environment sets a variable that the SDK would apply to every request.

    The SDKs read some settings from the environment even when the key and the base URL are
    passed in. A header meant for another tool could then replace our key or reach the wrong API.
    """
    found = [variable for variable in variables if os.environ.get(variable, "").strip()]
    if found:
        them = "it" if len(found) == 1 else "them"
        raise ProviderError(
            f"unset {' and '.join(found)} before running Sieve, the {sdk} SDK would send "
            f"{them} with every request",
            retryable=False,
        )


def split_system(messages: tuple[Message, ...]) -> tuple[str, list[dict[str, str]]]:
    """Separates the leading system messages from the conversation that follows them."""
    system: list[str] = []
    conversation: list[dict[str, str]] = []
    for message in messages:
        if message.role == "system":
            if conversation:
                raise ValueError("system messages must come before the conversation")
            system.append(message.content)
        else:
            conversation.append({"role": message.role, "content": message.content})
    return "\n\n".join(system), conversation


class LLMProvider(ABC):
    """Sends one request to one API and reports the answer and its token usage.

    Providers don't cache, price or log calls. LLMClient does that the same way for all of them.
    """

    name: str
    api_key_variable: str
    # Variables that the provider's SDK applies to every request even though the key and the
    # base URL are passed in. The provider refuses to start while one of them is set.
    refused_variables: tuple[str, ...] = ()

    @abstractmethod
    def complete(self, request: LLMRequest) -> LLMResponse:
        """Sends the request and returns the text, the exact model version and the tokens used."""
