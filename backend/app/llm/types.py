"""Requests and responses as LLMClient and the providers pass them around."""

from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from typing import Literal

Role = Literal["system", "user", "assistant"]


@dataclass(frozen=True)
class Message:
    role: Role
    content: str


@dataclass(frozen=True)
class CodeBlock:
    """Code from the scanned repository. It only ever goes into a prompt as data."""

    path: str
    start_line: int
    end_line: int
    text: str


@dataclass(frozen=True)
class LLMRequest:
    model: str
    messages: tuple[Message, ...]
    max_tokens: int
    effort: str | None = None
    # Set only for models that accept it, see "temperature" in models.json.
    temperature: float | None = None
    # Ask the API to rerun a declined request on a substitute model (Claude only).
    server_fallbacks: bool = False


class StopReason(StrEnum):
    COMPLETE = "complete"
    MAX_TOKENS = "max_tokens"
    REFUSAL = "refusal"
    OTHER = "other"


@dataclass(frozen=True)
class Usage:
    # Input tokens billed at the normal input price, so without cache reads and writes.
    input_tokens: int = 0
    # All output tokens, including thinking and reasoning tokens.
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

    @property
    def prompt_tokens(self) -> int:
        return self.input_tokens + self.cache_read_tokens + self.cache_write_tokens

    def __add__(self, other: "Usage") -> "Usage":
        return Usage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            cache_read_tokens=self.cache_read_tokens + other.cache_read_tokens,
            cache_write_tokens=self.cache_write_tokens + other.cache_write_tokens,
        )


@dataclass(frozen=True)
class Attempt:
    """One model run behind a response. A refusal fallback adds a second one."""

    model: str
    usage: Usage


@dataclass(frozen=True)
class LLMResponse:
    text: str
    model_version: str
    stop_reason: StopReason
    raw_stop_reason: str | None
    attempts: tuple[Attempt, ...]
    request_id: str | None = None
    # Filled in by LLMClient.
    cost_usd: Decimal = Decimal(0)
    duration_ms: int = 0
    cached: bool = False
    call_id: str | None = None

    @property
    def usage(self) -> Usage:
        """Token counts summed over all attempts."""
        return sum((attempt.usage for attempt in self.attempts), Usage())
