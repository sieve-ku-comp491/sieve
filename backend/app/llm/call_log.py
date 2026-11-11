"""The record of every LLM call, so each AI decision can be traced to its prompt (N3)."""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from typing import Protocol

from app.llm.types import Attempt, Message, Usage


@dataclass(frozen=True)
class CallRecord:
    provider: str
    model: str
    messages: tuple[Message, ...]
    max_tokens: int
    cache_key: str
    cached: bool
    cost_usd: Decimal
    duration_ms: int
    model_version: str | None = None
    response_text: str | None = None
    stop_reason: str | None = None
    raw_stop_reason: str | None = None
    attempts: tuple[Attempt, ...] = ()
    effort: str | None = None
    temperature: float | None = None
    template_name: str | None = None
    template_version: str | None = None
    job_id: str | None = None
    request_id: str | None = None
    error: str | None = None
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def usage(self) -> Usage:
        return sum((attempt.usage for attempt in self.attempts), Usage())


class CallLog(Protocol):
    def record(self, record: CallRecord) -> None: ...


class InMemoryCallLog:
    def __init__(self) -> None:
        self.records: list[CallRecord] = []

    def record(self, record: CallRecord) -> None:
        self.records.append(record)
