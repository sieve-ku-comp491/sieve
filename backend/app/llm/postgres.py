"""The call log in the llm_calls table, which also serves as the response cache."""

import os
from pathlib import Path
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from app.llm.call_log import CallRecord
from app.llm.types import Attempt, LLMResponse, StopReason, Usage

SCHEMA_FILE = Path(__file__).with_name("llm_calls.sql")

INSERT = """
INSERT INTO llm_calls (
    id, job_id, provider, model, model_version, template_name, template_version, messages,
    response_text, stop_reason, raw_stop_reason, attempts, input_tokens, output_tokens,
    cache_read_tokens, cache_write_tokens, cost_usd, duration_ms, cached, cache_key,
    temperature, effort, max_tokens, request_id, error, created_at
) VALUES (
    %(id)s, %(job_id)s, %(provider)s, %(model)s, %(model_version)s, %(template_name)s,
    %(template_version)s, %(messages)s, %(response_text)s, %(stop_reason)s, %(raw_stop_reason)s,
    %(attempts)s, %(input_tokens)s, %(output_tokens)s, %(cache_read_tokens)s,
    %(cache_write_tokens)s, %(cost_usd)s, %(duration_ms)s, %(cached)s, %(cache_key)s,
    %(temperature)s, %(effort)s, %(max_tokens)s, %(request_id)s, %(error)s, %(created_at)s
)
"""

# Only complete answers from real calls are reused. Refusals, cut-off answers and errors are not.
LOOKUP = """
SELECT response_text, model_version, stop_reason, raw_stop_reason, attempts, request_id
FROM llm_calls
WHERE cache_key = %(key)s AND NOT cached AND error IS NULL AND stop_reason = 'complete'
ORDER BY created_at DESC
LIMIT 1
"""


class PostgresCallStore:
    """CallLog and ResponseCache backed by the llm_calls table.

    put() stores nothing, because record() already saved the response. get() finds the latest
    complete answer with the same cache key.
    """

    def __init__(self, conninfo: str | None = None):
        self._conninfo = conninfo or os.environ["DATABASE_URL"]

    def create_table(self) -> None:
        with psycopg.connect(self._conninfo) as conn:
            conn.execute(SCHEMA_FILE.read_text(encoding="utf-8"))

    def record(self, record: CallRecord) -> None:
        usage = record.usage
        with psycopg.connect(self._conninfo) as conn:
            conn.execute(
                INSERT,
                {
                    "id": record.id,
                    "job_id": record.job_id,
                    "provider": record.provider,
                    "model": record.model,
                    "model_version": record.model_version,
                    "template_name": record.template_name,
                    "template_version": record.template_version,
                    "messages": Jsonb(
                        [{"role": m.role, "content": m.content} for m in record.messages]
                    ),
                    "response_text": record.response_text,
                    "stop_reason": record.stop_reason,
                    "raw_stop_reason": record.raw_stop_reason,
                    "attempts": Jsonb([_attempt_json(a) for a in record.attempts]),
                    "input_tokens": usage.input_tokens,
                    "output_tokens": usage.output_tokens,
                    "cache_read_tokens": usage.cache_read_tokens,
                    "cache_write_tokens": usage.cache_write_tokens,
                    "cost_usd": record.cost_usd,
                    "duration_ms": record.duration_ms,
                    "cached": record.cached,
                    "cache_key": record.cache_key,
                    "temperature": record.temperature,
                    "effort": record.effort,
                    "max_tokens": record.max_tokens,
                    "request_id": record.request_id,
                    "error": record.error,
                    "created_at": record.created_at,
                },
            )

    def get(self, key: str) -> LLMResponse | None:
        with psycopg.connect(self._conninfo) as conn:
            row = conn.execute(LOOKUP, {"key": key}).fetchone()
        if row is None:
            return None
        text, model_version, stop_reason, raw_stop_reason, attempts, request_id = row
        return LLMResponse(
            text=text,
            model_version=model_version,
            stop_reason=StopReason(stop_reason),
            raw_stop_reason=raw_stop_reason,
            attempts=tuple(_attempt_from_json(a) for a in attempts),
            request_id=request_id,
        )

    def put(self, key: str, response: LLMResponse) -> None:
        pass


def _attempt_json(attempt: Attempt) -> dict[str, Any]:
    usage = attempt.usage
    return {
        "model": attempt.model,
        "input_tokens": usage.input_tokens,
        "output_tokens": usage.output_tokens,
        "cache_read_tokens": usage.cache_read_tokens,
        "cache_write_tokens": usage.cache_write_tokens,
    }


def _attempt_from_json(data: dict[str, Any]) -> Attempt:
    usage = {key: value for key, value in data.items() if key != "model"}
    return Attempt(data["model"], Usage(**usage))
