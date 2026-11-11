import os
import uuid
from decimal import Decimal

import psycopg
import pytest

from app.llm.call_log import CallRecord
from app.llm.postgres import PostgresCallStore
from app.llm.types import Attempt, Message, StopReason, Usage

DATABASE_URL = os.environ.get("SIEVE_TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="set SIEVE_TEST_DATABASE_URL to a throwaway PostgreSQL database"
)


@pytest.fixture
def store():
    store = PostgresCallStore(DATABASE_URL)
    store.create_table()
    yield store
    with psycopg.connect(DATABASE_URL) as conn:
        conn.execute("DELETE FROM llm_calls WHERE cache_key LIKE 'test:%'")


def record(key: str, **fields) -> CallRecord:
    values = {
        "provider": "anthropic",
        "model": "claude-haiku-5-5",
        "messages": (Message("system", "Decide."), Message("user", "data")),
        "max_tokens": 1000,
        "cache_key": key,
        "cached": False,
        "cost_usd": Decimal("0.00012345"),
        "duration_ms": 850,
        "model_version": "claude-haiku-5-5",
        "response_text": "true positive",
        "stop_reason": StopReason.COMPLETE.value,
        "raw_stop_reason": "end_turn",
        "attempts": (Attempt("claude-haiku-5-5", Usage(1000, 200, cache_read_tokens=50)),),
        "job_id": str(uuid.uuid4()),
        "request_id": "req_1",
    }
    return CallRecord(**(values | fields))


def test_a_recorded_call_is_stored_with_tokens_and_exact_cost(store):
    call = record("test:stored")

    store.record(call)

    with psycopg.connect(DATABASE_URL) as conn:
        row = conn.execute(
            "SELECT input_tokens, output_tokens, cache_read_tokens, cost_usd, messages, cached"
            " FROM llm_calls WHERE id = %s",
            (call.id,),
        ).fetchone()
    assert row == (
        1000,
        200,
        50,
        Decimal("0.00012345"),
        [{"role": "system", "content": "Decide."}, {"role": "user", "content": "data"}],
        False,
    )


def test_the_latest_complete_answer_is_served_from_the_store(store):
    store.record(record("test:hit", response_text="older"))
    store.record(record("test:hit", response_text="newer"))

    cached = store.get("test:hit")

    assert cached is not None
    assert cached.text == "newer"
    assert cached.stop_reason is StopReason.COMPLETE
    assert cached.attempts == (Attempt("claude-haiku-5-5", Usage(1000, 200, cache_read_tokens=50)),)


def test_cache_hits_failures_and_incomplete_or_empty_answers_are_never_served(store):
    store.record(record("test:miss", cached=True))
    store.record(record("test:miss", error="ProviderError: overloaded", response_text=None))
    store.record(record("test:miss", stop_reason=StopReason.REFUSAL.value))
    store.record(record("test:miss", stop_reason=StopReason.MAX_TOKENS.value))
    store.record(record("test:miss", response_text=""))
    store.record(record("test:miss", response_text=" \n"))

    assert store.get("test:miss") is None
