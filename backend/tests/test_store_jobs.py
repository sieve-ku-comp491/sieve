"""The job queue in the jobs table, on the test database."""

from dataclasses import replace

import psycopg
import pytest

from app.runner import PluginManifest, RunStatus
from app.store import PostgresRunStore
from app.store.jobs import PostgresJobQueue

PYGOAT = "https://github.com/adeyosemanputra/pygoat"


@pytest.fixture
def queue(database) -> PostgresJobQueue:
    """The queue with every job other tests left queued taken out of the way."""
    queue = PostgresJobQueue(database)
    with psycopg.connect(database) as conn:
        conn.execute("UPDATE jobs SET status = 'failed' WHERE status IN ('queued', 'running')")
    return queue


def row(database, sql: str, *params):
    with psycopg.connect(database) as conn:
        return conn.execute(sql, params).fetchone()


def test_jobs_are_claimed_oldest_first_once_each(database, queue):
    first_scan, first_job = queue.create_scan(PYGOAT, None, "HEAD")
    _, second_job = queue.create_scan(PYGOAT, None, "main")

    job = queue.claim(["scan"])
    assert (job.id, job.kind, job.payload) == (first_job, "scan", {"scan_id": first_scan})
    status, started_at = row(database, "SELECT status, started_at FROM jobs WHERE id = %s", job.id)
    assert status == "running" and started_at is not None
    assert queue.claim(["scan"]).id == second_job
    assert queue.claim(["scan"]) is None


def test_only_the_kinds_asked_for_are_claimed(database, queue):
    with psycopg.connect(database) as conn:
        conn.execute("INSERT INTO jobs (kind, payload) VALUES ('triage', '{}')")
    assert queue.claim(["scan"]) is None
    assert queue.claim(["triage"]).kind == "triage"


def test_finish_records_success_or_the_error(database, queue):
    queue.create_scan(PYGOAT, None, "HEAD")
    queue.create_scan(PYGOAT, None, "HEAD")
    done, broken = queue.claim(["scan"]), queue.claim(["scan"])
    queue.finish(done.id)
    queue.finish(broken.id, error="RuntimeError: boom")
    sql = "SELECT status, error, finished_at IS NOT NULL FROM jobs WHERE id = %s"
    assert row(database, sql, done.id) == ("succeeded", None, True)
    assert row(database, sql, broken.id) == ("failed", "RuntimeError: boom", True)


def test_a_starting_worker_fails_interrupted_jobs_with_their_scans_and_runs(database, queue):
    scan_id, job_id = queue.create_scan(PYGOAT, None, "HEAD")
    queue.claim(["scan"])
    store = PostgresRunStore(database)
    store.update_scan(scan_id, "running")
    manifest = PluginManifest("semgrep", "sieve-plugin-semgrep:1", ("python",), "semgrep", "1", "1")
    running = store.create_run(scan_id, manifest)
    running.status = RunStatus.RUNNING
    store.update(running)
    done = store.create_run(scan_id, replace(manifest, name="bandit"))
    done.status = RunStatus.SUCCEEDED
    store.update(done)

    assert queue.recover_interrupted() == [scan_id]
    assert row(database, "SELECT status, error FROM jobs WHERE id = %s", job_id) == (
        "failed",
        "interrupted",
    )
    assert row(database, "SELECT status, error FROM scans WHERE id = %s", scan_id) == (
        "failed",
        "interrupted",
    )
    runs = "SELECT status, reason FROM analyzer_runs WHERE id = %s"
    assert row(database, runs, running.run_id) == ("failed", "interrupted")
    assert row(database, runs, done.run_id) == ("succeeded", None)
    assert queue.recover_interrupted() == []
