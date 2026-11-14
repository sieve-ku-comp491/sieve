"""The worker loop on the test database, with a scan service that only records its calls."""

import psycopg
import pytest

from app.store import PostgresRunStore
from app.store.jobs import PostgresJobQueue
from app.worker import Worker

PYGOAT = "https://github.com/adeyosemanputra/pygoat"


class RecordingService:
    def __init__(self, store, error: Exception | None = None):
        self.store = store
        self.error = error
        self.scans: list[str] = []

    def run_scan(self, scan_id: str) -> str:
        self.scans.append(scan_id)
        if self.error:
            raise self.error
        return "completed"


class RecordingRunner:
    def __init__(self):
        self.removed: list[str] = []

    def remove_leftovers(self, scan_id: str) -> None:
        self.removed.append(scan_id)


@pytest.fixture
def queue(database) -> PostgresJobQueue:
    with psycopg.connect(database) as conn:
        conn.execute("UPDATE jobs SET status = 'failed' WHERE status IN ('queued', 'running')")
    return PostgresJobQueue(database)


def status(database, table: str, row_id: str) -> tuple:
    with psycopg.connect(database) as conn:
        sql = f"SELECT status, error FROM {table} WHERE id = %s"
        return conn.execute(sql, (row_id,)).fetchone()


def test_the_worker_runs_a_queued_scan_and_finishes_its_job(database, queue):
    scan_id, job_id = queue.create_scan(PYGOAT, None, "HEAD")
    service = RecordingService(PostgresRunStore(database))
    worker = Worker(queue, service, RecordingRunner())
    assert worker.run_next() is True
    assert service.scans == [scan_id]
    assert status(database, "jobs", job_id) == ("succeeded", None)
    assert worker.run_next() is False


def test_an_unexpected_error_fails_the_job_and_its_scan(database, queue):
    scan_id, job_id = queue.create_scan(PYGOAT, None, "HEAD")
    service = RecordingService(PostgresRunStore(database), error=OSError("disk full"))
    Worker(queue, service, RecordingRunner()).run_next()
    assert status(database, "jobs", job_id) == ("failed", "OSError: disk full")
    assert status(database, "scans", scan_id) == ("failed", "OSError: disk full")


def test_a_starting_worker_removes_the_containers_of_interrupted_scans(database, queue):
    scan_id, _ = queue.create_scan(PYGOAT, None, "HEAD")
    queue.claim(["scan"])
    runner = RecordingRunner()
    Worker(queue, RecordingService(PostgresRunStore(database)), runner).recover()
    assert runner.removed == [scan_id]
