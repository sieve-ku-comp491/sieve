"""The job queue in the jobs table (docs/database.md, docs/architecture.md "Background jobs").

The API creates a scan together with its job in one transaction, so no scan is ever left
without a job. The worker claims the oldest waiting job with SELECT ... FOR UPDATE SKIP LOCKED
and commits before it starts the work. Payloads hold IDs only.
"""

from dataclasses import dataclass
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from app.store.runs import INSERT_SCAN

INSERT_JOB = "INSERT INTO jobs (kind, payload) VALUES (%s, %s) RETURNING id"

CLAIM = """
UPDATE jobs SET status = 'running', started_at = now()
WHERE id = (
    SELECT id FROM jobs
    WHERE status = 'queued' AND kind = ANY(%(kinds)s)
    ORDER BY created_at, id
    LIMIT 1
    FOR UPDATE SKIP LOCKED
)
RETURNING id, kind, payload
"""

FINISH = """
UPDATE jobs SET status = %(status)s, error = %(error)s, finished_at = now()
WHERE id = %(id)s AND status = 'running'
"""

INTERRUPTED_JOBS = """
UPDATE jobs SET status = 'failed', error = 'interrupted', finished_at = now()
WHERE status = 'running'
RETURNING kind, payload
"""

INTERRUPTED_SCAN = """
UPDATE scans SET status = 'failed', error = 'interrupted', finished_at = now()
WHERE id = %(id)s AND status IN ('queued', 'running')
"""

INTERRUPTED_RUNS = """
UPDATE analyzer_runs SET status = 'failed', reason = 'interrupted', finished_at = now()
WHERE scan_id = %(id)s AND status IN ('pending', 'building', 'running')
"""


@dataclass(frozen=True)
class Job:
    id: str
    kind: str
    payload: dict[str, Any]


class PostgresJobQueue:
    def __init__(self, conninfo: str):
        self._conninfo = conninfo

    def create_scan(
        self, repo_url: str, commit_sha: str | None, requested_ref: str | None
    ) -> tuple[str, str]:
        """A queued scan and the job that runs it, in one transaction. Returns both IDs."""
        with psycopg.connect(self._conninfo) as conn:
            scan_id = conn.execute(INSERT_SCAN, (repo_url, commit_sha, requested_ref)).fetchone()[0]
            job = conn.execute(INSERT_JOB, ("scan", Jsonb({"scan_id": str(scan_id)}))).fetchone()
        return str(scan_id), str(job[0])

    def claim(self, kinds: list[str]) -> Job | None:
        """Sets the oldest queued job of these kinds to running and returns it, or None."""
        with psycopg.connect(self._conninfo) as conn:
            row = conn.execute(CLAIM, {"kinds": kinds}).fetchone()
        if row is None:
            return None
        return Job(id=str(row[0]), kind=row[1], payload=row[2])

    def finish(self, job_id: str, error: str | None = None) -> None:
        """Marks the job succeeded, or failed with error."""
        with psycopg.connect(self._conninfo) as conn:
            conn.execute(
                FINISH,
                {"id": job_id, "status": "failed" if error else "succeeded", "error": error},
            )

    def recover_interrupted(self) -> list[str]:
        """For a worker that is starting: every job still running was interrupted. Marks it
        failed, with its scan and the scan's unfinished plug-in runs, and returns the IDs of
        those scans so their leftover containers can be removed."""
        scan_ids = []
        with psycopg.connect(self._conninfo) as conn:
            for kind, payload in conn.execute(INTERRUPTED_JOBS).fetchall():
                if kind == "scan" and payload.get("scan_id"):
                    scan_ids.append(payload["scan_id"])
            for scan_id in scan_ids:
                conn.execute(INTERRUPTED_SCAN, {"id": scan_id})
                conn.execute(INTERRUPTED_RUNS, {"id": scan_id})
        return scan_ids
