"""Scans, plug-in runs and their findings in PostgreSQL (docs/database.md, scan side)."""

from datetime import UTC, datetime
from decimal import Decimal

import psycopg
from psycopg.types.json import Jsonb

from app.adapters import AdapterResult, Finding, Location
from app.runner.manifest import PluginManifest
from app.runner.runner import PluginRun

INSERT_SCAN = """
INSERT INTO scans (repo_url, commit_sha, requested_ref) VALUES (%s, %s, %s) RETURNING id
"""

UPDATE_SCAN = """
UPDATE scans SET
    status = %(status)s,
    error = %(error)s,
    languages = coalesce(%(languages)s, languages),
    commit_sha = coalesce(%(commit_sha)s, commit_sha),
    started_at = coalesce(started_at, %(started_at)s),
    finished_at = %(finished_at)s
WHERE id = %(id)s
"""

INSERT_RUN = """
INSERT INTO analyzer_runs (scan_id, plugin, image, tool_version, rules_version)
VALUES (%s, %s, %s, %s, %s)
RETURNING id
"""

UPDATE_RUN = """
UPDATE analyzer_runs SET
    image_digest = %(image_digest)s,
    status = %(status)s,
    reason = %(reason)s,
    exit_code = %(exit_code)s,
    files_scanned = %(files_scanned)s,
    result_count = %(result_count)s,
    dropped_count = %(dropped_count)s,
    sarif_path = %(sarif_path)s,
    log_path = %(log_path)s,
    started_at = %(started_at)s,
    finished_at = %(finished_at)s
WHERE id = %(id)s AND scan_id = %(scan_id)s
"""

INSERT_FINDING = """
INSERT INTO findings (
    scan_id, run_id, tool, tool_version, rule_id, rule_description, rule_help_uri, cwe, message,
    tool_severity, tool_score, tool_confidence, file, start_line, end_line, start_column,
    end_column, snippet, fingerprint, fingerprint_ambiguous, context_hash, suppressed,
    tool_fingerprint, language, raw
) VALUES (
    %(scan_id)s, %(run_id)s, %(tool)s, %(tool_version)s, %(rule_id)s, %(rule_description)s,
    %(rule_help_uri)s, %(cwe)s, %(message)s, %(tool_severity)s, %(tool_score)s,
    %(tool_confidence)s, %(file)s, %(start_line)s, %(end_line)s, %(start_column)s,
    %(end_column)s, %(snippet)s, %(fingerprint)s, %(fingerprint_ambiguous)s, %(context_hash)s,
    %(suppressed)s, %(tool_fingerprint)s, %(language)s, %(raw)s
)
RETURNING id
"""

INSERT_LOCATION = """
INSERT INTO locations (
    finding_id, kind, position, file, start_line, end_line, start_column, end_column, snippet,
    message
) VALUES (
    %(finding_id)s, %(kind)s, %(position)s, %(file)s, %(start_line)s, %(end_line)s,
    %(start_column)s, %(end_column)s, %(snippet)s, %(message)s
)
"""


class StoreError(RuntimeError):
    pass


class PostgresRunStore:
    """The RunStore of the plug-in runner on the analyzer_runs table, plus the scans the runs
    belong to and the findings each run produced."""

    def __init__(self, conninfo: str):
        self._conninfo = conninfo

    def create_scan(
        self, repo_url: str, commit_sha: str | None = None, requested_ref: str | None = None
    ) -> str:
        """A new scan with the status queued. Returns its ID."""
        with psycopg.connect(self._conninfo) as conn:
            row = conn.execute(INSERT_SCAN, (repo_url, commit_sha, requested_ref)).fetchone()
        return str(row[0])

    def update_scan(
        self,
        scan_id: str,
        status: str,
        *,
        error: str | None = None,
        languages: list[str] | None = None,
        commit_sha: str | None = None,
    ) -> None:
        """Sets the scan's status. started_at is set the first time the scan leaves queued, and
        finished_at when it ends as completed, partial or failed."""
        now = datetime.now(UTC)
        with psycopg.connect(self._conninfo) as conn:
            cursor = conn.execute(
                UPDATE_SCAN,
                {
                    "id": scan_id,
                    "status": status,
                    "error": error,
                    "languages": languages,
                    "commit_sha": commit_sha,
                    "started_at": None if status == "queued" else now,
                    "finished_at": now if status in ("completed", "partial", "failed") else None,
                },
            )
            if cursor.rowcount != 1:
                raise StoreError(f"no scan {scan_id}")

    def create_run(self, scan_id: str, plugin: PluginManifest) -> PluginRun:
        with psycopg.connect(self._conninfo) as conn:
            row = conn.execute(
                INSERT_RUN,
                (scan_id, plugin.name, plugin.image, plugin.tool_version, plugin.rules_version),
            ).fetchone()
        return PluginRun(
            run_id=str(row[0]),
            scan_id=scan_id,
            plugin=plugin.name,
            image=plugin.image,
            tool_version=plugin.tool_version,
            rules_version=plugin.rules_version,
        )

    def update(self, run: PluginRun) -> None:
        with psycopg.connect(self._conninfo) as conn:
            _update_run(conn, run)

    def save_findings(self, run: PluginRun, result: AdapterResult) -> list[str]:
        """Stores the run's findings with their locations, and the run itself with its dropped
        count, in one transaction. Either all of it is saved or none. Sets each finding's
        finding_id and returns the IDs in the order of result.findings."""
        for finding in result.findings:
            if (finding.scan_id, finding.run_id) != (run.scan_id, run.run_id):
                raise StoreError(f"a finding of run {finding.run_id} given for run {run.run_id}")
        run.dropped_count = result.dropped_count
        ids = []
        with psycopg.connect(self._conninfo) as conn, conn.cursor() as cursor:
            _update_run(conn, run)
            for finding in result.findings:
                cursor.execute(INSERT_FINDING, _finding_row(finding))
                finding_id = cursor.fetchone()[0]
                ids.append(str(finding_id))
                rows = [
                    _location_row(finding_id, "related", position, location)
                    for position, location in enumerate(finding.related_locations, 1)
                ]
                rows += [
                    _location_row(finding_id, "flow_step", step.step or n, step, step.message)
                    for n, step in enumerate(finding.data_flow, 1)
                ]
                if rows:
                    cursor.executemany(INSERT_LOCATION, rows)
        for finding, finding_id in zip(result.findings, ids, strict=True):
            finding.finding_id = finding_id
        return ids


def _update_run(conn: psycopg.Connection, run: PluginRun) -> None:
    cursor = conn.execute(
        UPDATE_RUN,
        {
            "id": run.run_id,
            "scan_id": run.scan_id,
            "image_digest": run.image_digest,
            "status": str(run.status),
            "reason": None if run.reason is None else str(run.reason),
            "exit_code": run.exit_code,
            "files_scanned": run.files_scanned,
            "result_count": run.result_count,
            "dropped_count": run.dropped_count,
            "sarif_path": run.sarif_path,
            "log_path": run.log_path,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
        },
    )
    if cursor.rowcount != 1:
        raise StoreError(f"no run {run.run_id} in scan {run.scan_id}")


def _finding_row(finding: Finding) -> dict:
    location = finding.location
    return {
        "scan_id": finding.scan_id,
        "run_id": finding.run_id,
        "tool": finding.tool,
        "tool_version": finding.tool_version,
        "rule_id": finding.rule_id,
        "rule_description": finding.rule_description,
        "rule_help_uri": finding.rule_help_uri,
        "cwe": list(finding.cwe),
        "message": finding.message,
        "tool_severity": finding.tool_severity,
        "tool_score": None if finding.tool_score is None else Decimal(str(finding.tool_score)),
        "tool_confidence": finding.tool_confidence,
        "file": location.file,
        "start_line": location.start_line,
        "end_line": location.end_line,
        "start_column": location.start_column,
        "end_column": location.end_column,
        "snippet": location.snippet,
        "fingerprint": finding.fingerprint,
        "fingerprint_ambiguous": finding.fingerprint_ambiguous,
        "context_hash": finding.context_hash,
        "suppressed": finding.suppressed,
        "tool_fingerprint": finding.tool_fingerprint,
        "language": finding.language,
        "raw": Jsonb(finding.raw),
    }


def _location_row(
    finding_id, kind: str, position: int, location: Location, message: str | None = None
) -> dict:
    return {
        "finding_id": finding_id,
        "kind": kind,
        "position": position,
        "file": location.file,
        "start_line": location.start_line,
        "end_line": location.end_line,
        "start_column": location.start_column,
        "end_column": location.end_column,
        "snippet": location.snippet,
        "message": message,
    }
