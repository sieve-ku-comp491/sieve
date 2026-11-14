"""Saving a plug-in run's findings in one transaction."""

import copy
from pathlib import Path

import psycopg
import pytest

from app.adapters import AdapterResult, Finding, FlowStep, Location
from app.runner.manifest import PluginManifest
from app.runner.runner import RunStatus
from app.store import PostgresRunStore, StoreError

MANIFEST = Path(__file__).resolve().parents[2] / "plugins" / "semgrep" / "plugin.toml"
LAB = "dockerized_labs/sql_injection_lab/app.py"
PYGOAT = "https://github.com/adeyosemanputra/pygoat"
COMMIT = "2aa4cc14f251e4a780e94e200aed6b36a5b15c21"
SQL_RULE = "python.lang.security.audit.formatted-sql-query"


@pytest.fixture
def store(database):
    return PostgresRunStore(database)


@pytest.fixture
def run(store):
    scan_id = store.create_scan(PYGOAT, commit_sha=COMMIT)
    return store.create_run(scan_id, PluginManifest.load(MANIFEST))


def finding(run, fingerprint: str, **fields) -> Finding:
    values = {
        "scan_id": run.scan_id,
        "run_id": run.run_id,
        "tool": "semgrep",
        "tool_version": "1.183.0",
        "rule_id": SQL_RULE,
        "message": "m",
        "tool_severity": "warning",
        "location": Location(LAB, 57, 57, 22, 42, "x"),
        "raw": {"ruleId": SQL_RULE},
        "fingerprint": fingerprint,
        "context_hash": "c1:x",
    }
    return Finding(**(values | fields))


def run_row(database, run_id):
    with psycopg.connect(database) as conn:
        return conn.execute(
            "SELECT status, dropped_count, (SELECT count(*) FROM findings WHERE run_id = r.id)"
            " FROM analyzer_runs r WHERE id = %s",
            (run_id,),
        ).fetchone()


def test_related_locations_and_flow_steps_go_to_locations(database, store, run):
    related = [Location(LAB, 50, 52), Location(LAB, 46, 46, 9, 17, "username = ...")]
    flow = [FlowStep(LAB, 46, 46, step=1, message="source"), FlowStep(LAB, 57, 57, step=2)]
    result = AdapterResult([finding(run, "v1:a", related_locations=related, data_flow=flow)])
    run.status = RunStatus.SUCCEEDED

    (finding_id,) = store.save_findings(run, result)

    assert result.findings[0].finding_id == finding_id
    with psycopg.connect(database) as conn:
        rows = conn.execute(
            "SELECT kind, position, start_line, end_line, start_column, snippet, message"
            " FROM locations WHERE finding_id = %s ORDER BY kind, position",
            (finding_id,),
        ).fetchall()
    assert rows == [
        ("flow_step", 1, 46, 46, None, None, "source"),
        ("flow_step", 2, 57, 57, None, None, None),
        ("related", 1, 50, 52, None, None, None),
        ("related", 2, 46, 46, 9, "username = ...", None),
    ]
    assert run_row(database, run.run_id) == ("succeeded", 0, 1)


def test_a_run_is_saved_whole_or_not_at_all(database, store, run):
    """The second finding repeats the first one's fingerprint, which the store refuses, so the
    first finding and the run's new status and dropped count are not saved either."""
    result = AdapterResult([finding(run, "v1:same"), finding(run, "v1:same")])
    result.drop("path_outside_checkout")
    run.status = RunStatus.SUCCEEDED

    with pytest.raises(psycopg.errors.UniqueViolation):
        store.save_findings(run, result)

    assert run_row(database, run.run_id) == ("pending", 0, 0)
    assert [f.finding_id for f in result.findings] == [None, None]


def test_findings_of_another_run_are_refused(store, run):
    other = copy.copy(run)
    other.run_id = "00000000-0000-0000-0000-000000000000"
    with pytest.raises(StoreError):
        store.save_findings(run, AdapterResult([finding(other, "v1:b")]))
