"""Saving a plug-in run's findings, and loading a saved Semgrep SARIF file of PyGoat
(tests/adapter_fixture/README.md). Expected values are the ones of the example in
docs/finding-format.md and the 9 results of the fixture, read from the SARIF file."""

import copy
import uuid
from pathlib import Path

import psycopg
import pytest

from app.adapters import AdapterResult, Finding, FlowStep, Location
from app.runner.manifest import PluginManifest
from app.runner.runner import RunStatus
from app.store import PostgresRunStore, StoreError, load_sarif

FIXTURE = Path(__file__).parent / "adapter_fixture"
MANIFEST = Path(__file__).resolve().parents[2] / "plugins" / "semgrep" / "plugin.toml"
LAB = "dockerized_labs/sql_injection_lab/app.py"
PYGOAT = "https://github.com/adeyosemanputra/pygoat"
COMMIT = "2aa4cc14f251e4a780e94e200aed6b36a5b15c21"
SQL_RULE = "python.lang.security.audit.formatted-sql-query"


def load(database, data_dir):
    return load_sarif(
        database,
        data_dir,
        MANIFEST,
        FIXTURE / "semgrep-pygoat.sarif",
        FIXTURE / "pygoat",
        PYGOAT,
        COMMIT,
        image_digest="sha256:" + "8" * 64,
    )


@pytest.fixture(scope="module")
def loaded(database, tmp_path_factory):
    data_dir = tmp_path_factory.mktemp("data")
    return load(database, data_dir), data_dir


def test_loading_stores_a_completed_scan_with_one_succeeded_run(database, loaded):
    result, data_dir = loaded
    assert result.findings == 9 and result.dropped == {}
    with psycopg.connect(database) as conn:
        scan = conn.execute(
            "SELECT repo_url, commit_sha, status, languages, started_at IS NOT NULL,"
            " finished_at IS NOT NULL FROM scans WHERE id = %s",
            (result.scan_id,),
        ).fetchone()
        run = conn.execute(
            "SELECT plugin, image, tool_version, rules_version, status, reason, result_count,"
            " dropped_count, files_scanned, sarif_path FROM analyzer_runs WHERE id = %s",
            (result.run_id,),
        ).fetchone()
    assert scan == (PYGOAT, COMMIT, "completed", ["python"], True, True)
    assert run == (
        "semgrep",
        "sieve-plugin-semgrep:1.183.0-16b9e6d",
        "1.183.0",
        "semgrep-rules@16b9e6d45f10649f6a531ec4838ed9924372c3bc",
        "succeeded",
        None,
        9,
        0,
        None,
        f"runs/{result.run_id}/out/results.sarif",
    )
    assert (data_dir / "scans" / result.scan_id / "src" / LAB).is_file()
    assert (data_dir / "runs" / result.run_id / "out" / "results.sarif").read_bytes() == (
        FIXTURE / "semgrep-pygoat.sarif"
    ).read_bytes()


def test_the_example_finding_is_stored_as_in_docs_finding_format(database, loaded):
    result, _ = loaded
    with psycopg.connect(database) as conn:
        row = conn.execute(
            "SELECT run_id, tool, tool_version, rule_description, rule_help_uri, cwe, message,"
            " tool_severity, tool_score, tool_confidence, file, start_line, end_line,"
            " start_column, end_column, snippet, fingerprint, fingerprint_ambiguous,"
            " context_hash, suppressed, tool_fingerprint, language, hidden, group_id,"
            " raw -> 'locations' -> 0 -> 'physicalLocation' -> 'artifactLocation' ->> 'uri'"
            " FROM findings WHERE scan_id = %s AND rule_id = %s AND start_line = 57",
            (result.scan_id, SQL_RULE),
        ).fetchone()
    message = "Detected possible formatted SQL query. Use parameterized queries instead."
    assert row == (
        uuid.UUID(result.run_id),
        "semgrep",
        "1.183.0",
        message,
        None,
        ["CWE-89"],
        message,
        "warning",
        None,
        "low",
        LAB,
        57,
        57,
        22,
        42,
        "            result = c.execute(sql_query).fetchone()",
        "v1:418dc3c913dc63ec1ee12209f03b55f1",
        False,
        "c1:a5b7da088c06eb2371e6939f52ee1e61",
        False,
        None,
        "python",
        False,
        None,
        "/src/dockerized_labs/sql_injection_lab/app.py",
    )


def test_every_result_of_the_fixture_is_a_finding(database, loaded):
    result, _ = loaded
    with psycopg.connect(database) as conn:
        rows = conn.execute(
            "SELECT rule_id, start_line, end_line, tool_severity FROM findings"
            " WHERE scan_id = %s ORDER BY start_line, rule_id",
            (result.scan_id,),
        ).fetchall()
    assert rows == [
        ("python.flask.security.audit.avoid_hardcoded_config_SECRET_KEY", 7, 7, "error"),
        ("python.django.security.injection.sql.sql-injection-db-cursor-execute", 46, 69, "warning"),
        ("python.django.security.injection.sql.sql-injection-db-cursor-execute", 47, 69, "warning"),
        ("python.django.security.injection.tainted-sql-string", 50, 52, "error"),
        ("python.flask.security.injection.tainted-sql-string", 50, 52, "error"),
        (SQL_RULE, 57, 57, "warning"),
        ("python.sqlalchemy.security.sqlalchemy-execute-raw-query", 57, 57, "error"),
        ("python.flask.security.audit.avoid_app_run_with_bad_host", 78, 78, "warning"),
        ("python.flask.security.audit.debug-enabled", 78, 78, "warning"),
    ]


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


def test_a_load_that_fails_marks_its_scan_and_run_failed(database, tmp_path, monkeypatch):
    def fail(self, run, result):
        raise RuntimeError("disk full")

    monkeypatch.setattr(PostgresRunStore, "save_findings", fail)
    with pytest.raises(RuntimeError):
        load(database, tmp_path)

    with psycopg.connect(database) as conn:
        row = conn.execute(
            "SELECT s.status, s.error, r.status, r.reason FROM scans s"
            " JOIN analyzer_runs r ON r.scan_id = s.id ORDER BY s.created_at DESC LIMIT 1"
        ).fetchone()
    assert row == (
        "failed",
        "loading semgrep-pygoat.sarif failed: disk full",
        "failed",
        "runner_error",
    )
