"""The scan and finding endpoints on the Semgrep fixture of PyGoat (tests/adapter_fixture),
loaded into the test database. The expected rules, lines and code are read from the fixture's
SARIF file and from dockerized_labs/sql_injection_lab/app.py."""

import json
from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient

from app.api.deps import Settings
from app.main import create_app
from app.store import load_sarif

FIXTURE = Path(__file__).parent / "adapter_fixture"
MANIFEST = Path(__file__).resolve().parents[2] / "plugins" / "semgrep" / "plugin.toml"
LAB = "dockerized_labs/sql_injection_lab/app.py"
SQL_RULE = "python.lang.security.audit.formatted-sql-query"
V4_KEYS = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]


def load(database, data_dir) -> str:
    return load_sarif(
        database,
        data_dir,
        MANIFEST,
        FIXTURE / "semgrep-pygoat.sarif",
        FIXTURE / "pygoat",
        "https://github.com/adeyosemanputra/pygoat",
        "2aa4cc14f251e4a780e94e200aed6b36a5b15c21",
    ).scan_id


def make_client(database, data_dir) -> TestClient:
    app = create_app(Settings(database_url=database, data_dir=data_dir))
    return TestClient(app, base_url="http://localhost")


@pytest.fixture(scope="module")
def setup(database, tmp_path_factory):
    data_dir = tmp_path_factory.mktemp("data")
    scan_id = load(database, data_dir)
    return make_client(database, data_dir), scan_id


@pytest.fixture(scope="module")
def client(setup):
    return setup[0]


@pytest.fixture(scope="module")
def scan_id(setup):
    return setup[1]


def findings(client, scan_id, **params):
    response = client.get(f"/scans/{scan_id}/findings", params=params)
    assert response.status_code == 200, response.text
    return response.json()


def rules_and_lines(page):
    return [(item["rule_id"], item["start_line"]) for item in page["items"]]


def finding_id(client, scan_id, rule_id, line):
    (item,) = [
        item
        for item in findings(client, scan_id, q=rule_id)["items"]
        if item["rule_id"] == rule_id and item["start_line"] == line
    ]
    return item["id"]


def test_the_scan_is_listed_with_its_run_and_counts(client, scan_id):
    assert scan_id in [scan["id"] for scan in client.get("/scans").json()]
    scan = client.get(f"/scans/{scan_id}").json()
    assert scan["status"] == "completed" and scan["finding_count"] == 9
    assert scan["state_counts"] == {
        "new": 9,
        "grouped": 0,
        "triaged": 0,
        "edited": 0,
        "approved": 0,
        "rejected": 0,
        "reported": 0,
    }
    assert scan["hidden_count"] == 0 and scan["triage_run"] is None
    (run,) = scan["runs"]
    assert (run["plugin"], run["status"], run["result_count"]) == ("semgrep", "succeeded", 9)


def test_before_triage_findings_come_by_tool_severity_then_file_and_line(client, scan_id):
    page = findings(client, scan_id)
    assert page["total"] == 9
    assert rules_and_lines(page) == [
        ("python.flask.security.audit.avoid_hardcoded_config_SECRET_KEY", 7),
        ("python.django.security.injection.tainted-sql-string", 50),
        ("python.flask.security.injection.tainted-sql-string", 50),
        ("python.sqlalchemy.security.sqlalchemy-execute-raw-query", 57),
        ("python.django.security.injection.sql.sql-injection-db-cursor-execute", 46),
        ("python.django.security.injection.sql.sql-injection-db-cursor-execute", 47),
        (SQL_RULE, 57),
        ("python.flask.security.audit.avoid_app_run_with_bad_host", 78),
        ("python.flask.security.audit.debug-enabled", 78),
    ]
    item = page["items"][6]
    assert item["state"] == "new" and item["file"] == LAB and item["cwe"] == ["CWE-89"]
    assert (item["verdict"], item["severity"], item["score"]) == (None, None, None)


def test_pages(client, scan_id):
    page = findings(client, scan_id, limit=2, offset=3)
    assert (page["total"], page["limit"], page["offset"]) == (9, 2, 3)
    assert rules_and_lines(page) == [
        ("python.sqlalchemy.security.sqlalchemy-execute-raw-query", 57),
        ("python.django.security.injection.sql.sql-injection-db-cursor-execute", 46),
    ]


@pytest.mark.parametrize(
    ("params", "total"),
    [
        ({"tool_severity": "error"}, 4),
        ({"tool_severity": ["error", "warning"]}, 9),
        ({"tool": "semgrep"}, 9),
        ({"tool": "bandit"}, 0),
        ({"status": "new"}, 9),
        ({"status": ["triaged", "edited"]}, 0),
        ({"q": "tainted-sql"}, 2),
        ({"q": "SQL_INJECTION_LAB/"}, 9),
        ({"q": "%"}, 0),
        ({"verdict": "true_positive"}, 0),
        ({"severity": "critical"}, 0),
    ],
)
def test_filters(client, scan_id, params, total):
    assert findings(client, scan_id, **params)["total"] == total


def test_a_filter_value_that_isnt_allowed_is_refused(client, scan_id):
    response = client.get(f"/scans/{scan_id}/findings", params={"status": "open"})
    assert response.status_code == 422


def test_an_unknown_scan_or_finding_is_not_found(client):
    unknown = "00000000-0000-0000-0000-000000000000"
    assert client.get(f"/scans/{unknown}").status_code == 404
    assert client.get(f"/scans/{unknown}/findings").status_code == 404
    assert client.get(f"/findings/{unknown}").status_code == 404
    assert client.get("/findings/not-a-uuid").status_code == 422


def test_one_finding_with_its_location_and_code(client, scan_id):
    detail = client.get(f"/findings/{finding_id(client, scan_id, SQL_RULE, 57)}").json()
    assert detail["location"] == {
        "file": LAB,
        "start_line": 57,
        "end_line": 57,
        "start_column": 22,
        "end_column": 42,
        "snippet": "            result = c.execute(sql_query).fetchone()",
        "message": None,
    }
    assert detail["fingerprint"] == "v1:418dc3c913dc63ec1ee12209f03b55f1"
    assert detail["related_locations"] == [] and detail["data_flow"] == []
    assert detail["raw"]["ruleId"] == SQL_RULE
    code = detail["code"]
    assert (code["file"], code["start_line"], code["end_line"]) == (LAB, 47, 67)
    assert len(code["lines"]) == 21
    assert code["lines"][0] == '        password = request.form.get("password", "")'
    assert code["lines"][10] == "            result = c.execute(sql_query).fetchone()"
    assert code["lines"][-1] == "                )"
    assert detail["state"] == "new"
    assert detail["verdict"] is None and detail["latest_edit"] is None
    assert detail["reviews"] == [] and detail["carried_review"] is None
    assert detail["group"] is None


def test_the_code_stops_at_the_ends_of_the_file(client, scan_id):
    rule = "python.flask.security.audit.debug-enabled"
    code = client.get(f"/findings/{finding_id(client, scan_id, rule, 78)}").json()["code"]
    assert (code["start_line"], code["end_line"], len(code["lines"])) == (68, 78, 11)
    assert code["lines"][-1] == '    app.run(host="0.0.0.0", port=5012, debug=True)'
    rule = "python.flask.security.audit.avoid_hardcoded_config_SECRET_KEY"
    code = client.get(f"/findings/{finding_id(client, scan_id, rule, 7)}").json()["code"]
    assert (code["start_line"], code["end_line"]) == (1, 17)
    assert code["lines"][0] == "from flask import Flask, render_template, request"


def test_without_the_checkout_the_code_is_empty(database, scan_id, tmp_path):
    client = make_client(database, tmp_path)
    detail = client.get(f"/findings/{finding_id(client, scan_id, SQL_RULE, 57)}").json()
    assert detail["code"] is None


def test_a_verdict_and_an_edit_show_in_the_queue_and_the_detail(database, tmp_path):
    """A triage run that grouped a scan of its own and judged one finding. The edit changes
    only the verdict, so the severity stays the AI's."""
    scan_id = load(database, tmp_path)
    client = make_client(database, tmp_path)
    target = finding_id(client, scan_id, SQL_RULE, 57)
    with psycopg.connect(database) as conn:
        run_id = conn.execute(
            "INSERT INTO triage_runs (scan_id, cheap_model, strong_model, budget_usd, grouped_at)"
            " VALUES (%s, 'cheap', 'strong', 5, now()) RETURNING id",
            (scan_id,),
        ).fetchone()[0]
        verdict_id = conn.execute(
            "INSERT INTO verdicts (triage_run_id, finding_id, verdict, reasoning, cited_lines,"
            " injection_suspected, model_version, cvss_v4_vector, cvss_v4_score, cvss_v4_level,"
            " cvss_v4_justifications) VALUES (%s, %s, 'true_positive', 'f-string query',"
            " %s, false, 'm-1', 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',"
            " 9.3, 'critical', %s) RETURNING id",
            (
                run_id,
                target,
                json.dumps([{"file": LAB, "start_line": 50, "end_line": 57}]),
                json.dumps(dict.fromkeys(V4_KEYS, "why")),
            ),
        ).fetchone()[0]

    page = findings(client, scan_id)
    assert page["items"][0]["id"] == target
    assert (page["items"][0]["verdict"], page["items"][0]["severity"]) == (
        "true_positive",
        "critical",
    )
    assert page["items"][0]["score"] == 9.3
    assert findings(client, scan_id, severity="critical")["total"] == 1
    assert findings(client, scan_id, status="triaged")["total"] == 1
    assert findings(client, scan_id, status="grouped")["total"] == 8

    with psycopg.connect(database) as conn:
        conn.execute(
            "INSERT INTO finding_edits (finding_id, verdict_id, editor, verdict, note)"
            " VALUES (%s, %s, 'Furkan', 'unsure', 'needs a look')",
            (target, verdict_id),
        )

    assert findings(client, scan_id, verdict="unsure")["total"] == 1
    assert findings(client, scan_id, verdict="true_positive")["total"] == 0
    assert findings(client, scan_id, status="edited")["total"] == 1
    detail = client.get(f"/findings/{target}").json()
    assert detail["state"] == "edited"
    assert detail["verdict"]["verdict"] == "true_positive"
    assert detail["verdict"]["cvss_v4_score"] == 9.3
    assert detail["verdict"]["call_count"] == 0
    assert detail["latest_edit"]["verdict"] == "unsure"
    assert detail["latest_edit"]["editor"] == "Furkan"
    counts = client.get(f"/scans/{scan_id}").json()["state_counts"]
    assert (counts["edited"], counts["grouped"], counts["new"]) == (1, 8, 0)
    assert client.get(f"/scans/{scan_id}").json()["triage_run"]["id"] == str(run_id)
