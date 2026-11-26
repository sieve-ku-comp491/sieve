"""The scan and finding endpoints on the Semgrep fixture of PyGoat (tests/adapter_fixture),
loaded into the test database. The expected rules, lines and code are read from the fixture's
SARIF file and from dockerized_labs/sql_injection_lab/app.py."""

import json
import uuid
from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient

from app.api.deps import Settings
from app.main import create_app
from app.store import load_sarif

FIXTURE = Path(__file__).parent / "adapter_fixture"
PLUGINS = Path(__file__).resolve().parents[2] / "plugins"
MANIFEST = PLUGINS / "semgrep" / "plugin.toml"
LAB = "dockerized_labs/sql_injection_lab/app.py"
SQL_RULE = "python.lang.security.audit.formatted-sql-query"
TOKEN = "test-token"
PYGOAT = "https://github.com/adeyosemanputra/pygoat"
DJANGO_RULE = "python.django.security.injection.tainted-sql-string"
FLASK_RULE = "python.flask.security.injection.tainted-sql-string"
V4_KEYS = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]


def load(database, data_dir, manifest=MANIFEST, sarif="semgrep-pygoat.sarif", repo=PYGOAT) -> str:
    return load_sarif(
        database,
        data_dir,
        manifest,
        FIXTURE / sarif,
        FIXTURE / "pygoat",
        repo,
        "2aa4cc14f251e4a780e94e200aed6b36a5b15c21",
    ).scan_id


def make_client(database, data_dir) -> TestClient:
    app = create_app(Settings(token=TOKEN, database_url=database, data_dir=data_dir))
    return TestClient(
        app, base_url="http://localhost", headers={"Authorization": f"Bearer {TOKEN}"}
    )


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


@pytest.mark.parametrize("offset", [-1, 1_000_001, 9223372036854775808])
def test_an_offset_out_of_range_is_refused(client, scan_id, offset):
    assert client.get("/scans", params={"offset": offset}).status_code == 422
    response = client.get(f"/scans/{scan_id}/findings", params={"offset": offset})
    assert response.status_code == 422


def test_the_last_offset_allowed_gives_an_empty_page(client, scan_id):
    assert client.get("/scans", params={"offset": 1_000_000}).json() == []
    assert findings(client, scan_id, offset=1_000_000)["items"] == []


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


def insert_triage_run(conn, scan_id):
    """A triage run of the scan whose group step has finished."""
    return conn.execute(
        "INSERT INTO triage_runs (scan_id, cheap_model, strong_model, budget_usd, grouped_at)"
        " VALUES (%s, 'cheap', 'strong', 5, now()) RETURNING id",
        (scan_id,),
    ).fetchone()[0]


def insert_verdict(conn, run_id, finding=None, group=None):
    """A true positive of critical severity for the finding or the group."""
    return conn.execute(
        "INSERT INTO verdicts (triage_run_id, finding_id, group_id, verdict, reasoning,"
        " cited_lines, injection_suspected, model_version, cvss_v4_vector, cvss_v4_score,"
        " cvss_v4_level, cvss_v4_justifications) VALUES (%s, %s, %s, 'true_positive',"
        " 'f-string query', %s, false, 'm-1',"
        " 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', 9.3, 'critical', %s)"
        " RETURNING id",
        (
            run_id,
            finding,
            group,
            json.dumps([{"file": LAB, "start_line": 50, "end_line": 57}]),
            json.dumps(dict.fromkeys(V4_KEYS, "why")),
        ),
    ).fetchone()[0]


def test_a_verdict_and_an_edit_show_in_the_queue_and_the_detail(database, tmp_path):
    """A triage run that grouped a scan of its own and judged one finding. The edit changes
    only the verdict, so the severity stays the AI's."""
    scan_id = load(database, tmp_path)
    client = make_client(database, tmp_path)
    target = finding_id(client, scan_id, SQL_RULE, 57)
    with psycopg.connect(database) as conn:
        run_id = insert_triage_run(conn, scan_id)
        verdict_id = insert_verdict(conn, run_id, finding=target)

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


def test_a_group_with_its_verdict_and_its_cost_in_the_detail(database, tmp_path):
    """The two tainted-sql-string findings on line 50 grouped by a rule, with Django's as the
    representative, and judged together by one verdict that took two LLM calls, of 0.0012 and
    0.003 USD."""
    scan_id = load(database, tmp_path)
    client = make_client(database, tmp_path)
    django = finding_id(client, scan_id, DJANGO_RULE, 50)
    flask = finding_id(client, scan_id, FLASK_RULE, 50)
    with psycopg.connect(database) as conn:
        run_id = insert_triage_run(conn, scan_id)
        group_id = conn.execute(
            "INSERT INTO duplicate_groups (scan_id, representative_finding_id, method, rule,"
            " reason) VALUES (%s, %s, 'rule', 'nearby_lines_related_cwe', 'same line, CWE-89')"
            " RETURNING id",
            (scan_id, django),
        ).fetchone()[0]
        conn.execute(
            "UPDATE findings SET group_id = %s WHERE id IN (%s, %s)", (group_id, django, flask)
        )
        verdict_id = insert_verdict(conn, run_id, group=group_id)
        for role, cost in [("verdict", "0.0012"), ("severity", "0.003")]:
            call_id = conn.execute(
                "INSERT INTO llm_calls (provider, model, messages, cache_key, max_tokens,"
                " cost_usd, triage_run_id) VALUES ('anthropic', 'm-1', '[]', %s, 1000, %s, %s)"
                " RETURNING id",
                (f"api:{verdict_id}:{role}", cost, run_id),
            ).fetchone()[0]
            conn.execute(
                "INSERT INTO verdict_llm_calls (verdict_id, llm_call_id, role) VALUES (%s, %s, %s)",
                (verdict_id, call_id, role),
            )

    detail = client.get(f"/findings/{flask}").json()
    assert detail["state"] == "triaged" and detail["group_id"] == str(group_id)
    group = detail["group"]
    assert (group["id"], group["method"], group["rule"], group["similarity"]) == (
        str(group_id),
        "rule",
        "nearby_lines_related_cwe",
        None,
    )
    assert group["reason"] == "same line, CWE-89"
    assert group["representative_finding_id"] == django
    assert [(m["id"], m["rule_id"], m["start_line"], m["state"]) for m in group["members"]] == [
        (django, DJANGO_RULE, 50, "triaged"),
        (flask, FLASK_RULE, 50, "triaged"),
    ]
    verdict = detail["verdict"]
    assert (verdict["id"], verdict["group_id"], verdict["finding_id"]) == (
        str(verdict_id),
        str(group_id),
        None,
    )
    assert (verdict["call_count"], verdict["cost_usd"]) == (2, 0.0042)
    assert client.get(f"/findings/{django}").json()["verdict"]["id"] == str(verdict_id)
    page = findings(client, scan_id, status="triaged")
    assert sorted(item["id"] for item in page["items"]) == sorted([django, flask])
    assert {item["group_id"] for item in page["items"]} == {str(group_id)}


def test_a_carried_review_hides_the_finding_and_shows_in_the_detail(database, tmp_path):
    """Two scans of the same commit. The first scan's SQL finding on line 57 is rejected, so
    the second scan's finding with the same fingerprint and context is hidden with that
    review, and the queue and the counts leave it out. A repository URL of its own keeps the
    review from hiding findings of the other tests."""
    repo = f"https://example.test/{uuid.uuid4().hex}"
    first = load(database, tmp_path / "first", repo=repo)
    client = make_client(database, tmp_path / "second")
    earlier = finding_id(client, first, SQL_RULE, 57)
    with psycopg.connect(database) as conn:
        review_id = conn.execute(
            "INSERT INTO reviews (finding_id, decision, reviewer, comment)"
            " VALUES (%s, 'reject', 'Ali', 'the query is a constant') RETURNING id",
            (earlier,),
        ).fetchone()[0]
    second = load(database, tmp_path / "second", repo=repo)

    scan = client.get(f"/scans/{second}").json()
    assert (scan["finding_count"], scan["hidden_count"]) == (9, 1)
    assert (scan["state_counts"]["new"], scan["state_counts"]["rejected"]) == (8, 0)
    assert findings(client, second)["total"] == 8
    assert SQL_RULE not in [item["rule_id"] for item in findings(client, second)["items"]]
    (hidden,) = [
        item
        for item in findings(client, second, include_hidden=True)["items"]
        if item["rule_id"] == SQL_RULE
    ]
    assert (hidden["hidden"], hidden["state"]) == (True, "rejected")
    assert hidden["carried_review_id"] == str(review_id)
    detail = client.get(f"/findings/{hidden['id']}").json()
    assert (detail["hidden"], detail["matched_finding_id"]) == (True, earlier)
    assert detail["reviews"] == []
    carried = detail["carried_review"]
    assert (carried["id"], carried["decision"], carried["reviewer"], carried["comment"]) == (
        str(review_id),
        "reject",
        "Ali",
        "the query is a constant",
    )
    assert carried["verdict_id"] is None and carried["finding_edit_id"] is None


# The four Gitleaks results in this file, at lines 53, 59, 65 and 71, read from
# gitleaks-pygoat.sarif: a password hash in each user of USERS.
AUTH = "dockerized_labs/auth_failure_lab/app.py"
SECRET_LINES = (53, 59, 65, 71)


def load_gitleaks(database, data_dir) -> str:
    return load(database, data_dir, PLUGINS / "gitleaks" / "plugin.toml", "gitleaks-pygoat.sarif")


def test_every_secret_in_the_code_window_is_masked(database, tmp_path):
    """The code window of each finding at 53 and 59 holds the other one's line too. Both read
    REDACTED in both, as does any other Gitleaks line in the window, and the lines between
    them show as they are."""
    scan_id = load_gitleaks(database, tmp_path)
    client = make_client(database, tmp_path)
    source = (FIXTURE / "pygoat" / AUTH).read_text(encoding="utf-8").splitlines()
    secrets = [source[line - 1] for line in SECRET_LINES]
    for line, window, masked in [(53, (43, 63), (53, 59)), (59, (49, 69), (53, 59, 65))]:
        code = client.get(f"/findings/{finding_id(client, scan_id, 'generic-api-key', line)}")
        code = code.json()["code"]
        assert (code["file"], code["start_line"], code["end_line"]) == (AUTH, *window)
        assert not set(secrets) & set(code["lines"])
        for number, text in enumerate(code["lines"], start=window[0]):
            assert text == ("REDACTED" if number in masked else source[number - 1])
        assert code["lines"][58 - window[0]] == '        "role": "user",'


def test_the_code_window_of_a_long_finding_stops_at_200_lines(database, tmp_path):
    """The finding at line 71 made to span lines 20 to 238, the end of the file, as a private
    key or a finding on a whole class can. With 10 lines before and after, the window would be
    lines 10 to 238; it stops at 209, 200 lines in all."""
    scan_id = load_gitleaks(database, tmp_path)
    client = make_client(database, tmp_path)
    target = finding_id(client, scan_id, "generic-api-key", 71)
    with psycopg.connect(database) as conn:
        conn.execute("UPDATE findings SET start_line = 20, end_line = 238 WHERE id = %s", (target,))
    detail = client.get(f"/findings/{target}").json()
    assert (detail["location"]["start_line"], detail["location"]["end_line"]) == (20, 238)
    code = detail["code"]
    assert (code["start_line"], code["end_line"], len(code["lines"])) == (10, 209, 200)
    assert code["lines"][:2] == ["", 'app = Flask("app")']
    assert set(code["lines"][10:]) == {"REDACTED"}
