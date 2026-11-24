"""The approve, reject and edit endpoints on the Semgrep fixture of PyGoat, with the state
changes of docs/finding-states.md. Each test loads a scan of its own and adds the triage rows
it needs, since triage itself isn't built yet."""

import json

import psycopg
import pytest

from tests.test_api_findings import LAB, SQL_RULE, V4_KEYS, finding_id, findings, load, make_client

AI_VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
LOW_VECTOR = "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
CURSOR_RULE = "python.django.security.injection.sql.sql-injection-db-cursor-execute"
UI = {"Origin": "http://localhost:8080"}


@pytest.fixture
def scan(database, tmp_path):
    scan_id = load(database, tmp_path)
    return make_client(database, tmp_path), scan_id


def triage_run(database, scan_id) -> str:
    with psycopg.connect(database) as conn:
        return conn.execute(
            "INSERT INTO triage_runs (scan_id, cheap_model, strong_model, budget_usd, grouped_at)"
            " VALUES (%s, 'cheap', 'strong', 5, now()) RETURNING id",
            (scan_id,),
        ).fetchone()[0]


def add_verdict(database, run_id, finding=None, group=None) -> str:
    with psycopg.connect(database) as conn:
        return conn.execute(
            "INSERT INTO verdicts (triage_run_id, finding_id, group_id, verdict, reasoning,"
            " cited_lines, injection_suspected, model_version, cvss_v4_vector, cvss_v4_score,"
            " cvss_v4_level, cvss_v4_justifications) VALUES (%s, %s, %s, 'true_positive',"
            " 'f-string query', %s, false, 'm-1', %s, 9.3, 'critical', %s) RETURNING id",
            (
                run_id,
                finding,
                group,
                json.dumps([{"file": LAB, "start_line": 50, "end_line": 57}]),
                AI_VECTOR,
                json.dumps(dict.fromkeys(V4_KEYS, "why")),
            ),
        ).fetchone()[0]


@pytest.fixture
def triaged(database, scan):
    """The SQL finding on line 57 with a verdict, the others of the scan grouped only."""
    client, scan_id = scan
    target = finding_id(client, scan_id, SQL_RULE, 57)
    add_verdict(database, triage_run(database, scan_id), finding=target)
    return client, scan_id, target


def decide(client, target, decision, seen=None, **extra):
    body = {"decision": decision, "reviewer": "Furkan", "finding_edit_id": seen} | extra
    return client.post(f"/findings/{target}/reviews", json=body, headers=UI)


def edit(client, target, **fields):
    return client.post(f"/findings/{target}/edits", json={"editor": "Furkan"} | fields, headers=UI)


def state(client, target):
    return client.get(f"/findings/{target}").json()["state"]


def test_nothing_is_decided_or_edited_before_triage(scan):
    client, scan_id = scan
    target = finding_id(client, scan_id, SQL_RULE, 57)
    for response in (decide(client, target, "approve"), edit(client, target, verdict="unsure")):
        assert response.status_code == 409
        assert response.json()["detail"] == (
            "the finding has no verdict yet: triage hasn't checked it"
        )
    assert state(client, target) == "new"


def test_a_grouped_finding_without_its_verdict_is_refused_too(triaged):
    client, scan_id, _ = triaged
    other = finding_id(client, scan_id, CURSOR_RULE, 46)
    assert state(client, other) == "grouped"
    assert decide(client, other, "approve").status_code == 409


def test_approve_saves_a_review_with_the_verdict(database, triaged):
    client, _, target = triaged
    response = decide(client, target, "approve", comment="confirmed by hand")
    assert response.status_code == 201, response.text
    saved = response.json()
    assert (saved["decision"], saved["reviewer"], saved["state"]) == (
        "approve",
        "Furkan",
        "approved",
    )
    assert saved["comment"] == "confirmed by hand" and saved["finding_edit_id"] is None
    detail = client.get(f"/findings/{target}").json()
    assert detail["state"] == "approved"
    assert detail["reviews"][0]["id"] == saved["id"]
    assert saved["verdict_id"] == detail["verdict"]["id"]


def test_the_latest_decision_counts(triaged):
    client, scan_id, target = triaged
    assert decide(client, target, "approve").json()["state"] == "approved"
    assert decide(client, target, "reject", comment="test code").json()["state"] == "rejected"
    assert findings(client, scan_id, status="rejected")["total"] == 1
    assert decide(client, target, "approve").json()["state"] == "approved"
    reviews = client.get(f"/findings/{target}").json()["reviews"]
    assert [review["decision"] for review in reviews] == ["approve", "reject", "approve"]


def test_an_edit_keeps_the_ai_verdict_and_carries_earlier_edits(triaged):
    client, scan_id, target = triaged
    first = edit(client, target, verdict="unsure", note="needs a look")
    assert first.status_code == 201, first.text
    assert first.json()["state"] == "edited"
    second = edit(client, target, cvss_v4_vector=LOW_VECTOR)
    assert second.status_code == 201, second.text
    latest = second.json()
    assert (latest["verdict"], latest["reasoning"], latest["note"]) == ("unsure", None, None)
    assert (latest["cvss_v4_vector"], latest["cvss_v4_score"], latest["cvss_v4_level"]) == (
        LOW_VECTOR,
        4.8,
        "medium",
    )
    detail = client.get(f"/findings/{target}").json()
    assert detail["verdict"]["verdict"] == "true_positive"
    assert detail["verdict"]["cvss_v4_score"] == 9.3
    assert detail["latest_edit"]["id"] == latest["id"]
    (item,) = findings(client, scan_id, status="edited")["items"]
    assert (item["verdict"], item["severity"], item["score"]) == ("unsure", "medium", 4.8)


def test_the_vector_is_written_in_the_standard_order(triaged):
    client, _, target = triaged
    shuffled = "CVSS:4.0/SA:N/SI:N/SC:N/VA:N/VI:N/VC:L/UI:N/PR:L/AT:N/AC:L/AV:L"
    assert edit(client, target, cvss_v4_vector=shuffled).json()["cvss_v4_vector"] == LOW_VECTOR


def test_an_edit_undoes_an_approval_until_the_edit_is_approved(triaged):
    client, _, target = triaged
    decide(client, target, "approve")
    edit_id = edit(client, target, reasoning="only reachable by an admin").json()["id"]
    assert state(client, target) == "edited"

    stale = decide(client, target, "approve", seen=None)
    assert stale.status_code == 409
    assert "edited since you opened it" in stale.json()["detail"]
    assert state(client, target) == "edited"

    approved = decide(client, target, "approve", seen=edit_id).json()
    assert (approved["state"], approved["finding_edit_id"]) == ("approved", edit_id)


def test_an_edit_after_a_rejection_waits_for_a_new_decision(triaged):
    client, _, target = triaged
    decide(client, target, "reject")
    edit_id = edit(client, target, verdict="false_positive").json()["id"]
    assert state(client, target) == "edited"
    assert decide(client, target, "reject", seen=edit_id).json()["state"] == "rejected"


def test_members_of_a_group_share_its_verdict(database, scan):
    client, scan_id = scan
    members = [finding_id(client, scan_id, CURSOR_RULE, line) for line in (46, 47)]
    with psycopg.connect(database) as conn:
        group = conn.execute(
            "INSERT INTO duplicate_groups (scan_id, method, rule, reason)"
            " VALUES (%s, 'rule', 'same function', 'same query') RETURNING id",
            (scan_id,),
        ).fetchone()[0]
        conn.execute("UPDATE findings SET group_id = %s WHERE id = ANY(%s)", (group, members))
    verdict = add_verdict(database, triage_run(database, scan_id), group=group)

    assert [state(client, member) for member in members] == ["triaged", "triaged"]
    assert edit(client, members[0], verdict="unsure").json()["verdict_id"] == str(verdict)
    assert decide(client, members[1], "reject").json()["state"] == "rejected"
    assert state(client, members[0]) == "edited"


def test_a_reported_finding_is_final(database, triaged):
    client, _, target = triaged
    review = decide(client, target, "approve").json()["id"]
    with psycopg.connect(database) as conn:
        report = conn.execute(
            "INSERT INTO reports (finding_id) VALUES (%s) RETURNING id", (target,)
        ).fetchone()[0]
        text = conn.execute(
            "INSERT INTO report_texts (report_id, version, source, author, title, summary,"
            ' impact, steps_to_reproduce, fix, "references", cvss_v4_vector, cvss_v4_score,'
            " cvss_v4_level, locations, approved_by, approved_at) VALUES (%s, 1,"
            " 'reviewer_edit', 'Furkan', 't', 's', 'i', '{step}', 'f', '{CWE-89}', %s, 9.3,"
            " 'critical', %s, 'Furkan', now()) RETURNING id",
            (report, AI_VECTOR, json.dumps([{"file": LAB, "start_line": 57}])),
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO report_findings (report_id, finding_id, review_id) VALUES (%s, %s, %s)",
            (report, target, review),
        )
        conn.execute(
            "UPDATE reports SET status = 'exported', exported_text_id = %s, export_path = 'x.md',"
            " exported_by = 'Furkan', exported_at = now() WHERE id = %s",
            (text, report),
        )
    assert state(client, target) == "reported"
    for response in (decide(client, target, "reject"), edit(client, target, verdict="unsure")):
        assert response.status_code == 409
        assert response.json()["detail"] == "the finding is reported: its report has been exported"


def test_a_hidden_finding_can_get_a_decision_of_its_own(database, triaged):
    """A finding hidden in a repeated scan counts with the earlier review until it gets its
    own, which then counts instead."""
    client, scan_id, target = triaged
    earlier = decide(client, target, "approve").json()["id"]
    repeat = load(database, client.app.state.settings.data_dir)
    hidden = finding_id(client, repeat, SQL_RULE, 57)
    with psycopg.connect(database) as conn:
        conn.execute(
            "UPDATE findings SET hidden = true, carried_review_id = %s, matched_finding_id = %s"
            " WHERE id = %s",
            (earlier, target, hidden),
        )
    assert state(client, hidden) == "approved"
    assert decide(client, hidden, "reject").json()["state"] == "rejected"
    assert state(client, target) == "approved"


@pytest.mark.parametrize(
    ("vector", "reason"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "starts with CVSS:4.0/"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N", "11 base metrics"),
        (AI_VECTOR + "/E:A", "11 base metrics"),
        (AI_VECTOR.replace("AV:N", "AV:Q"), "AV"),
    ],
)
def test_a_vector_that_isnt_a_v4_base_vector_is_refused(triaged, vector, reason):
    client, _, target = triaged
    response = edit(client, target, cvss_v4_vector=vector)
    assert response.status_code == 422
    assert reason in response.json()["detail"]
    assert state(client, target) == "triaged"


@pytest.mark.parametrize(
    "body",
    [
        {"editor": "Furkan"},
        {"editor": "Furkan", "note": "only a note"},
        {"editor": "  ", "verdict": "unsure"},
        {"editor": "Furkan", "verdict": "maybe"},
        {"editor": "Furkan", "verdict": "unsure", "cvss_v4_score": 1.0},
    ],
)
def test_an_edit_that_changes_nothing_or_is_malformed_is_refused(triaged, body):
    client, _, target = triaged
    response = client.post(f"/findings/{target}/edits", json=body, headers=UI)
    assert response.status_code == 422


@pytest.mark.parametrize(
    "body",
    [
        {"decision": "approve", "reviewer": "Furkan"},
        {"decision": "maybe", "reviewer": "Furkan", "finding_edit_id": None},
        {"decision": "approve", "reviewer": "", "finding_edit_id": None},
        {"decision": "approve", "reviewer": "Furkan", "finding_edit_id": "not-a-uuid"},
    ],
)
def test_a_malformed_decision_is_refused(triaged, body):
    client, _, target = triaged
    response = client.post(f"/findings/{target}/reviews", json=body, headers=UI)
    assert response.status_code == 422
    assert state(client, target) == "triaged"


def test_an_unknown_finding_is_not_found(triaged):
    client, _, _ = triaged
    unknown = "00000000-0000-0000-0000-000000000000"
    assert decide(client, unknown, "approve").status_code == 404
    assert edit(client, unknown, verdict="unsure").status_code == 404


@pytest.mark.parametrize(
    "origin", ["https://example.com", "http://localhost:8081", "null", "http://localhost.evil"]
)
def test_another_web_page_cant_decide(triaged, origin):
    client, _, target = triaged
    body = {"decision": "approve", "reviewer": "Furkan", "finding_edit_id": None}
    response = client.post(f"/findings/{target}/reviews", json=body, headers={"Origin": origin})
    assert response.status_code == 403
    assert state(client, target) == "triaged"


@pytest.mark.parametrize("content_type", ["text/plain", "application/x-www-form-urlencoded", None])
def test_only_a_json_body_is_taken(triaged, content_type):
    """A page on another site can send text/plain or a form, or a body with no type at all,
    without the browser asking first. Even with the JSON inside, they are refused."""
    client, _, target = triaged
    body = json.dumps({"decision": "approve", "reviewer": "Furkan", "finding_edit_id": None})
    headers = {} if content_type is None else {"Content-Type": content_type}
    request = client.build_request("POST", f"/findings/{target}/reviews", content=body)
    request.headers.pop("content-type", None)
    request.headers.update(headers)
    assert client.send(request).status_code == 415
    assert state(client, target) == "triaged"


def test_the_cli_without_an_origin_can_decide(triaged):
    client, _, target = triaged
    body = {"decision": "reject", "reviewer": "cli", "finding_edit_id": None}
    response = client.post(f"/findings/{target}/reviews", json=body)
    assert response.status_code == 201


def test_the_ui_origins_can_be_configured(triaged, monkeypatch):
    client, _, target = triaged
    monkeypatch.setenv("SIEVE_UI_ORIGINS", "http://localhost:3000")
    assert decide(client, target, "approve").status_code == 403
    body = {"decision": "approve", "reviewer": "Furkan", "finding_edit_id": None}
    headers = {"Origin": "http://localhost:3000"}
    assert client.post(f"/findings/{target}/reviews", json=body, headers=headers).status_code == 201


def test_the_token_is_still_needed(triaged):
    client, _, target = triaged
    body = {"decision": "approve", "reviewer": "Furkan", "finding_edit_id": None}
    headers = UI | {"Authorization": "Bearer wrong"}
    response = client.post(f"/findings/{target}/reviews", json=body, headers=headers)
    assert response.status_code == 401
