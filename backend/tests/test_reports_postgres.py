"""The report service on the findings store, with the real PyGoat findings of tests/adapter_fixture.

The model's answers come from a fake provider, and every call is logged in llm_calls, so a text's
llm_call_id points to a real row. The export check is the SQL of migration 0004. Skipped without
SIEVE_TEST_DATABASE_URL, like the other store tests.
"""

import json
import threading
import time
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import psycopg
import pytest

from app.llm.budget import Budget
from app.llm.cache import InMemoryResponseCache
from app.llm.catalog import Catalog, ModelInfo, Price
from app.llm.client import LLMClient
from app.llm.fake import FakeProvider
from app.llm.postgres import PostgresCallStore
from app.reports import (
    NotApproved,
    ReportError,
    ReportService,
    StaleVersion,
    UnknownReport,
)
from app.reports.postgres import PostgresReportStore
from app.store import load_sarif

FIXTURE = Path(__file__).parent / "adapter_fixture"
MANIFEST = Path(__file__).resolve().parents[2] / "plugins" / "semgrep" / "plugin.toml"
LAB = "dockerized_labs/sql_injection_lab/app.py"
FORMATTED_SQL = "python.lang.security.audit.formatted-sql-query"
CURSOR_EXECUTE = "python.django.security.injection.sql.sql-injection-db-cursor-execute"
RAW_QUERY = "python.sqlalchemy.security.sqlalchemy-execute-raw-query"
NOW = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)
VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
V4_KEYS = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]
OWASP = "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
CWE_89 = "https://cwe.mitre.org/data/definitions/89.html"
DRAFT = {
    "title": "SQL injection in the login form of the SQL injection lab",
    "summary": "The /lab route formats the user name and password into its SQL string.",
    "impact": "An unauthenticated attacker can log in as any user and read the users table.",
    "steps_to_reproduce": ["Open the /lab page.", "Enter admin' -- as the user name."],
    "fix": "Pass the values as query parameters to execute().",
    "references": [OWASP],
}


def reply(**changes) -> str:
    return json.dumps({**DRAFT, **changes})


@pytest.fixture
def scan(database, tmp_path) -> str:
    return load_sarif(
        database,
        tmp_path / "data",
        MANIFEST,
        FIXTURE / "semgrep-pygoat.sarif",
        FIXTURE / "pygoat",
        # A repository URL of its own, so the matching of repeated scans doesn't carry the
        # reviews of an earlier test into this one.
        f"https://github.com/adeyosemanputra/pygoat?test={uuid.uuid4().hex}",
        "2aa4cc14f251e4a780e94e200aed6b36a5b15c21",
    ).scan_id


def finding(database, scan, rule_id, line) -> str:
    with psycopg.connect(database) as conn:
        (row,) = conn.execute(
            """SELECT id::text FROM findings
               WHERE scan_id = %s AND rule_id = %s AND file = %s AND start_line = %s""",
            (scan, rule_id, LAB, line),
        ).fetchall()
    return row[0]


def triage(database, scan, finding_id=None, group_id=None, vector=VECTOR, score="9.3") -> str:
    """A finished triage run with a true-positive verdict on one finding or one group."""
    with psycopg.connect(database) as conn:
        run = conn.execute(
            """INSERT INTO triage_runs (scan_id, cheap_model, strong_model, budget_usd, status,
                   grouped_at) VALUES (%s, 'cheap', 'strong', 1, 'finished', now())
               RETURNING id""",
            (scan,),
        ).fetchone()[0]
        return str(
            conn.execute(
                """INSERT INTO verdicts (triage_run_id, finding_id, group_id, verdict, reasoning,
                       cited_lines, injection_suspected, model_version, cvss_v4_vector,
                       cvss_v4_score, cvss_v4_level, cvss_v4_justifications)
                   VALUES (%s, %s, %s, 'true_positive', %s, %s, false, 'fake-model-1', %s, %s,
                           'critical', %s)
                   RETURNING id""",
                (
                    run,
                    finding_id,
                    group_id,
                    "The user name reaches cursor.execute without parameters.",
                    json.dumps([{"file": LAB, "start_line": 52, "end_line": 57}]),
                    vector,
                    Decimal(score),
                    json.dumps({key: "a reason" for key in V4_KEYS}),
                ),
            ).fetchone()[0]
        )


def review(database, finding_id, decision="approve", edit_id=None) -> str:
    with psycopg.connect(database) as conn:
        return str(
            conn.execute(
                """INSERT INTO reviews (finding_id, decision, reviewer, finding_edit_id)
                   VALUES (%s, %s, 'ayse', %s) RETURNING id""",
                (finding_id, decision, edit_id),
            ).fetchone()[0]
        )


def group(database, scan, *finding_ids) -> str:
    with psycopg.connect(database) as conn:
        group_id = str(
            conn.execute(
                """INSERT INTO duplicate_groups (scan_id, representative_finding_id, method, rule,
                       reason) VALUES (%s, %s, 'rule', 'same-function', 'test group')
                   RETURNING id""",
                (scan, finding_ids[0]),
            ).fetchone()[0]
        )
        conn.execute(
            "UPDATE findings SET group_id = %s WHERE id = ANY(%s::uuid[])",
            (group_id, list(finding_ids)),
        )
    return group_id


def make_service(database, tmp_path, replies):
    calls = PostgresCallStore(database)
    client = LLMClient(
        providers={"fake": FakeProvider(replies=replies)},
        catalog=Catalog(
            {
                "fake-model": ModelInfo(
                    "fake-model",
                    "fake",
                    Price(
                        input=Decimal("1.00"),
                        output=Decimal("2.00"),
                        cache_read=Decimal("0.10"),
                        cache_write=Decimal("1.25"),
                    ),
                    temperature=False,
                )
            },
            checked_on="test",
        ),
        budget=Budget("1.00"),
        call_log=calls,
        # Each test has a cache of its own. The tests share one llm_calls table, and the same
        # finding gives the same prompt in every test.
        cache=InMemoryResponseCache(),
    )
    store = PostgresReportStore(database)
    service = ReportService(
        store, client, tmp_path / "exports", model="fake-model", max_tokens=1000, now=lambda: NOW
    )
    return service, store


class InBackground:
    """Runs one call in a thread, so a test can see it wait for a lock."""

    def __init__(self, call):
        self.error = None
        self.thread = threading.Thread(target=self._run, args=(call,))
        self.thread.start()

    def _run(self, call):
        try:
            call()
        except BaseException as error:
            self.error = error

    def waits_for_a_lock(self, database, seconds=5.0) -> bool:
        """True once a connection of the test database waits for a lock, False if the call
        finished first."""
        deadline = time.monotonic() + seconds
        with psycopg.connect(database, autocommit=True) as conn:
            while self.thread.is_alive() and time.monotonic() < deadline:
                (waiting,) = conn.execute(
                    "SELECT count(*) FROM pg_stat_activity"
                    " WHERE wait_event_type = 'Lock' AND datname = current_database()"
                ).fetchone()
                if waiting:
                    return True
                time.sleep(0.02)
        return False

    def finish(self):
        self.thread.join(10)
        assert not self.thread.is_alive()
        return self.error


def covered_findings(database, report_id) -> list[str]:
    with psycopg.connect(database) as conn:
        return [
            row[0]
            for row in conn.execute(
                "SELECT finding_id::text FROM report_findings WHERE report_id = %s", (report_id,)
            )
        ]


@pytest.fixture
def approved(database, scan):
    """The SQL injection finding on line 57, triaged and approved."""
    finding_id = finding(database, scan, FORMATTED_SQL, 57)
    triage(database, scan, finding_id=finding_id)
    review_id = review(database, finding_id)
    return finding_id, review_id


def test_a_real_pygoat_finding_from_draft_to_exported_markdown(database, tmp_path, approved):
    finding_id, review_id = approved
    service, store = make_service(database, tmp_path, [reply()])

    report = service.draft((finding_id,))
    assert report.finding_ids == (finding_id,) and report.version == 1
    assert report.references == (CWE_89, OWASP)
    assert report.severity.vector == VECTOR and report.severity.score == 9.3

    service.approve_text(report.report_id, 1, "ayse")
    content = service.export(report.report_id, exported_by="ayse")

    assert content.startswith(
        "# SQL injection in the login form of the SQL injection lab\n\n"
        "Severity: Critical (CVSS 4.0 score 9.3)\n"
    )
    path = tmp_path / "exports" / f"{report.report_id}.md"
    assert path.read_text() == content
    with psycopg.connect(database) as conn:
        status, exported_text, export_path, by = conn.execute(
            """SELECT r.status, t.version, r.export_path, r.exported_by FROM reports r
               JOIN report_texts t ON t.id = r.exported_text_id WHERE r.id = %s""",
            (report.report_id,),
        ).fetchone()
        (linked_review,) = conn.execute(
            "SELECT review_id::text FROM report_findings WHERE report_id = %s",
            (report.report_id,),
        ).fetchone()
        (state,) = conn.execute(
            "SELECT state FROM finding_states WHERE finding_id = %s", (finding_id,)
        ).fetchone()
    assert (status, exported_text, export_path, by) == ("exported", 1, str(path), "ayse")
    # F5, test 4: the exported report links to the review that approved the finding.
    assert linked_review == review_id
    assert state == "reported"


def test_the_draft_is_logged_in_llm_calls_with_its_prompt(database, tmp_path, approved):
    finding_id, _ = approved
    service, store = make_service(database, tmp_path, [reply()])
    report = service.draft((finding_id,))
    (text,) = store.texts(report.report_id)
    with psycopg.connect(database) as conn:
        template, messages = conn.execute(
            "SELECT template_name, messages FROM llm_calls WHERE id = %s", (text.llm_call_id,)
        ).fetchone()
    assert template == "report_draft"
    user = messages[-1]["content"]
    assert FORMATTED_SQL in user and "CWE-89" in user and LAB in user


def test_an_unreviewed_or_rejected_finding_gets_no_report(database, tmp_path, scan):
    finding_id = finding(database, scan, FORMATTED_SQL, 57)
    triage(database, scan, finding_id=finding_id)
    service, store = make_service(database, tmp_path, [reply(), reply()])
    with pytest.raises(NotApproved, match="is triaged, not approved"):
        service.draft((finding_id,))
    review(database, finding_id, "reject")
    with pytest.raises(NotApproved, match="is rejected, not approved"):
        service.draft((finding_id,))
    assert store.report_for((finding_id,)) is None


def test_a_finding_without_a_verdict_has_no_severity_for_a_report(database, tmp_path, scan):
    finding_id = finding(database, scan, FORMATTED_SQL, 57)
    review(database, finding_id)
    service, _ = make_service(database, tmp_path, [reply()])
    with pytest.raises(ReportError, match="no verdict"):
        service.draft((finding_id,))


def test_versions_are_kept_and_the_sql_check_refuses_text_no_one_approved(
    database, tmp_path, approved
):
    finding_id, _ = approved
    service, store = make_service(database, tmp_path, [reply(), reply(title="A second draft")])
    report_id = service.draft((finding_id,)).report_id
    service.approve_text(report_id, 1, "ayse")
    service.edit(report_id, {"fix": "Use parameters."}, "ayse")

    first, second = store.texts(report_id)
    assert (first.source, first.fix, first.approved_by) == ("llm_draft", DRAFT["fix"], "ayse")
    assert (second.source, second.author, second.approved_at) == ("reviewer_edit", "ayse", None)
    with pytest.raises(NotApproved, match="current report text is not approved"):
        service.export(report_id, exported_by="ayse")

    service.approve_text(report_id, 2, "ayse")
    redrafted = service.redraft(report_id)
    assert (redrafted.version, redrafted.title) == (3, "A second draft")
    with pytest.raises(NotApproved, match="current report text is not approved"):
        service.export(report_id, exported_by="ayse")
    exports = tmp_path / "exports"
    assert not exports.exists() or not list(exports.iterdir())


def test_a_finding_rejected_after_its_text_was_approved_blocks_the_export(
    database, tmp_path, approved
):
    finding_id, _ = approved
    service, _ = make_service(database, tmp_path, [reply()])
    report_id = service.draft((finding_id,)).report_id
    service.approve_text(report_id, 1, "ayse")
    review(database, finding_id, "reject")
    with pytest.raises(NotApproved, match="no approved finding in the report"):
        service.export(report_id, exported_by="ayse")
    assert service.get(report_id).status == "draft"


def test_a_group_report_waits_for_every_member_and_leaves_out_a_rejected_one(
    database, tmp_path, scan
):
    first = finding(database, scan, CURSOR_EXECUTE, 46)
    second = finding(database, scan, CURSOR_EXECUTE, 47)
    third = finding(database, scan, RAW_QUERY, 57)
    group_id = group(database, scan, first, second, third)
    triage(database, scan, group_id=group_id)
    first_review, second_review = review(database, first), review(database, second)
    service, _ = make_service(database, tmp_path, [reply()])

    report = service.draft((first, second))
    assert set(report.finding_ids) == {first, second}
    assert len(report.locations) == 2
    service.approve_text(report.report_id, 1, "ayse")

    # F5, test 3: the third member has no review yet, so the group can't be exported.
    with pytest.raises(NotApproved, match=f"finding {third} is triaged, not decided"):
        service.export(report.report_id, exported_by="ayse")
    assert not (tmp_path / "exports" / f"{report.report_id}.md").exists()

    review(database, third, "reject")
    service.export(report.report_id, exported_by="ayse")
    with psycopg.connect(database) as conn:
        covered = dict(
            conn.execute(
                "SELECT finding_id::text, review_id::text FROM report_findings"
                " WHERE report_id = %s",
                (report.report_id,),
            ).fetchall()
        )
    assert covered == {first: first_review, second: second_review}


def test_a_member_approved_after_the_draft_is_covered_at_export(database, tmp_path, scan):
    first = finding(database, scan, CURSOR_EXECUTE, 46)
    second = finding(database, scan, CURSOR_EXECUTE, 47)
    group_id = group(database, scan, first, second)
    triage(database, scan, group_id=group_id)
    review(database, first)
    service, _ = make_service(database, tmp_path, [reply()])
    report_id = service.draft((first,)).report_id
    service.approve_text(report_id, 1, "ayse")
    late = review(database, second)
    service.export(report_id, exported_by="ayse")
    with psycopg.connect(database) as conn:
        covered = dict(
            conn.execute(
                "SELECT finding_id::text, review_id::text FROM report_findings"
                " WHERE report_id = %s",
                (report_id,),
            ).fetchall()
        )
    assert covered[second] == late and set(covered) == {first, second}


def test_the_report_uses_the_reviewers_edited_severity_and_reasoning(database, tmp_path, scan):
    finding_id = finding(database, scan, FORMATTED_SQL, 57)
    verdict_id = triage(database, scan, finding_id=finding_id)
    edited = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"
    with psycopg.connect(database) as conn:
        edit_id = str(
            conn.execute(
                """INSERT INTO finding_edits (finding_id, verdict_id, editor, reasoning,
                       cvss_v4_vector, cvss_v4_score, cvss_v4_level)
                   VALUES (%s, %s, 'ayse', 'Only logged-in users reach this route.', %s, 7.1,
                           'high') RETURNING id""",
                (finding_id, verdict_id, edited),
            ).fetchone()[0]
        )
    review(database, finding_id, edit_id=edit_id)
    service, store = make_service(database, tmp_path, [reply()])

    report = service.draft((finding_id,))

    assert (report.severity.vector, report.severity.score, report.severity.level) == (
        edited,
        7.1,
        "high",
    )
    context = store.finding_context((finding_id,))
    assert context.reasoning == "Only logged-in users reach this route."
    assert context.justifications == {}  # the AI's reasons were for its own vector


def test_drafting_twice_makes_one_report_and_one_call(database, tmp_path, approved):
    finding_id, _ = approved
    service, store = make_service(database, tmp_path, [reply(), reply(title="Other")])
    first = service.draft((finding_id,))
    assert service.draft((finding_id,)).report_id == first.report_id
    with psycopg.connect(database) as conn:
        (count,) = conn.execute(
            "SELECT count(*) FROM reports WHERE finding_id = %s", (finding_id,)
        ).fetchone()
    assert count == 1


def test_unknown_ids(database, tmp_path):
    service, store = make_service(database, tmp_path, [])
    with pytest.raises(UnknownReport):
        service.get("not-a-uuid")
    with pytest.raises(UnknownReport):
        service.get("00000000-0000-4000-8000-000000000000")
    with pytest.raises(LookupError):
        store.finding_context(("00000000-0000-4000-8000-000000000000",))
    with pytest.raises(LookupError):
        store.finding_context(("not-a-uuid",))


def test_findings_from_different_groups_are_not_one_report(database, tmp_path, scan):
    first = finding(database, scan, FORMATTED_SQL, 57)
    second = finding(database, scan, RAW_QUERY, 57)
    _, store = make_service(database, tmp_path, [])
    with pytest.raises(ReportError, match="one duplicate group"):
        store.finding_context((first, second))


def test_the_store_refuses_a_report_whose_finding_was_rejected_after_the_service_checked(
    database, tmp_path, approved
):
    finding_id, _ = approved
    service, store = make_service(database, tmp_path, [reply()])
    report_id = service.draft((finding_id,)).report_id
    service.approve_text(report_id, 1, "ayse")
    # The service's own check has passed, and the finding is rejected before the store marks
    # the report. The store checks again in its transaction.
    review(database, finding_id, "reject")

    with pytest.raises(NotApproved, match="no approved finding"):
        store.mark_exported(report_id, 1, str(tmp_path / "x.md"), "ayse", NOW)

    assert service.get(report_id).status == "draft"


def test_a_member_rejected_after_the_draft_is_left_out_of_the_new_draft_and_the_export(
    database, tmp_path, scan
):
    first = finding(database, scan, CURSOR_EXECUTE, 46)
    second = finding(database, scan, CURSOR_EXECUTE, 47)
    third = finding(database, scan, RAW_QUERY, 57)
    group_id = group(database, scan, first, second, third)
    triage(database, scan, group_id=group_id)
    reviews = {fid: review(database, fid) for fid in (first, second, third)}
    service, _ = make_service(database, tmp_path, [reply(), reply(title="Two findings")])
    report_id = service.draft((first, second, third)).report_id
    service.approve_text(report_id, 1, "ayse")
    # Deduplication put the third finding in the wrong group, and the reviewer says so.
    review(database, third, "reject")

    # The text was drafted for three places, so the export asks for a new draft.
    with pytest.raises(NotApproved, match="ask for a new draft"):
        service.export(report_id, exported_by="ayse")
    service.redraft(report_id)
    service.approve_text(report_id, 2, "ayse")
    service.export(report_id, exported_by="ayse")

    with psycopg.connect(database) as conn:
        covered = dict(
            conn.execute(
                "SELECT finding_id::text, review_id::text FROM report_findings"
                " WHERE report_id = %s",
                (report_id,),
            ).fetchall()
        )
    assert covered == {first: reviews[first], second: reviews[second]}


def test_an_export_waits_for_a_review_that_is_being_written(database, tmp_path, approved):
    finding_id, _ = approved
    service, store = make_service(database, tmp_path, [reply()])
    report_id = service.draft((finding_id,)).report_id
    service.approve_text(report_id, 1, "ayse")

    with psycopg.connect(database) as other:
        other.execute(
            "INSERT INTO reviews (finding_id, decision, reviewer) VALUES (%s, 'reject', 'ayse')",
            (finding_id,),
        )
        export = InBackground(
            lambda: store.mark_exported(report_id, 1, str(tmp_path / "x.md"), "ayse", NOW)
        )
        assert export.waits_for_a_lock(database), "the export didn't wait for the review"
        other.commit()

    # The review is seen once the export goes on, so the report keeps its finding and stays a
    # draft instead of being exported with no finding (F5, test 1).
    assert isinstance(export.finish(), NotApproved)
    assert service.get(report_id).status == "draft"
    assert covered_findings(database, report_id) == [finding_id]


def test_an_export_that_would_cover_no_finding_is_refused(
    database, tmp_path, approved, monkeypatch
):
    finding_id, _ = approved
    service, store = make_service(database, tmp_path, [reply()])
    report_id = service.draft((finding_id,)).report_id
    service.approve_text(report_id, 1, "ayse")
    monkeypatch.setattr(store, "_approved_members", lambda conn, report: [])

    with pytest.raises(NotApproved, match="no approved finding"):
        store.mark_exported(report_id, 1, str(tmp_path / "x.md"), "ayse", NOW)

    assert service.get(report_id).status == "draft"
    assert covered_findings(database, report_id) == [finding_id]


def test_the_store_exports_only_the_newest_text(database, tmp_path, approved):
    finding_id, _ = approved
    service, store = make_service(database, tmp_path, [reply()])
    report_id = service.draft((finding_id,)).report_id
    service.approve_text(report_id, 1, "ayse")
    service.edit(report_id, {"fix": "Use parameters."}, "ayse")
    service.approve_text(report_id, 2, "ayse")

    # A service that read version 1 before the edit was saved asks to export it.
    with pytest.raises(StaleVersion):
        store.mark_exported(report_id, 1, str(tmp_path / "x.md"), "ayse", NOW)

    assert service.get(report_id).status == "draft"
