"""Grouping a stored scan, saving its groups, and writing them as the evaluation's CSV
(requirement F3, tests 1 and 2, docs/evaluation.md).

The PyGoat tests load the Semgrep fixture (tests/adapter_fixture). Its rules, lines, CWEs and
levels were read from semgrep-pygoat.sarif: the four results tagged CWE-89 are in lab(), lines
42 to 71 of dockerized_labs/sql_injection_lab/app.py, and the one at line 57 from
sqlalchemy-execute-raw-query is the only one of them at level error. The results at lines 7
and 78 are outside any function and have unrelated CWEs (CWE-489, CWE-668 and CWE-489, 71
lines apart). docs/finding-format.md counts all six SQL injection results as one bug, which is
what the hand-labeled CSV below says.
"""

import csv
import io
import json
import uuid
from decimal import Decimal
from pathlib import Path

import psycopg
import pytest

from app.adapters import AdapterResult, Finding, Location
from app.dedup import (
    NEARBY,
    SAME_FUNCTION,
    FunctionSpan,
    Group,
    GroupingError,
    LLMStep,
    SimilarityStep,
    group_scan,
)
from app.dedup.__main__ import main as dedup_main
from app.dedup.store import save_groups, scan_findings, write_groups_csv
from app.eval.__main__ import main as eval_main
from app.llm.budget import Budget
from app.llm.catalog import Catalog, ModelInfo, Price
from app.llm.client import LLMClient
from app.llm.fake import FakeProvider
from app.llm.postgres import PostgresCallStore
from app.runner.manifest import PluginManifest
from app.runner.runner import RunStatus
from app.store import PostgresRunStore, load_sarif

FIXTURE = Path(__file__).parent / "adapter_fixture"
MANIFEST = Path(__file__).resolve().parents[2] / "plugins" / "semgrep" / "plugin.toml"
COMMIT = "2aa4cc14f251e4a780e94e200aed6b36a5b15c21"
LAB = "dockerized_labs/sql_injection_lab/app.py"
VIEWS = "introduction/views.py"
SQL_RULES = [
    ("python.django.security.injection.sql.sql-injection-db-cursor-execute", 46),
    ("python.django.security.injection.sql.sql-injection-db-cursor-execute", 47),
    ("python.lang.security.audit.formatted-sql-query", 57),
    ("python.sqlalchemy.security.sqlalchemy-execute-raw-query", 57),
]


class FakeLookup:
    def __init__(self, file: str, *functions: FunctionSpan):
        self._file, self._functions = file, functions

    def enclosing_function(self, file, line):
        if file != self._file:
            return None
        return next((f for f in self._functions if f.start_line <= line <= f.end_line), None)


@pytest.fixture
def pygoat(database, tmp_path):
    return load_sarif(
        database,
        tmp_path,
        MANIFEST,
        FIXTURE / "semgrep-pygoat.sarif",
        FIXTURE / "pygoat",
        f"https://example.test/{uuid.uuid4().hex}",
        COMMIT,
    ).scan_id


def triage_run(database, scan_id) -> str:
    with psycopg.connect(database) as conn:
        return str(
            conn.execute(
                "INSERT INTO triage_runs (scan_id, cheap_model, strong_model, budget_usd)"
                " VALUES (%s, 'cheap', 'strong', 1) RETURNING id",
                (scan_id,),
            ).fetchone()[0]
        )


def test_grouping_pygoat_saves_the_group_and_how_it_was_formed(database, pygoat):
    """F3, test 2: the group records its method, the rule that matched and a reason."""
    run_id = triage_run(database, pygoat)

    (group,) = group_scan(
        database, pygoat, FakeLookup(LAB, FunctionSpan("lab", 42, 71)), triage_run_id=run_id
    )

    with psycopg.connect(database) as conn:
        row = conn.execute(
            "SELECT g.scan_id::text, g.method, g.rule, g.similarity, g.reason, f.rule_id,"
            " f.start_line FROM duplicate_groups g"
            " JOIN findings f ON f.id = g.representative_finding_id WHERE g.id = %s",
            (group.group_id,),
        ).fetchone()
        grouped = conn.execute(
            "SELECT rule_id, start_line FROM findings WHERE group_id = %s"
            " ORDER BY start_line, rule_id",
            (group.group_id,),
        ).fetchall()
        states = conn.execute(
            "SELECT DISTINCT state FROM finding_states WHERE scan_id = %s", (pygoat,)
        ).fetchall()
        grouped_at = conn.execute(
            "SELECT grouped_at IS NOT NULL FROM triage_runs WHERE id = %s", (run_id,)
        ).fetchone()[0]
    assert row == (
        pygoat,
        "rule",
        SAME_FUNCTION,
        None,
        "Same function lab (lines 42 to 71) and related CWEs (CWE-89)",
        "python.sqlalchemy.security.sqlalchemy-execute-raw-query",
        57,
    )
    assert grouped == SQL_RULES
    assert states == [("grouped",)] and grouped_at


def test_a_scan_is_grouped_only_once(database, pygoat):
    group_scan(database, pygoat)
    with pytest.raises(GroupingError, match="already grouped"):
        group_scan(database, pygoat)


def test_a_scan_with_a_grouped_triage_run_is_not_grouped_again(database):
    """A scan without duplicates has no groups, so grouped_at is what says it was grouped."""
    scan_id = store_scan(database, {"semgrep": [(5, ["CWE-89"])]})
    assert group_scan(database, scan_id, triage_run_id=triage_run(database, scan_id)) == []
    with pytest.raises(GroupingError, match="already grouped"):
        group_scan(database, scan_id, triage_run_id=triage_run(database, scan_id))


@pytest.mark.parametrize("status", ["running", "failed"])
def test_a_scan_that_did_not_complete_is_not_grouped(database, status):
    """While a scan runs, a plug-in run may still be storing findings, which would stay out of
    every group."""
    scan_id = store_scan(database, {"semgrep": [(5, ["CWE-89"]), (5, ["CWE-89"])]}, status=status)
    with pytest.raises(GroupingError, match=f"is {status}, only a completed or partial"):
        group_scan(database, scan_id)
    with psycopg.connect(database) as conn:
        count = conn.execute(
            "SELECT count(*) FROM duplicate_groups WHERE scan_id = %s", (scan_id,)
        ).fetchone()[0]
    assert count == 0


def test_a_partial_scan_is_grouped(database):
    scan_id = store_scan(
        database, {"semgrep": [(5, ["CWE-89"]), (5, ["CWE-89"])]}, status="partial"
    )
    assert len(group_scan(database, scan_id)) == 1


def test_the_groups_as_the_csv_of_the_dedup_metric(database, pygoat, tmp_path, capsys):
    """Without the lookup the same four SQL injection findings are grouped by nearby lines.
    Labeled, all six are one group: 15 pairs, of which Sieve merged 6, all correct."""
    group_scan(database, pygoat)
    out = io.StringIO()
    assert write_groups_csv(database, pygoat, out) == 9
    predicted = tmp_path / "predicted.csv"
    predicted.write_text(out.getvalue(), encoding="utf-8")

    rows = list(csv.DictReader(io.StringIO(out.getvalue())))
    assert [list(row) for row in rows[:1]] == [["finding_id", "group"]]
    assert sum(1 for row in rows if row["group"]) == 4
    assert len({row["group"] for row in rows if row["group"]}) == 1

    with psycopg.connect(database) as conn:
        ids = conn.execute(
            "SELECT id::text, rule_id LIKE '%%sql%%' FROM findings WHERE scan_id = %s",
            (pygoat,),
        ).fetchall()
    labeled = tmp_path / "labeled.csv"
    with labeled.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["finding_id", "group"])
        writer.writerows((fid, "sqli" if sql else "") for fid, sql in ids)

    eval_main(["metrics", "dedup", "--labeled", str(labeled), "--predicted", str(predicted)])
    result = json.loads(capsys.readouterr().out)
    assert result == {
        "findings": 9,
        "labeled_pairs": 15,
        "merged_pairs": 6,
        "correct_pairs": 6,
        "precision": 1.0,
        "recall": 0.4,
    }


def store_scan(database, runs: dict[str, list[tuple]], repo=None, status="completed") -> str:
    """One scan with a run of each tool, and one finding in VIEWS for each (line, CWEs), or
    (line, CWEs, rule ID, message)."""
    store = PostgresRunStore(database)
    scan_id = store.create_scan(repo or f"https://example.test/{uuid.uuid4().hex}", COMMIT)
    store.update_scan(scan_id, "running")
    for tool, findings in runs.items():
        run = store.create_run(scan_id, PluginManifest(tool, "image", ("python",), tool, "1", "r"))
        run.status = RunStatus.SUCCEEDED
        result = AdapterResult(
            [
                Finding(
                    scan_id=scan_id,
                    run_id=run.run_id,
                    tool=tool,
                    tool_version="1",
                    rule_id=spec[2] if len(spec) > 2 else f"{tool}-rule",
                    message=spec[3] if len(spec) > 2 else "m",
                    tool_severity="warning",
                    location=Location(VIEWS, spec[0], spec[0]),
                    raw={},
                    cwe=spec[1],
                    fingerprint=f"v1:{tool}{n}",
                    context_hash="c1:x",
                )
                for n, spec in enumerate(findings)
            ]
        )
        store.save_findings(run, result)
    if status != "running":
        store.update_scan(scan_id, status)
    return scan_id


def test_semgrep_and_bandit_on_one_line_of_one_function_in_the_store(database):
    """F3, test 1, through the store: one Semgrep and one Bandit finding at line 12 of
    run_ping(), tagged CWE-78 and CWE-77, and the same Semgrep rule again in run_trace()."""
    scan_id = store_scan(
        database, {"semgrep": [(12, ["CWE-78"]), (17, ["CWE-78"])], "bandit": [(12, ["CWE-77"])]}
    )
    lookup = FakeLookup(VIEWS, FunctionSpan("run_ping", 10, 14), FunctionSpan("run_trace", 16, 20))

    (group,) = group_scan(database, scan_id, lookup)

    with psycopg.connect(database) as conn:
        rows = conn.execute(
            "SELECT tool, start_line, group_id::text FROM findings WHERE scan_id = %s"
            " ORDER BY start_line, tool",
            (scan_id,),
        ).fetchall()
    assert rows == [
        ("bandit", 12, group.group_id),
        ("semgrep", 12, group.group_id),
        ("semgrep", 17, None),
    ]
    assert group.reason == (
        "Same function run_ping (lines 10 to 14) and related CWEs (CWE-77 and CWE-78)"
    )


class LlmStep:
    """Stands in for the LLM step: puts the two findings left over in one group, decided by
    the given calls."""

    def __init__(self, call_ids):
        self.call_ids = call_ids

    def group(self, findings, groups):
        taken = {m.finding_id for g in groups for m in g.members}
        rest = [f for f in findings if f.finding_id not in taken]
        return groups + [
            Group(rest, "llm", "The model judged both the same", llm_call_ids=self.call_ids)
        ]


def llm_call(conn) -> str:
    return str(
        conn.execute(
            "INSERT INTO llm_calls (provider, model, messages, cache_key, max_tokens)"
            " VALUES ('fake', 'fake-1', '[]', 'k', 10) RETURNING id"
        ).fetchone()[0]
    )


def test_an_llm_group_links_to_its_calls(database):
    scan_id = store_scan(database, {"semgrep": [(30, ["CWE-915"])], "bandit": [(30, ["CWE-89"])]})
    with psycopg.connect(database) as conn:
        calls = [llm_call(conn), llm_call(conn)]

    (group,) = group_scan(database, scan_id, later_steps=[LlmStep(calls)])

    with psycopg.connect(database) as conn:
        linked = conn.execute(
            "SELECT llm_call_id::text FROM duplicate_group_llm_calls WHERE group_id = %s",
            (group.group_id,),
        ).fetchall()
        method = conn.execute(
            "SELECT method, rule FROM duplicate_groups WHERE id = %s", (group.group_id,)
        ).fetchone()
    assert sorted(row[0] for row in linked) == sorted(calls)
    assert method == ("llm", None)


def test_the_llm_step_links_the_calls_it_logged(database, pygoat_findings):
    """The LLM step inside group_scan, with the call log in llm_calls, which writes each call on
    a connection of its own while the scan is locked. The two findings carry the rules and
    messages of the unclear pair in test_dedup_llm.py, on one line, with CWEs the rules can't
    relate."""
    scan_id = store_scan(database, {"semgrep": [(30, ["CWE-89"]), (30, ["CWE-915"])]})
    (cursor,) = [
        f
        for f in pygoat_findings
        if f.rule_id.endswith("sql-injection-db-cursor-execute") and f.start_line == 46
    ]
    (tainted,) = [
        f
        for f in pygoat_findings
        if f.rule_id.endswith("django.security.injection.tainted-sql-string")
    ]
    with psycopg.connect(database) as conn:
        for fingerprint, finding in (("v1:semgrep0", cursor), ("v1:semgrep1", tainted)):
            conn.execute(
                "UPDATE findings SET rule_id = %s, message = %s"
                " WHERE scan_id = %s AND fingerprint = %s",
                (finding.rule_id, finding.message, scan_id, fingerprint),
            )
    price = Price(Decimal("1"), Decimal("2"), Decimal("0.1"), Decimal("1.25"))
    store = PostgresCallStore(database)
    client = LLMClient(
        providers={
            "fake": FakeProvider(
                replies=[
                    json.dumps({"same_issue": "unsure"}),
                    json.dumps({"same_issue": "yes", "reason": "One query."}),
                ]
            )
        },
        catalog=Catalog({m: ModelInfo(m, "fake", price) for m in ("cheap", "strong")}, "test"),
        budget=Budget(Decimal("1")),
        call_log=store,
        cache=store,
    )

    (group,) = group_scan(
        database,
        scan_id,
        later_steps=[SimilarityStep(), LLMStep(client, "cheap", "strong")],
        triage_run_id=triage_run(database, scan_id),
    )

    with psycopg.connect(database) as conn:
        linked = conn.execute(
            "SELECT c.model, c.template_name FROM duplicate_group_llm_calls l"
            " JOIN llm_calls c ON c.id = l.llm_call_id WHERE l.group_id = %s"
            " ORDER BY c.created_at",
            (group.group_id,),
        ).fetchall()
        saved = conn.execute(
            "SELECT method, reason FROM duplicate_groups WHERE id = %s", (group.group_id,)
        ).fetchone()
    assert linked == [("cheap", "duplicate_check"), ("strong", "duplicate_check")]
    assert saved == ("llm", "Same file, line 30, and a model judged them one issue: One query.")


def test_a_group_that_cannot_be_saved_leaves_the_scan_ungrouped(database):
    """The second group names a finding of another scan, so neither group is saved."""
    scan_id = store_scan(database, {"semgrep": [(5, ["CWE-89"]), (5, ["CWE-89"]), (40, [])]})
    other = store_scan(database, {"semgrep": [(5, ["CWE-79"])]})
    with psycopg.connect(database) as conn:
        a, b, c = scan_findings(conn, scan_id)
        (stranger,) = scan_findings(conn, other)
    groups = [
        Group([a, b], "rule", "r", rule="x"),
        Group([c, stranger], "similarity", "r", similarity=0.5),
    ]

    with pytest.raises(GroupingError, match="not in scan"):
        with psycopg.connect(database) as conn:
            save_groups(conn, scan_id, groups)

    with psycopg.connect(database) as conn:
        count = conn.execute(
            "SELECT count(*) FROM duplicate_groups WHERE scan_id = %s", (scan_id,)
        ).fetchone()[0]
        members = conn.execute(
            "SELECT count(*) FROM findings WHERE scan_id = %s AND group_id IS NOT NULL",
            (scan_id,),
        ).fetchone()[0]
    assert (count, members) == (0, 0)


def test_hidden_findings_are_not_grouped(database):
    """The second scan's Semgrep finding is hidden by the review of the first one, so its
    Bandit finding on the same line has nothing to be grouped with."""
    repo = f"https://example.test/{uuid.uuid4().hex}"
    first = store_scan(database, {"semgrep": [(12, ["CWE-78"])]}, repo)
    with psycopg.connect(database) as conn:
        conn.execute(
            "INSERT INTO reviews (finding_id, decision, reviewer)"
            " SELECT id, 'reject', 'Ali' FROM findings WHERE scan_id = %s",
            (first,),
        )
    second = store_scan(
        database, {"semgrep": [(12, ["CWE-78"])], "bandit": [(12, ["CWE-77"])]}, repo
    )

    with psycopg.connect(database) as conn:
        assert [f.tool for f in scan_findings(conn, second)] == ["bandit"]
    assert group_scan(database, second) == []


def test_the_command_line_groups_a_scan_and_writes_the_csv(database, pygoat, tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", database)
    out = tmp_path / "groups.csv"
    assert dedup_main(["group", pygoat]) == 0
    assert dedup_main(["group", pygoat]) == 1
    assert dedup_main(["csv", pygoat, "--out", str(out)]) == 0
    rows = list(csv.DictReader(io.StringIO(out.read_text(encoding="utf-8"))))
    # The four CWE-89 results by the rules, and the two copies of tainted-sql-string, tagged
    # CWE-915 and CWE-704, by text similarity.
    assert len(rows) == 9 and sum(1 for row in rows if row["group"]) == 6
    assert len({row["group"] for row in rows if row["group"]}) == 2


# Two methods with findings three lines apart, and two functions with findings four lines apart.
# The finding lines, and the function lines in the reasons below, were counted by hand.
NETWORK_VIEWS = """import os
import subprocess

from django.db import connection


class Network:
    def ping(self, host):
        return subprocess.check_output("ping -c 1 " + host, shell=True)

    def trace(self, host):
        return os.popen("traceroute " + host).read()


def lookup(request):
    name = request.GET["name"]
    query = "SELECT address FROM hosts WHERE name = '%s'" % name
    if not name:
        return None
    with connection.cursor() as cursor:
        cursor.execute(query)
        return cursor.fetchone()


def calculate(request):
    expression = request.GET["expression"]
    if not expression:
        return None
    print(expression)
    return eval(expression)
"""
EVAL_MESSAGE = "User input from request.GET is evaluated as Python code by eval()."
NETWORK_FINDINGS = {
    "semgrep": [
        (9, ["CWE-78"], "python.lang.security.audit.subprocess-shell-true", "Found shell=True."),
        (
            21,
            ["CWE-89"],
            "python.django.security.injection.sql.sql-injection-db-cursor-execute",
            "User-controlled data from a request is passed to 'execute()'.",
        ),
        (26, ["CWE-95"], "python.django.security.injection.code.user-eval", EVAL_MESSAGE),
    ],
    "bandit": [
        (12, ["CWE-78"], "B605", "Starting a process with a shell, possible injection detected."),
        (
            17,
            ["CWE-89"],
            "B608",
            "Possible SQL injection vector through string-based query construction.",
        ),
        (30, ["CWE-78"], "B307", EVAL_MESSAGE),
    ],
}


def grouped(database, scan_id) -> list[tuple]:
    with psycopg.connect(database) as conn:
        return conn.execute(
            "SELECT f.tool, f.start_line, g.method, g.rule, g.reason FROM findings f"
            " JOIN duplicate_groups g ON g.id = f.group_id WHERE f.scan_id = %s"
            " ORDER BY f.start_line",
            (scan_id,),
        ).fetchall()


def test_the_command_line_groups_with_the_functions_of_the_checkout(
    database, tmp_path, monkeypatch, capsys
):
    """The rules split the two methods of Network and join the two SQL injection findings of
    lookup(). The eval findings carry the same message, but their CWEs, CWE-95 and the CWE-78
    that Bandit gives eval, don't relate, so text similarity joins them, and only because it
    asks the same lookup."""
    scan_id = store_scan(database, NETWORK_FINDINGS)
    views = tmp_path / "scans" / scan_id / "src" / VIEWS
    views.parent.mkdir(parents=True)
    views.write_text(NETWORK_VIEWS, encoding="utf-8")
    monkeypatch.setenv("DATABASE_URL", database)
    monkeypatch.setenv("SIEVE_DATA_DIR", str(tmp_path))

    assert dedup_main(["group", scan_id]) == 0

    out, err = capsys.readouterr()
    assert out.startswith("groups: 2, with 4 findings\n")
    assert err == ""
    rows = grouped(database, scan_id)
    assert [row[:4] for row in rows] == [
        ("bandit", 17, "rule", SAME_FUNCTION),
        ("semgrep", 21, "rule", SAME_FUNCTION),
        ("semgrep", 26, "similarity", None),
        ("bandit", 30, "similarity", None),
    ]
    assert rows[0][4] == "Same function lookup (lines 15 to 22) and related CWEs (CWE-89)"
    assert rows[2][4].startswith(
        "Same function calculate (lines 25 to 30), similar analyzer messages (text similarity "
    )


def test_the_command_line_groups_by_nearby_lines_when_the_checkout_is_gone(
    database, tmp_path, monkeypatch, capsys
):
    """The same scan without its checkout: the two methods are three lines apart, so the rules
    join them, and the other pairs are four lines apart."""
    scan_id = store_scan(database, NETWORK_FINDINGS)
    monkeypatch.setenv("DATABASE_URL", database)
    monkeypatch.setenv("SIEVE_DATA_DIR", str(tmp_path))

    assert dedup_main(["group", scan_id]) == 0

    out, err = capsys.readouterr()
    assert out.startswith("groups: 1, with 2 findings\n")
    checkout = tmp_path / "scans" / scan_id / "src"
    assert err == f"no checkout at {checkout}, grouping by the same file and nearby lines\n"
    assert grouped(database, scan_id) == [
        ("semgrep", 9, "rule", NEARBY, "Same file, lines 9 to 12, and related CWEs (CWE-78)"),
        ("bandit", 12, "rule", NEARBY, "Same file, lines 9 to 12, and related CWEs (CWE-78)"),
    ]
