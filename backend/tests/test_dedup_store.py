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
from pathlib import Path

import psycopg
import pytest

from app.adapters import AdapterResult, Finding, Location
from app.dedup import SAME_FUNCTION, FunctionSpan, Group, GroupingError, group_scan
from app.dedup.__main__ import main as dedup_main
from app.dedup.store import save_groups, scan_findings, write_groups_csv
from app.eval.__main__ import main as eval_main
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


def store_scan(database, runs: dict[str, list[tuple[int, list[str]]]], repo=None) -> str:
    """One scan with a run of each tool, and one finding in VIEWS for each (line, CWEs)."""
    store = PostgresRunStore(database)
    scan_id = store.create_scan(repo or f"https://example.test/{uuid.uuid4().hex}", COMMIT)
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
                    rule_id=f"{tool}-rule",
                    message="m",
                    tool_severity="warning",
                    location=Location(VIEWS, line, line),
                    raw={},
                    cwe=cwe,
                    fingerprint=f"v1:{tool}{n}",
                    context_hash="c1:x",
                )
                for n, (line, cwe) in enumerate(findings)
            ]
        )
        store.save_findings(run, result)
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
    assert len(rows) == 9 and sum(1 for row in rows if row["group"]) == 4
