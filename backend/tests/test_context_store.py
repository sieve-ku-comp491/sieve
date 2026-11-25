"""A scan's triage items from the findings store, with the saved Semgrep run of PyGoat in
tests/adapter_fixture. Its four results tagged CWE-89 in lab() are one group by the rules, and
the other five are items of their own."""

import uuid
from pathlib import Path

import psycopg
import pytest

from app.adapters import FlowStep, Location
from app.adapters.gitleaks import REDACTED
from app.checkout import CheckoutReader
from app.context import ContextCollector, Lines, Repo, scan_items
from app.dedup import FunctionSpan, group_scan
from app.store import load_sarif

FIXTURE = Path(__file__).parent / "adapter_fixture"
MANIFEST = Path(__file__).resolve().parents[2] / "plugins" / "semgrep" / "plugin.toml"
COMMIT = "2aa4cc14f251e4a780e94e200aed6b36a5b15c21"
LAB = "dockerized_labs/sql_injection_lab/app.py"


def load(database, tmp_path, repo: str) -> str:
    return load_sarif(
        database,
        tmp_path,
        MANIFEST,
        FIXTURE / "semgrep-pygoat.sarif",
        FIXTURE / "pygoat",
        repo,
        COMMIT,
    ).scan_id


def items(database, scan_id):
    return scan_items(database, scan_id, ContextCollector(CheckoutReader(FIXTURE / "pygoat")))


def test_the_items_of_a_grouped_scan(database, tmp_path):
    scan_id = load(database, tmp_path, f"https://example.test/{uuid.uuid4().hex}")
    (group,) = group_scan(database, scan_id)

    found = items(database, scan_id)

    first_lines = [min(f.location.start_line for f in item.findings) for item in found]
    assert first_lines == [7, 46, 50, 50, 78, 78]
    assert all(item.repo == Repo(scan_id, COMMIT) for item in found)
    (grouped,) = [item for item in found if len(item.findings) > 1]
    assert grouped.item_id == group.group_id
    assert grouped.findings[0].finding_id == group.representative.finding_id
    assert sorted(f.finding_id for f in grouped.findings) == sorted(
        m.finding_id for m in group.members
    )
    assert grouped.context.function == FunctionSpan("lab", 42, 71)
    for item in found:
        if len(item.findings) == 1:
            assert item.item_id == item.findings[0].finding_id
    first = found[0].findings[0]
    assert (first.scan_id, first.tool, first.location.file, first.language) == (
        scan_id,
        "semgrep",
        LAB,
        "python",
    )


def test_an_item_carries_the_data_flow_and_related_locations(database, tmp_path):
    scan_id = load(database, tmp_path, f"https://example.test/{uuid.uuid4().hex}")
    with psycopg.connect(database) as conn:
        finding_id = conn.execute(
            "SELECT id FROM findings WHERE scan_id = %s AND start_line = 57"
            " AND rule_id LIKE '%%formatted-sql-query'",
            (scan_id,),
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO locations (finding_id, kind, position, file, start_line, end_line,"
            " message) VALUES (%(id)s, 'flow_step', 1, %(file)s, 46, 46, 'source'),"
            " (%(id)s, 'flow_step', 2, %(file)s, 57, 57, 'sink'),"
            " (%(id)s, 'related', 1, %(file)s, 50, 52, 'the query')",
            {"id": finding_id, "file": LAB},
        )

    (item,) = [i for i in items(database, scan_id) if i.item_id == str(finding_id)]

    (finding,) = item.findings
    assert finding.data_flow == [
        FlowStep(LAB, 46, 46, step=1, message="source"),
        FlowStep(LAB, 57, 57, step=2, message="sink"),
    ]
    assert finding.related_locations == [Location(LAB, 50, 52)]
    assert item.context.data_flow == finding.data_flow
    assert item.context.location == Lines(LAB, 42, 71)


def test_findings_an_earlier_review_decides_have_no_items(database, tmp_path):
    """The same commit scanned again: the review of the first scan hides every finding of the
    second, so nothing of it is triaged."""
    repo = f"https://example.test/{uuid.uuid4().hex}"
    first = load(database, tmp_path / "first", repo)
    with psycopg.connect(database) as conn:
        conn.execute(
            "INSERT INTO reviews (finding_id, decision, reviewer)"
            " SELECT id, 'reject', 'Ali' FROM findings WHERE scan_id = %s",
            (first,),
        )
    second = load(database, tmp_path / "second", repo)

    assert items(database, second) == []


def test_a_scan_that_does_not_exist(database):
    with pytest.raises(LookupError):
        items(database, str(uuid.uuid4()))


def test_a_line_another_finding_masks_stays_masked(database, tmp_path):
    """The result at line 57 stored as a Gitleaks one: every item whose code covers line 57,
    the six findings in lab() without grouping, shows it masked."""
    scan_id = load(database, tmp_path, f"https://example.test/{uuid.uuid4().hex}")
    with psycopg.connect(database) as conn:
        conn.execute(
            "UPDATE findings SET tool = 'gitleaks' WHERE scan_id = %s AND start_line = 57"
            " AND rule_id LIKE '%%formatted-sql-query'",
            (scan_id,),
        )

    covering = [
        item
        for item in items(database, scan_id)
        if item.context.location.start_line <= 57 <= item.context.location.end_line
    ]

    assert len(covering) == 6
    for item in covering:
        code = item.context.code.split("\n")
        assert code[57 - item.context.location.start_line] == REDACTED
