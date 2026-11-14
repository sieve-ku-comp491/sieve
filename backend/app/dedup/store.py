"""Reading a scan's findings for grouping, and saving its duplicate groups (docs/database.md,
duplicate_groups)."""

import csv
from collections.abc import Iterable
from typing import TextIO

import psycopg

from app.dedup.functions import FunctionLookup
from app.dedup.groups import Group, GroupingError, GroupingStep, ScanFinding, group_findings
from app.dedup.rules import RuleStep

# Hidden findings are left out: an earlier review decides them, so they are not triaged and
# don't need a group.
SCAN_FINDINGS = """
SELECT id::text, tool, rule_id, cwe, message, tool_severity, file, start_line, end_line,
    rule_description, snippet, language
FROM findings WHERE scan_id = %(scan_id)s AND NOT hidden
ORDER BY file, start_line, end_line, tool, rule_id, id
"""

LOCK_SCAN = "SELECT id FROM scans WHERE id = %(scan_id)s FOR UPDATE"

ALREADY_GROUPED = """
SELECT EXISTS (SELECT 1 FROM duplicate_groups WHERE scan_id = %(scan_id)s)
    OR EXISTS (SELECT 1 FROM triage_runs WHERE scan_id = %(scan_id)s AND grouped_at IS NOT NULL)
"""

INSERT_GROUP = """
INSERT INTO duplicate_groups (scan_id, representative_finding_id, method, rule, similarity, reason)
VALUES (%(scan_id)s, %(representative)s, %(method)s, %(rule)s, %(similarity)s, %(reason)s)
RETURNING id::text
"""

SET_MEMBERS = """
UPDATE findings SET group_id = %(group_id)s
WHERE id = ANY(%(members)s::uuid[]) AND scan_id = %(scan_id)s AND group_id IS NULL AND NOT hidden
"""

INSERT_LLM_CALL = """
INSERT INTO duplicate_group_llm_calls (group_id, llm_call_id) VALUES (%s, %s)
"""

SET_GROUPED_AT = """
UPDATE triage_runs SET grouped_at = now()
WHERE id = %(triage_run_id)s AND scan_id = %(scan_id)s AND grouped_at IS NULL
"""

CSV_ROWS = """
SELECT id::text, coalesce(group_id::text, '') FROM findings WHERE scan_id = %(scan_id)s
ORDER BY file, start_line, end_line, tool, rule_id, id
"""


def scan_findings(conn: psycopg.Connection, scan_id: str) -> list[ScanFinding]:
    """The scan's findings that grouping works on: all but the hidden ones."""
    return [
        ScanFinding(
            finding_id=row[0],
            tool=row[1],
            rule_id=row[2],
            cwe=tuple(row[3]),
            message=row[4],
            tool_severity=row[5],
            file=row[6],
            start_line=row[7],
            end_line=row[8],
            rule_description=row[9],
            snippet=row[10],
            language=row[11],
        )
        for row in conn.execute(SCAN_FINDINGS, {"scan_id": scan_id})
    ]


def group_scan(
    conninfo: str,
    scan_id: str,
    lookup: FunctionLookup | None = None,
    later_steps: Iterable[GroupingStep] = (),
    triage_run_id: str | None = None,
) -> list[Group]:
    """Groups the scan's findings once: the rule step with lookup, then later_steps, such as
    text similarity and the LLM. Saves the groups, and sets grouped_at on the triage run when
    one is given, all in one transaction. Refuses a scan that was already grouped, because its
    groups may already have verdicts."""
    with psycopg.connect(conninfo) as conn:
        if conn.execute(LOCK_SCAN, {"scan_id": scan_id}).fetchone() is None:
            raise GroupingError(f"no scan {scan_id}")
        if conn.execute(ALREADY_GROUPED, {"scan_id": scan_id}).fetchone()[0]:
            raise GroupingError(f"scan {scan_id} is already grouped")
        findings = scan_findings(conn, scan_id)
        groups = group_findings(findings, [RuleStep(lookup), *later_steps])
        save_groups(conn, scan_id, groups)
        if triage_run_id is not None:
            cursor = conn.execute(
                SET_GROUPED_AT, {"triage_run_id": triage_run_id, "scan_id": scan_id}
            )
            if cursor.rowcount != 1:
                raise GroupingError(f"no ungrouped triage run {triage_run_id} of scan {scan_id}")
    return groups


def save_groups(conn: psycopg.Connection, scan_id: str, groups: list[Group]) -> None:
    """Writes each group with its members and LLM calls in the caller's transaction, and sets
    each group's group_id."""
    for group in groups:
        group.check()
        group_id = conn.execute(
            INSERT_GROUP,
            {
                "scan_id": scan_id,
                "representative": group.representative.finding_id,
                "method": group.method,
                "rule": group.rule,
                "similarity": None if group.similarity is None else round(group.similarity, 3),
                "reason": group.reason.strip(),
            },
        ).fetchone()[0]
        members = [member.finding_id for member in group.members]
        cursor = conn.execute(
            SET_MEMBERS, {"group_id": group_id, "members": members, "scan_id": scan_id}
        )
        if cursor.rowcount != len(members):
            raise GroupingError(
                f"group of {members}: a finding is not in scan {scan_id}, hidden, or grouped"
            )
        for call_id in group.llm_call_ids:
            conn.execute(INSERT_LLM_CALL, (group_id, call_id))
        group.group_id = group_id


def write_groups_csv(conninfo: str, scan_id: str, out: TextIO) -> int:
    """Every finding of the scan with its group, as the CSV that python -m app.eval metrics
    dedup reads: finding_id and group, empty for a finding on its own. Returns the row count."""
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(["finding_id", "group"])
    with psycopg.connect(conninfo) as conn:
        rows = conn.execute(CSV_ROWS, {"scan_id": scan_id}).fetchall()
    writer.writerows(rows)
    return len(rows)
