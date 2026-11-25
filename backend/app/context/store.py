"""A scan's triage items, read from the findings store (T3.3, docs/interfaces.md, Triage item)."""

from collections import defaultdict

import psycopg
from psycopg.rows import dict_row

from app.adapters import Finding, FlowStep, Location
from app.context.items import ContextCollector, Flagged, Repo, TriageItem

SCAN = "SELECT commit_sha FROM scans WHERE id = %(scan_id)s"

# Every finding of the scan, hidden ones too, for the lines their adapters mask.
FLAGGED = """
SELECT tool, file, start_line, end_line FROM findings WHERE scan_id = %(scan_id)s
"""

FINDINGS = """
SELECT id::text, scan_id::text, run_id::text, group_id::text, tool, tool_version, rule_id,
    rule_description, rule_help_uri, cwe, message, tool_severity, tool_score, tool_confidence,
    file, start_line, end_line, start_column, end_column, snippet, fingerprint,
    fingerprint_ambiguous, context_hash, suppressed, tool_fingerprint, language, raw
FROM findings WHERE scan_id = %(scan_id)s AND NOT hidden
ORDER BY file, start_line, end_line, tool, rule_id, id
"""

LOCATIONS = """
SELECT l.finding_id::text, l.kind, l.position, l.file, l.start_line, l.end_line, l.start_column,
    l.end_column, l.snippet, l.message
FROM locations l JOIN findings f ON f.id = l.finding_id
WHERE f.scan_id = %(scan_id)s AND NOT f.hidden
ORDER BY l.finding_id, l.kind, l.position
"""

GROUPS = """
SELECT id::text, representative_finding_id::text FROM duplicate_groups WHERE scan_id = %(scan_id)s
"""


def scan_items(conninfo: str, scan_id: str, collector: ContextCollector) -> list[TriageItem]:
    """The scan's triage items, by the file and line of their first finding: one for each
    duplicate group, with the representative first, and one for each finding in no group. Hidden
    findings are left out, because an earlier review decides them (docs/finding-format.md),
    but the lines their adapters mask stay masked in the other items' code. The scan is grouped
    first (app.dedup.group_scan), or every finding is an item of its own."""
    params = {"scan_id": scan_id}
    with psycopg.connect(conninfo, row_factory=dict_row) as conn:
        scan = conn.execute(SCAN, params).fetchone()
        if scan is None:
            raise LookupError(f"no scan {scan_id}")
        rows = conn.execute(FINDINGS, params).fetchall()
        locations = conn.execute(LOCATIONS, params).fetchall()
        representatives = {
            row["id"]: row["representative_finding_id"]
            for row in conn.execute(GROUPS, params).fetchall()
        }
        flagged: dict[str, list[Flagged]] = defaultdict(list)
        for row in conn.execute(FLAGGED, params).fetchall():
            location = Location(row["file"], row["start_line"], row["end_line"])
            flagged[row["file"]].append((row["tool"], location))

    related: dict[str, list[Location]] = defaultdict(list)
    flows: dict[str, list[FlowStep]] = defaultdict(list)
    for row in locations:
        where = (row["file"], row["start_line"], row["end_line"], row["start_column"])
        if row["kind"] == "related":
            related[row["finding_id"]].append(Location(*where, row["end_column"], row["snippet"]))
        else:
            flows[row["finding_id"]].append(
                FlowStep(*where, row["end_column"], row["snippet"], row["position"], row["message"])
            )

    members: dict[str, list[Finding]] = {}
    for row in rows:
        finding = _finding(row, related[row["id"]], flows[row["id"]])
        members.setdefault(row["group_id"] or row["id"], []).append(finding)
    repo = Repo(scan_id, scan["commit_sha"])
    items = []
    for item_id, findings in members.items():
        representative = representatives.get(item_id)
        findings.sort(key=lambda finding: finding.finding_id != representative)
        others = flagged[findings[0].location.file]
        items.append(collector.item(item_id, findings, repo, others))
    return items


def _finding(row: dict, related: list[Location], data_flow: list[FlowStep]) -> Finding:
    return Finding(
        scan_id=row["scan_id"],
        run_id=row["run_id"],
        tool=row["tool"],
        tool_version=row["tool_version"],
        rule_id=row["rule_id"],
        message=row["message"],
        tool_severity=row["tool_severity"],
        location=Location(
            row["file"],
            row["start_line"],
            row["end_line"],
            row["start_column"],
            row["end_column"],
            row["snippet"],
        ),
        raw=row["raw"],
        rule_description=row["rule_description"],
        rule_help_uri=row["rule_help_uri"],
        cwe=list(row["cwe"]),
        tool_score=None if row["tool_score"] is None else float(row["tool_score"]),
        tool_confidence=row["tool_confidence"],
        related_locations=related,
        data_flow=data_flow,
        fingerprint=row["fingerprint"],
        fingerprint_ambiguous=row["fingerprint_ambiguous"],
        context_hash=row["context_hash"],
        suppressed=row["suppressed"],
        tool_fingerprint=row["tool_fingerprint"],
        language=row["language"] or "other",
        finding_id=row["id"],
    )
