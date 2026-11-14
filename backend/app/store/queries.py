"""What the API reads from the findings store: scans, their findings and one finding's details.

A finding's state comes from the finding_states view (docs/finding-states.md). Its verdict and
severity are those of its triage item's latest verdict, or of the reviewer's latest edit where
the edit changed them, so the queue shows the finding as the reviewer left it. Before triage
both are empty.
"""

from dataclasses import dataclass, field
from typing import Any

import psycopg
from psycopg.rows import dict_row

STATES = ("new", "grouped", "triaged", "edited", "approved", "rejected", "reported")

SCAN_COLUMNS = """
s.id, s.repo_url, s.commit_sha, s.requested_ref, s.status, s.error, s.languages, s.created_at,
s.started_at, s.finished_at
"""

LIST_SCANS = f"""
SELECT {SCAN_COLUMNS}, (SELECT count(*) FROM findings f WHERE f.scan_id = s.id) AS finding_count
FROM scans s
ORDER BY s.created_at DESC, s.id
LIMIT %(limit)s OFFSET %(offset)s
"""

GET_SCAN = f"""
SELECT {SCAN_COLUMNS}, (SELECT count(*) FROM findings f WHERE f.scan_id = s.id) AS finding_count
FROM scans s WHERE s.id = %(id)s
"""

SCAN_RUNS = """
SELECT id, plugin, image, image_digest, tool_version, rules_version, status, reason, exit_code,
    files_scanned, result_count, dropped_count, started_at, finished_at
FROM analyzer_runs WHERE scan_id = %(id)s ORDER BY plugin
"""

LATEST_TRIAGE_RUN = """
SELECT id, cheap_model, strong_model, budget_usd, cost_usd, status, grouped_at, created_at,
    finished_at
FROM triage_runs WHERE scan_id = %(id)s ORDER BY created_at DESC LIMIT 1
"""

STATE_COUNTS = """
SELECT st.state, count(*) AS count FROM finding_states st JOIN findings f ON f.id = st.finding_id
WHERE st.scan_id = %(id)s AND f.scan_id = %(id)s AND NOT f.hidden
GROUP BY st.state
"""

HIDDEN_COUNT = "SELECT count(*) FROM findings WHERE scan_id = %(id)s AND hidden"

# The latest verdict of the finding's triage item, which is the finding or its group.
LATEST_VERDICT = """
SELECT v.* FROM verdicts v
WHERE v.finding_id = f.id OR (f.group_id IS NOT NULL AND v.group_id = f.group_id)
ORDER BY v.created_at DESC LIMIT 1
"""

LATEST_EDIT = """
SELECT e.* FROM finding_edits e WHERE e.finding_id = f.id ORDER BY e.created_at DESC LIMIT 1
"""

ITEMS = f"""
SELECT
    f.id, f.scan_id, f.run_id, f.group_id, f.tool, f.tool_version, f.rule_id, f.cwe, f.message,
    f.tool_severity, f.tool_confidence, f.file, f.start_line, f.end_line, f.language,
    f.suppressed, f.hidden, f.carried_review_id,
    st.state,
    coalesce(e.verdict, v.verdict) AS verdict,
    coalesce(e.cvss_v4_level, v.cvss_v4_level) AS severity,
    coalesce(e.cvss_v4_score, v.cvss_v4_score) AS score,
    coalesce(v.injection_suspected, false) AS injection_suspected
FROM findings f
JOIN finding_states st ON st.finding_id = f.id
LEFT JOIN LATERAL ({LATEST_VERDICT}) v ON true
LEFT JOIN LATERAL ({LATEST_EDIT}) e ON true
WHERE f.scan_id = %(scan_id)s AND st.scan_id = %(scan_id)s
"""

FILTERED = f"""
SELECT * FROM ({ITEMS}) i
WHERE (%(include_hidden)s OR NOT i.hidden)
    AND (%(states)s::text[] IS NULL OR i.state = ANY(%(states)s::text[]))
    AND (%(tools)s::text[] IS NULL OR i.tool = ANY(%(tools)s::text[]))
    AND (%(severities)s::text[] IS NULL OR i.severity = ANY(%(severities)s::text[]))
    AND (%(verdicts)s::text[] IS NULL OR i.verdict = ANY(%(verdicts)s::text[]))
    AND (%(tool_severities)s::text[] IS NULL
        OR i.tool_severity = ANY(%(tool_severities)s::text[]))
    AND (%(pattern)s::text IS NULL
        OR i.file ILIKE %(pattern)s::text OR i.rule_id ILIKE %(pattern)s::text)
"""

LIST_FINDINGS = f"""
{FILTERED}
ORDER BY i.score DESC NULLS LAST,
    array_position(ARRAY['error', 'warning', 'note', 'none'], i.tool_severity),
    i.file, i.start_line, i.rule_id, i.id
LIMIT %(limit)s OFFSET %(offset)s
"""

COUNT_FINDINGS = f"SELECT count(*) FROM ({FILTERED}) c"

GET_FINDING = """
SELECT f.*, st.state FROM findings f JOIN finding_states st ON st.finding_id = f.id
WHERE f.id = %(id)s AND st.finding_id = %(id)s
"""

FINDING_LOCATIONS = """
SELECT kind, position, file, start_line, end_line, start_column, end_column, snippet, message
FROM locations WHERE finding_id = %(id)s ORDER BY kind, position
"""

FINDING_VERDICT = f"""
SELECT v.*,
    (SELECT count(*) FROM verdict_llm_calls l WHERE l.verdict_id = v.id) AS call_count,
    (SELECT coalesce(sum(c.cost_usd), 0) FROM verdict_llm_calls l
        JOIN llm_calls c ON c.id = l.llm_call_id WHERE l.verdict_id = v.id) AS cost_usd
FROM findings f, LATERAL ({LATEST_VERDICT}) v
WHERE f.id = %(id)s
"""

FINDING_EDIT = f"SELECT e.* FROM findings f, LATERAL ({LATEST_EDIT}) e WHERE f.id = %(id)s"

FINDING_REVIEWS = """
SELECT id, decision, reviewer, comment, verdict_id, finding_edit_id, created_at
FROM reviews WHERE finding_id = %(id)s ORDER BY created_at DESC, id
"""

REVIEW = """
SELECT id, decision, reviewer, comment, verdict_id, finding_edit_id, created_at
FROM reviews WHERE id = %(id)s
"""

GROUP = """
SELECT id, method, rule, similarity, reason, representative_finding_id, created_at
FROM duplicate_groups WHERE id = %(id)s
"""

GROUP_MEMBERS = """
SELECT f.id, f.tool, f.rule_id, f.message, f.file, f.start_line, f.end_line, f.cwe,
    f.tool_severity, st.state
FROM findings f JOIN finding_states st ON st.finding_id = f.id
WHERE f.group_id = %(id)s AND st.group_id = %(id)s
ORDER BY f.file, f.start_line, f.rule_id, f.id
"""


@dataclass
class FindingFilter:
    """Each list holds the values to keep. An empty list doesn't filter."""

    states: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    severities: list[str] = field(default_factory=list)
    verdicts: list[str] = field(default_factory=list)
    tool_severities: list[str] = field(default_factory=list)
    search: str | None = None
    include_hidden: bool = False

    def params(self) -> dict[str, Any]:
        pattern = None
        if self.search:
            escaped = self.search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            pattern = f"%{escaped}%"
        return {
            "states": self.states or None,
            "tools": self.tools or None,
            "severities": self.severities or None,
            "verdicts": self.verdicts or None,
            "tool_severities": self.tool_severities or None,
            "pattern": pattern,
            "include_hidden": self.include_hidden,
        }


class FindingsReader:
    def __init__(self, conninfo: str):
        self._conninfo = conninfo

    def _connect(self) -> psycopg.Connection:
        return psycopg.connect(self._conninfo, row_factory=dict_row)

    def list_scans(self, limit: int, offset: int) -> list[dict]:
        with self._connect() as conn:
            return conn.execute(LIST_SCANS, {"limit": limit, "offset": offset}).fetchall()

    def get_scan(self, scan_id: str) -> dict | None:
        """The scan with its plug-in runs, its latest triage run and the number of its findings
        in each state. Hidden findings are counted on their own, not by state, because the
        review queue leaves them out."""
        with self._connect() as conn:
            scan = conn.execute(GET_SCAN, {"id": scan_id}).fetchone()
            if scan is None:
                return None
            scan["runs"] = conn.execute(SCAN_RUNS, {"id": scan_id}).fetchall()
            scan["triage_run"] = conn.execute(LATEST_TRIAGE_RUN, {"id": scan_id}).fetchone()
            counts = dict.fromkeys(STATES, 0)
            for row in conn.execute(STATE_COUNTS, {"id": scan_id}):
                counts[row["state"]] = row["count"]
            scan["state_counts"] = counts
            scan["hidden_count"] = conn.execute(HIDDEN_COUNT, {"id": scan_id}).fetchone()["count"]
        return scan

    def scan_exists(self, scan_id: str) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT 1 FROM scans WHERE id = %s", (scan_id,)).fetchone()
        return row is not None

    def list_findings(
        self, scan_id: str, filters: FindingFilter, limit: int, offset: int
    ) -> tuple[int, list[dict]]:
        """The total that match the filters, and one page of them: highest severity first, then
        the analyzer's own severity, then by file and line."""
        params = filters.params() | {"scan_id": scan_id, "limit": limit, "offset": offset}
        with self._connect() as conn:
            total = conn.execute(COUNT_FINDINGS, params).fetchone()["count"]
            rows = conn.execute(LIST_FINDINGS, params).fetchall()
        return total, rows

    def get_finding(self, finding_id: str) -> dict | None:
        """The finding with its locations, its latest verdict and edit, its reviews, the review
        carried over from an earlier scan, and its duplicate group with the members."""
        with self._connect() as conn:
            finding = conn.execute(GET_FINDING, {"id": finding_id}).fetchone()
            if finding is None:
                return None
            locations = conn.execute(FINDING_LOCATIONS, {"id": finding_id}).fetchall()
            finding["related_locations"] = [r for r in locations if r["kind"] == "related"]
            finding["data_flow"] = [
                r | {"step": r["position"]} for r in locations if r["kind"] == "flow_step"
            ]
            finding["verdict"] = conn.execute(FINDING_VERDICT, {"id": finding_id}).fetchone()
            finding["latest_edit"] = conn.execute(FINDING_EDIT, {"id": finding_id}).fetchone()
            finding["reviews"] = conn.execute(FINDING_REVIEWS, {"id": finding_id}).fetchall()
            finding["carried_review"] = None
            if finding["carried_review_id"] is not None:
                finding["carried_review"] = conn.execute(
                    REVIEW, {"id": finding["carried_review_id"]}
                ).fetchone()
            finding["group"] = None
            if finding["group_id"] is not None:
                group = conn.execute(GROUP, {"id": finding["group_id"]}).fetchone()
                group["members"] = conn.execute(
                    GROUP_MEMBERS, {"id": finding["group_id"]}
                ).fetchall()
                finding["group"] = group
        return finding
