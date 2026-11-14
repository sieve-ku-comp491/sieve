"""Matching the findings of a repeated scan to earlier ones by fingerprint (requirement F3).

Runs once for each plug-in run, when its findings are stored, so matched_finding_id,
carried_review_id and hidden are fixed at import and a later review of an earlier finding
doesn't change them (docs/database.md, findings).

For each new finding, among the findings with the same fingerprint in earlier scans of the same
repo_url:

- matched_finding_id is the one of the latest scan.
- carried_review_id is the latest review of any of them.
- hidden is true only when all the rules of docs/finding-format.md, "When a finding is hidden",
  hold for the finding that review belongs to: its context hash is the new finding's and isn't
  empty, neither finding is ambiguous, unless both scans are of the same commit with the same
  tool and rules versions, and the tool is not Gitleaks. On top of that, the review must still
  be the decision on that finding: if the finding was edited after it, so its state is edited,
  the review is only a suggestion.
"""

from dataclasses import dataclass

import psycopg

MATCH = """
WITH new AS (
    SELECT f.id, f.fingerprint, f.context_hash, f.fingerprint_ambiguous, f.tool,
        s.repo_url, s.commit_sha, s.created_at, r.tool_version, r.rules_version
    FROM findings f
    JOIN scans s ON s.id = f.scan_id
    JOIN analyzer_runs r ON r.id = f.run_id
    WHERE f.run_id = %(run_id)s
),
decided AS (
    SELECT n.id, m.id AS matched_id, c.review_id, coalesce(c.hide, false) AS hide
    FROM new n
    LEFT JOIN LATERAL (
        SELECT e.id FROM findings e JOIN scans es ON es.id = e.scan_id
        WHERE e.fingerprint = n.fingerprint AND es.repo_url = n.repo_url
            AND es.created_at < n.created_at
        ORDER BY es.created_at DESC, es.id DESC
        LIMIT 1
    ) m ON true
    LEFT JOIN LATERAL (
        SELECT rv.id AS review_id,
            e.context_hash = n.context_hash
            AND n.context_hash <> ''
            AND n.tool <> 'gitleaks'
            AND (
                NOT (e.fingerprint_ambiguous OR n.fingerprint_ambiguous)
                OR (
                    es.commit_sha = n.commit_sha
                    AND er.tool_version = n.tool_version
                    AND er.rules_version = n.rules_version
                )
            )
            AND st.state IN ('approved', 'rejected', 'reported') AS hide
        FROM findings e
        JOIN scans es ON es.id = e.scan_id
        JOIN analyzer_runs er ON er.id = e.run_id
        JOIN reviews rv ON rv.finding_id = e.id
        JOIN finding_states st ON st.finding_id = e.id
        WHERE e.fingerprint = n.fingerprint AND es.repo_url = n.repo_url
            AND es.created_at < n.created_at
        ORDER BY rv.created_at DESC, rv.id DESC
        LIMIT 1
    ) c ON true
)
UPDATE findings f
SET matched_finding_id = d.matched_id, carried_review_id = d.review_id, hidden = d.hide
FROM decided d
WHERE f.id = d.id
RETURNING d.matched_id IS NOT NULL, d.review_id IS NOT NULL, d.hide
"""


@dataclass(frozen=True)
class Matched:
    findings: int
    matched: int
    carried: int
    hidden: int


def match_earlier_findings(conn: psycopg.Connection, run_id: str) -> Matched:
    """Sets matched_finding_id, carried_review_id and hidden on every finding of the run, in the
    caller's transaction, and counts them."""
    rows = conn.execute(MATCH, {"run_id": run_id}).fetchall()
    return Matched(
        findings=len(rows),
        matched=sum(1 for matched, _, _ in rows if matched),
        carried=sum(1 for _, carried, _ in rows if carried),
        hidden=sum(1 for _, _, hidden in rows if hidden),
    )
