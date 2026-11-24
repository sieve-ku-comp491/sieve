"""Saves the reviewer's decisions and edits (docs/finding-states.md, docs/database.md).

A decision is a row of reviews, and an edit is a row of finding_edits. Neither changes the AI's
verdict, and the finding's state follows from these rows through the finding_states view, so
nothing else is updated. Each save locks the finding's row first, so two saves for the same
finding can't both pass their checks against the same state.
"""

from dataclasses import dataclass

import psycopg
from psycopg.rows import dict_row

from app.cvss import score_v4
from app.store.queries import LATEST_EDIT, LATEST_VERDICT

LOCK_FINDING = "SELECT id FROM findings WHERE id = %(id)s FOR UPDATE"

CURRENT = f"""
SELECT st.state, v.id AS verdict_id, e.id AS edit_id, e.verdict, e.reasoning,
    e.cvss_v4_vector, e.cvss_v4_score, e.cvss_v4_level
FROM findings f
JOIN finding_states st ON st.finding_id = f.id
LEFT JOIN LATERAL ({LATEST_VERDICT}) v ON true
LEFT JOIN LATERAL ({LATEST_EDIT}) e ON true
WHERE f.id = %(id)s AND st.finding_id = %(id)s
"""

STATE = "SELECT state FROM finding_states WHERE finding_id = %(id)s"

INSERT_REVIEW = """
INSERT INTO reviews (finding_id, decision, reviewer, comment, verdict_id, finding_edit_id)
VALUES (%(finding_id)s, %(decision)s, %(reviewer)s, %(comment)s, %(verdict_id)s, %(edit_id)s)
RETURNING id, decision, reviewer, comment, verdict_id, finding_edit_id, created_at
"""

INSERT_EDIT = """
INSERT INTO finding_edits (
    finding_id, verdict_id, editor, verdict, reasoning, cvss_v4_vector, cvss_v4_score,
    cvss_v4_level, note
) VALUES (
    %(finding_id)s, %(verdict_id)s, %(editor)s, %(verdict)s, %(reasoning)s, %(vector)s,
    %(score)s, %(level)s, %(note)s
)
RETURNING id, verdict_id, editor, verdict, reasoning, cvss_v4_vector, cvss_v4_score,
    cvss_v4_level, note, created_at
"""

# Before triage there is nothing to decide on, and a reported finding has left Sieve.
NOT_YET = {
    "new": "the finding has no verdict yet: triage hasn't checked it",
    "grouped": "the finding has no verdict yet: triage hasn't checked it",
    "reported": "the finding is reported: its report has been exported",
}


class FindingNotFound(LookupError):
    pass


class ReviewConflict(Exception):
    """The finding's state doesn't allow the save. The message says why."""


@dataclass(frozen=True)
class Edit:
    """What the reviewer changes. None keeps the value of the latest edit, or the AI's."""

    editor: str
    verdict: str | None = None
    reasoning: str | None = None
    cvss_v4_vector: str | None = None
    note: str | None = None


class ReviewStore:
    def __init__(self, conninfo: str):
        self._conninfo = conninfo

    def _current(self, conn: psycopg.Connection, finding_id: str) -> dict:
        if conn.execute(LOCK_FINDING, {"id": finding_id}).fetchone() is None:
            raise FindingNotFound(finding_id)
        return conn.execute(CURRENT, {"id": finding_id}).fetchone()

    def decide(
        self,
        finding_id: str,
        decision: str,
        reviewer: str,
        comment: str | None,
        seen_edit_id: str | None,
    ) -> dict:
        """Saves an approve or a reject. seen_edit_id is the latest edit the reviewer saw, or
        None if they saw none. When another edit was saved since, the decision is refused, so
        nobody approves text they haven't read. The review records the verdict and the edit it
        decided on, which is how the state tells an approval of the latest edit from an older
        one."""
        with psycopg.connect(self._conninfo, row_factory=dict_row) as conn:
            current = self._current(conn, finding_id)
            if current["state"] in NOT_YET:
                raise ReviewConflict(NOT_YET[current["state"]])
            latest = None if current["edit_id"] is None else str(current["edit_id"])
            if (None if seen_edit_id is None else str(seen_edit_id)) != latest:
                raise ReviewConflict(
                    "the finding was edited since you opened it: read the latest edit first"
                )
            review = conn.execute(
                INSERT_REVIEW,
                {
                    "finding_id": finding_id,
                    "decision": decision,
                    "reviewer": reviewer,
                    "comment": comment,
                    "verdict_id": current["verdict_id"],
                    "edit_id": current["edit_id"],
                },
            ).fetchone()
            review["state"] = conn.execute(STATE, {"id": finding_id}).fetchone()["state"]
        return review

    def edit(self, finding_id: str, edit: Edit) -> dict:
        """Saves an edit next to the AI's verdict. Fields the edit leaves out keep the value of
        the previous edit, so the latest edit always holds everything the reviewer changed.
        The score and level are computed from the vector. The finding becomes edited, which
        undoes an approval or a rejection until the reviewer decides again."""
        severity = score_v4(edit.cvss_v4_vector) if edit.cvss_v4_vector is not None else None
        with psycopg.connect(self._conninfo, row_factory=dict_row) as conn:
            current = self._current(conn, finding_id)
            if current["state"] in NOT_YET:
                raise ReviewConflict(NOT_YET[current["state"]])
            if current["verdict_id"] is None:
                raise ReviewConflict("the finding has no verdict to edit")
            row = {
                "finding_id": finding_id,
                "verdict_id": current["verdict_id"],
                "editor": edit.editor,
                "verdict": edit.verdict or current["verdict"],
                "reasoning": edit.reasoning or current["reasoning"],
                "vector": current["cvss_v4_vector"],
                "score": current["cvss_v4_score"],
                "level": current["cvss_v4_level"],
                "note": edit.note,
            }
            if severity is not None:
                row |= {"vector": severity.vector, "score": severity.score}
                row["level"] = severity.level
            saved = conn.execute(INSERT_EDIT, row).fetchone()
            saved["state"] = conn.execute(STATE, {"id": finding_id}).fetchone()["state"]
        return saved
