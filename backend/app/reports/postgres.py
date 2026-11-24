"""Reports in PostgreSQL: the tables reports, report_texts and report_findings (docs/database.md).

The export check is export_refusals() of migration 0004, the SQL of docs/finding-states.md, so the
service and any other client refuse an export for the same reasons.
"""

import json
import uuid
from datetime import datetime

import psycopg
from psycopg.rows import dict_row

from app.llm.types import CodeBlock
from app.reports.models import (
    FindingContext,
    Location,
    NotApproved,
    ReportError,
    ReportExported,
    ReportText,
    RuleHit,
    Severity,
    StaleVersion,
    UnknownReport,
)
from app.reports.store import StoredReport

TEXT_COLUMNS = """version, source, llm_call_id, author, title, summary, impact, steps_to_reproduce,
    fix, "references", cvss_v4_vector, cvss_v4_score, cvss_v4_level, locations, approved_by,
    approved_at, created_at"""


class PostgresReportStore:
    """The report store on the findings store's database. Every method opens its own
    connection, and every change is one transaction."""

    def __init__(self, conninfo: str):
        self.conninfo = conninfo

    def _connect(self) -> psycopg.Connection:
        return psycopg.connect(self.conninfo, row_factory=dict_row)

    # What a report is drafted from --------------------------------------------------------

    def finding_context(self, finding_ids: tuple[str, ...]) -> FindingContext:
        """The findings, the latest verdict of their triage item, and the reviewer's latest
        edit, so the report is drafted from the finding as the reviewer left it (docs/sequences.md,
        approval and export). Raises LookupError for a finding that doesn't exist, and
        ReportError when the findings are not one finding or members of one group, or have no
        verdict with a severity."""
        ids = _normalized(finding_ids)
        with self._connect() as conn:
            findings = conn.execute(
                """SELECT id::text, group_id::text, tool, rule_id, message, cwe, file, start_line,
                          end_line, snippet
                   FROM findings WHERE id = ANY(%s::uuid[]) ORDER BY file, start_line, id""",
                (list(ids),),
            ).fetchall()
            if len(findings) != len(ids):
                missing = sorted(set(ids) - {row["id"] for row in findings})
                raise LookupError(f"no finding {', '.join(missing)}")
            group_id = _one_item(findings)
            states = {
                row["finding_id"]: row["state"]
                for row in conn.execute(
                    """SELECT finding_id::text, state FROM finding_states
                       WHERE (%(group)s::uuid IS NOT NULL AND group_id = %(group)s::uuid)
                          OR finding_id = ANY(%(ids)s::uuid[])""",
                    {"group": group_id, "ids": list(ids)},
                )
            }
            verdict = conn.execute(
                """SELECT reasoning, cited_lines, injection_suspected, cvss_v4_vector,
                          cvss_v4_score, cvss_v4_level, cvss_v4_justifications
                   FROM verdicts
                   WHERE (%(group)s::uuid IS NOT NULL AND group_id = %(group)s::uuid)
                      OR finding_id = ANY(%(ids)s::uuid[])
                   ORDER BY created_at DESC LIMIT 1""",
                {"group": group_id, "ids": list(ids)},
            ).fetchone()
            if verdict is None:
                raise ReportError("the findings have no verdict, so the report has no severity")
            edits = conn.execute(
                """SELECT reasoning, cvss_v4_vector, cvss_v4_score, cvss_v4_level
                   FROM finding_edits WHERE finding_id = ANY(%s::uuid[])
                   ORDER BY created_at DESC""",
                (list(ids),),
            ).fetchall()

        reasoning = next((e["reasoning"] for e in edits if e["reasoning"]), verdict["reasoning"])
        severity_edit = next((e for e in edits if e["cvss_v4_vector"]), None)
        if severity_edit is not None:
            severity = Severity(
                severity_edit["cvss_v4_vector"],
                float(severity_edit["cvss_v4_score"]),
                severity_edit["cvss_v4_level"],
            )
            # The AI's justifications explain its own vector, not the reviewer's.
            justifications = (
                verdict["cvss_v4_justifications"]
                if severity.vector == verdict["cvss_v4_vector"]
                else {}
            )
        else:
            severity = Severity(
                verdict["cvss_v4_vector"],
                float(verdict["cvss_v4_score"]),
                verdict["cvss_v4_level"],
            )
            justifications = verdict["cvss_v4_justifications"]

        locations: list[Location] = []
        for row in findings:
            location = Location(row["file"], row["start_line"], row["end_line"])
            if location not in locations:
                locations.append(location)
        cwes = sorted(
            {cwe for row in findings for cwe in row["cwe"]},
            key=lambda cwe: int(cwe.removeprefix("CWE-")),
        )
        return FindingContext(
            finding_ids=ids,
            states=states,
            rules=tuple(RuleHit(row["tool"], row["rule_id"], row["message"]) for row in findings),
            cwes=tuple(cwes),
            locations=tuple(locations),
            code=tuple(
                CodeBlock(row["file"], row["start_line"], row["end_line"], row["snippet"])
                for row in findings
                if row["snippet"]
            ),
            reasoning=reasoning,
            cited_lines=tuple(_location(item) for item in verdict["cited_lines"]),
            severity=severity,
            justifications=dict(justifications),
            injection_suspected=verdict["injection_suspected"],
        )

    # Reports and their texts ----------------------------------------------------------------

    def report_for(self, finding_ids: tuple[str, ...]) -> str | None:
        ids = _normalized(finding_ids)
        with self._connect() as conn:
            return self._report_for(conn, ids)

    def create_report(self, finding_ids: tuple[str, ...], text: ReportText) -> str:
        """The report row, its first text and the findings it covers, in one transaction. A lock
        on the triage item makes two drafts at the same time end up as one report."""
        ids = _normalized(finding_ids)
        with self._connect() as conn:
            group_id = self._group_of(conn, ids)
            item = group_id or ids[0]
            conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"report:{item}",))
            existing = self._report_for(conn, ids)
            if existing is not None:
                return existing
            report_id = conn.execute(
                """INSERT INTO reports (finding_id, group_id) VALUES (%s, %s) RETURNING id::text""",
                (None if group_id else ids[0], group_id),
            ).fetchone()["id"]
            self._insert_text(conn, report_id, 1, text)
            conn.cursor().executemany(
                "INSERT INTO report_findings (report_id, finding_id) VALUES (%s, %s)",
                [(report_id, finding_id) for finding_id in ids],
            )
            return report_id

    def get_report(self, report_id: str) -> StoredReport:
        with self._connect() as conn:
            row = self._report_row(conn, report_id)
            exported_version = None
            if row["exported_text_id"] is not None:
                exported_version = conn.execute(
                    "SELECT version FROM report_texts WHERE id = %s", (row["exported_text_id"],)
                ).fetchone()["version"]
            finding_ids = tuple(
                r["finding_id"]
                for r in conn.execute(
                    """SELECT rf.finding_id::text FROM report_findings rf
                       JOIN findings f ON f.id = rf.finding_id
                       WHERE rf.report_id = %s ORDER BY f.file, f.start_line, f.id""",
                    (report_id,),
                )
            )
        return StoredReport(
            report_id=report_id,
            finding_ids=finding_ids,
            status=row["status"],
            exported_at=row["exported_at"],
            exported_text_version=exported_version,
            export_path=row["export_path"],
            exported_by=row["exported_by"],
        )

    def current_text(self, report_id: str) -> ReportText:
        return self.texts(report_id)[-1]

    def texts(self, report_id: str) -> list[ReportText]:
        with self._connect() as conn:
            self._report_row(conn, report_id)
            rows = conn.execute(
                f"SELECT {TEXT_COLUMNS} FROM report_texts WHERE report_id = %s ORDER BY version",
                (report_id,),
            ).fetchall()
        return [_text(row) for row in rows]

    def add_text(self, report_id: str, text: ReportText) -> ReportText:
        """Saves text as the next version. Raises ReportExported, checked under the lock of the
        report row, when an export committed while the model was answering."""
        with self._connect() as conn:
            row = self._report_row(conn, report_id, lock=True)
            if row["status"] == "exported":
                raise ReportExported(f"report {report_id} was exported and can't change")
            version = conn.execute(
                "SELECT max(version) + 1 AS next FROM report_texts WHERE report_id = %s",
                (report_id,),
            ).fetchone()["next"]
            return self._insert_text(conn, report_id, version, text)

    def approve_text(self, report_id: str, version: int, approver: str, at: datetime) -> ReportText:
        with self._connect() as conn:
            row = conn.execute(
                f"""UPDATE report_texts SET approved_by = %s, approved_at = %s
                    WHERE report_id = %s AND version = %s RETURNING {TEXT_COLUMNS}""",
                (approver, at, report_id, version),
            ).fetchone()
        if row is None:
            raise UnknownReport(f"{report_id} version {version}")
        return _text(row)

    # Export -----------------------------------------------------------------------------------

    def export_refusals(self, report_id: str) -> list[str]:
        with self._connect() as conn:
            self._report_row(conn, report_id)
            return [
                row["reason"]
                for row in conn.execute("SELECT reason FROM export_refusals(%s)", (report_id,))
            ]

    def mark_exported(
        self, report_id: str, version: int, path: str, exported_by: str, at: datetime
    ) -> None:
        """Sets the report to exported, in one transaction that first checks the export again,
        so a decision made since the service checked can't slip through. The report keeps the
        approved members of its group, each linked to the review that approved it (F5, tests 3
        and 4).

        The transaction locks the report and its findings before it checks. A review or an edit
        that is being written waits for the export, or the export waits for it and then sees it,
        so a finding rejected at the same time can't leave a report that is exported with no
        finding. Raises StaleVersion when the version is not the newest text."""
        with self._connect() as conn:
            row = self._report_row(conn, report_id, lock=True)
            conn.execute(
                """SELECT id FROM findings
                   WHERE id = %(finding)s::uuid OR group_id = %(group)s::uuid
                   ORDER BY id FOR UPDATE""",
                {"finding": row["finding_id"], "group": row["group_id"]},
            )
            reasons = [
                r["reason"]
                for r in conn.execute("SELECT reason FROM export_refusals(%s)", (report_id,))
            ]
            if reasons:
                raise NotApproved(reasons)
            newest = self._newest_version(conn, report_id)
            if version != newest:
                raise StaleVersion(f"version {version} is not the newest, which is {newest}")
            members = self._approved_members(conn, row)
            if not members:
                raise NotApproved(["no approved finding in the report"])
            keep = [member["finding_id"] for member in members]
            conn.execute(
                """DELETE FROM report_findings WHERE report_id = %s
                   AND NOT finding_id = ANY(%s::uuid[])""",
                (report_id, keep),
            )
            conn.cursor().executemany(
                """INSERT INTO report_findings (report_id, finding_id, review_id)
                   VALUES (%s, %s, %s)
                   ON CONFLICT (report_id, finding_id)
                   DO UPDATE SET review_id = excluded.review_id""",
                [(report_id, m["finding_id"], m["counting_review_id"]) for m in members],
            )
            conn.execute(
                """UPDATE reports SET status = 'exported', exported_at = %s, export_path = %s,
                          exported_by = %s,
                          exported_text_id = (SELECT id FROM report_texts
                                              WHERE report_id = %s AND version = %s)
                   WHERE id = %s""",
                (at, path, exported_by, report_id, version, report_id),
            )

    # Helpers ----------------------------------------------------------------------------------

    def _report_row(self, conn: psycopg.Connection, report_id: str, lock: bool = False) -> dict:
        try:
            row = conn.execute(
                "SELECT finding_id::text, group_id::text, status, exported_at, exported_text_id,"
                " export_path, exported_by FROM reports WHERE id = %s"
                + (" FOR UPDATE" if lock else ""),
                (report_id,),
            ).fetchone()
        except psycopg.errors.InvalidTextRepresentation:
            raise UnknownReport(report_id) from None
        if row is None:
            raise UnknownReport(report_id)
        return row

    def _newest_version(self, conn: psycopg.Connection, report_id: str) -> int:
        return conn.execute(
            "SELECT max(version) AS newest FROM report_texts WHERE report_id = %s", (report_id,)
        ).fetchone()["newest"]

    def _approved_members(self, conn: psycopg.Connection, report: dict) -> list[dict]:
        """The findings of the report's item whose latest review approves them, with that
        review."""
        return conn.execute(
            """SELECT finding_id::text, counting_review_id::text FROM finding_states
               WHERE state = 'approved'
                 AND ((%(group)s::uuid IS NOT NULL AND group_id = %(group)s::uuid)
                      OR finding_id = %(finding)s::uuid)""",
            {"group": report["group_id"], "finding": report["finding_id"]},
        ).fetchall()

    def _group_of(self, conn: psycopg.Connection, ids: tuple[str, ...]) -> str | None:
        rows = conn.execute(
            "SELECT id::text, group_id::text FROM findings WHERE id = ANY(%s::uuid[])",
            (list(ids),),
        ).fetchall()
        if len(rows) != len(ids):
            raise LookupError(f"no finding among {', '.join(ids)}")
        return _one_item(rows)

    def _report_for(self, conn: psycopg.Connection, ids: tuple[str, ...]) -> str | None:
        group_id = self._group_of(conn, ids)
        row = conn.execute(
            "SELECT id::text FROM reports WHERE group_id = %s ORDER BY created_at LIMIT 1"
            if group_id
            else "SELECT id::text FROM reports WHERE finding_id = %s ORDER BY created_at LIMIT 1",
            (group_id or ids[0],),
        ).fetchone()
        return row["id"] if row else None

    def _insert_text(
        self, conn: psycopg.Connection, report_id: str, version: int, text: ReportText
    ) -> ReportText:
        row = conn.execute(
            f"""INSERT INTO report_texts (report_id, version, source, llm_call_id, author, title,
                    summary, impact, steps_to_reproduce, fix, "references", cvss_v4_vector,
                    cvss_v4_score, cvss_v4_level, locations)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING {TEXT_COLUMNS}""",
            (
                report_id,
                version,
                text.source,
                text.llm_call_id,
                text.author,
                text.title,
                text.summary,
                text.impact,
                list(text.steps_to_reproduce),
                text.fix,
                list(text.references),
                text.severity.vector,
                text.severity.score,
                text.severity.level,
                json.dumps([location.as_json() for location in text.locations]),
            ),
        ).fetchone()
        return _text(row)


def _normalized(finding_ids: tuple[str, ...]) -> tuple[str, ...]:
    """The finding IDs sorted and without repeats, so one set of findings always gives the same
    key. Something that is not a UUID can't be a finding."""
    ids = tuple(sorted({str(finding_id).lower() for finding_id in finding_ids}))
    if not ids:
        raise LookupError("a report needs at least one finding")
    for finding_id in ids:
        try:
            _uuid(finding_id)
        except ValueError:
            raise LookupError(f"no finding {finding_id}") from None
    return ids


def _uuid(value: str) -> str:
    return str(uuid.UUID(value))


def _one_item(rows: list[dict]) -> str | None:
    """The group of the findings, or None for a single finding without a group."""
    groups = {row["group_id"] for row in rows}
    if len(groups) == 1:
        (group_id,) = groups
        if group_id is not None or len(rows) == 1:
            return group_id
    raise ReportError("a report covers one finding, or approved members of one duplicate group")


def _location(item: dict) -> Location:
    return Location(item["file"], int(item["start_line"]), int(item["end_line"]))


def _text(row: dict) -> ReportText:
    return ReportText(
        version=row["version"],
        source=row["source"],
        title=row["title"],
        summary=row["summary"],
        impact=row["impact"],
        steps_to_reproduce=tuple(row["steps_to_reproduce"]),
        fix=row["fix"],
        references=tuple(row["references"]),
        severity=Severity(row["cvss_v4_vector"], float(row["cvss_v4_score"]), row["cvss_v4_level"]),
        locations=tuple(_location(item) for item in row["locations"]),
        llm_call_id=str(row["llm_call_id"]) if row["llm_call_id"] else None,
        author=row["author"],
        approved_by=row["approved_by"],
        approved_at=row["approved_at"],
        created_at=row["created_at"],
    )
