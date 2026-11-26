"""Where the report service keeps reports: an interface, and an in-memory store for tests.

The Postgres store, on the tables reports, report_texts and report_findings of docs/database.md,
implements the same interface. Both follow the rules of docs/finding-states.md, and the same
service tests run against each.
"""

from dataclasses import dataclass, replace
from datetime import datetime
from typing import Protocol

from app.reports.models import FindingContext, NotApproved, ReportText, UnknownReport

UNDECIDED = ("new", "grouped", "triaged", "edited")


@dataclass(frozen=True)
class StoredReport:
    """The row of a report. Its text is kept in versions, see ReportStore.texts."""

    report_id: str
    finding_ids: tuple[str, ...]
    status: str  # draft or exported
    exported_at: datetime | None = None
    exported_text_version: int | None = None
    export_path: str | None = None
    exported_by: str | None = None
    format: str = "markdown"  # the format it was exported in


class ReportStore(Protocol):
    def finding_context(self, finding_ids: tuple[str, ...]) -> FindingContext:
        """What the report of these findings is drafted from. Raises LookupError for a finding
        that doesn't exist."""

    def report_for(self, finding_ids: tuple[str, ...]) -> str | None:
        """The ID of the report of these findings, if they have one."""

    def create_report(self, finding_ids: tuple[str, ...], text: ReportText) -> str:
        """A new report with text as its version 1, saved together. Returns the report's ID."""

    def get_report(self, report_id: str) -> StoredReport:
        """Raises UnknownReport."""

    def current_text(self, report_id: str) -> ReportText:
        """The highest version."""

    def texts(self, report_id: str) -> list[ReportText]:
        """Every version, oldest first."""

    def add_text(
        self, report_id: str, text: ReportText, finding_ids: tuple[str, ...] | None = None
    ) -> ReportText:
        """Saves text as the next version, without an approval, and returns it with its number.
        finding_ids are the findings a new draft was drafted from, and become the report's.
        None keeps them, as for an edit."""

    def approve_text(self, report_id: str, version: int, approver: str, at: datetime) -> ReportText:
        """Sets the approval of one version of the text."""

    def export_refusals(self, report_id: str) -> list[str]:
        """Why the report can't be exported, empty when it can (export_refusals in
        docs/finding-states.md)."""

    def mark_exported(
        self,
        report_id: str,
        version: int,
        path: str,
        exported_by: str,
        at: datetime,
        format: str = "markdown",
    ) -> None:
        """Sets the report to exported, with the version and the format that were exported."""


class InMemoryReportStore:
    """A store in memory. The contexts say what each finding set is, and set_state changes the
    state of a finding, as a person's review would."""

    def __init__(self, contexts: list[FindingContext]):
        self._contexts = {context.finding_ids: context for context in contexts}
        self._reports: dict[str, StoredReport] = {}
        self._texts: dict[str, list[ReportText]] = {}
        self._count = 0

    def set_state(self, finding_id: str, state: str) -> None:
        for context in self._contexts.values():
            if finding_id in context.states:
                context.states[finding_id] = state

    def change_finding(self, finding_id: str, **fields: object) -> None:
        """Changes what every finding set with this finding says, such as its severity, as a
        reviewer's edit of the finding would."""
        for ids, context in self._contexts.items():
            if finding_id in ids:
                self._contexts[ids] = replace(context, **fields)

    def finding_context(self, finding_ids: tuple[str, ...]) -> FindingContext:
        try:
            return self._contexts[tuple(finding_ids)]
        except KeyError:
            raise LookupError(f"no finding set {tuple(finding_ids)}") from None

    def report_for(self, finding_ids: tuple[str, ...]) -> str | None:
        for report in self._reports.values():
            if report.finding_ids == tuple(finding_ids):
                return report.report_id
        return None

    def create_report(self, finding_ids: tuple[str, ...], text: ReportText) -> str:
        self._count += 1
        report_id = f"report-{self._count}"
        self._reports[report_id] = StoredReport(report_id, tuple(finding_ids), "draft")
        self._texts[report_id] = [replace(text, version=1)]
        return report_id

    def get_report(self, report_id: str) -> StoredReport:
        try:
            return self._reports[report_id]
        except KeyError:
            raise UnknownReport(report_id) from None

    def current_text(self, report_id: str) -> ReportText:
        return self.texts(report_id)[-1]

    def texts(self, report_id: str) -> list[ReportText]:
        self.get_report(report_id)
        return list(self._texts[report_id])

    def add_text(
        self, report_id: str, text: ReportText, finding_ids: tuple[str, ...] | None = None
    ) -> ReportText:
        report = self.get_report(report_id)
        if finding_ids is not None:
            self._reports[report_id] = replace(report, finding_ids=tuple(finding_ids))
        saved = replace(
            text,
            version=len(self._texts[report_id]) + 1,
            approved_by=None,
            approved_at=None,
        )
        self._texts[report_id].append(saved)
        return saved

    def approve_text(self, report_id: str, version: int, approver: str, at: datetime) -> ReportText:
        versions = self._texts[self.get_report(report_id).report_id]
        approved = replace(versions[version - 1], approved_by=approver, approved_at=at)
        versions[version - 1] = approved
        return approved

    def export_refusals(self, report_id: str) -> list[str]:
        report = self.get_report(report_id)
        context = self.finding_context(report.finding_ids)
        reasons = []
        if report.status == "exported":
            reasons.append("report is already exported")
        if not self.current_text(report_id).approved:
            reasons.append("current report text is not approved")
        for finding_id, state in context.states.items():
            if state in UNDECIDED:
                reasons.append(f"finding {finding_id} is {state}, not decided")
        if "approved" not in context.states.values():
            reasons.append("no approved finding in the report")
        return reasons

    def mark_exported(
        self,
        report_id: str,
        version: int,
        path: str,
        exported_by: str,
        at: datetime,
        format: str = "markdown",
    ) -> None:
        # Checks again, as the Postgres store does in the same transaction.
        reasons = self.export_refusals(report_id)
        if reasons:
            raise NotApproved(reasons)
        report = self.get_report(report_id)
        self._reports[report_id] = replace(
            report,
            status="exported",
            exported_at=at,
            exported_text_version=version,
            export_path=path,
            exported_by=exported_by,
            format=format,
        )
