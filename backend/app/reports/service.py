"""The report service (docs/class-diagrams.md, "Report format"; requirements F5 and F6).

It drafts the text of a report through LLMClient, keeps every version of the text, and exports a
report only when a person approved both the findings and the current text. The checks are here,
in the service, so no client can skip them, including the CLI and the evaluation harness.
"""

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path

from app.llm import LLMClient, StopReason, load_template
from app.reports.draft import TEMPLATE, parse_draft, prompt_values
from app.reports.formats import ReportFormat, default_formats
from app.reports.models import (
    LIST_FIELDS,
    TEXT_FIELDS,
    FindingContext,
    NotApproved,
    Report,
    ReportDraftError,
    ReportExported,
    ReportInvalid,
    ReportText,
    StaleVersion,
    UnknownFormat,
    problems,
)
from app.reports.store import ReportStore, StoredReport

DEFAULT_MAX_TOKENS = 4000


class ReportService:
    def __init__(
        self,
        store: ReportStore,
        client: LLMClient,
        exports_dir: Path,
        formats: Mapping[str, ReportFormat] | None = None,
        model: str | None = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ):
        self.store = store
        self.client = client
        self.exports_dir = exports_dir
        self.formats = dict(formats) if formats is not None else default_formats()
        self.model = model
        self.max_tokens = max_tokens
        self.now = now

    def draft(self, finding_ids: tuple[str, ...]) -> Report:
        """The report of approved findings, with the model's draft as version 1.

        Asking again for findings that already have a report returns it and makes no call.
        Raises NotApproved when a finding isn't approved, so a rejected or unreviewed finding
        gets no report (F6, test 2), and ReportDraftError when the model's answer isn't a
        complete report. In both cases nothing is saved. BudgetExceeded and ProviderError from
        the call pass through, and the approvals stay as they are.
        """
        finding_ids = tuple(finding_ids)
        existing = self.store.report_for(finding_ids)
        if existing is not None:
            return self.get(existing)
        context = self.store.finding_context(finding_ids)
        self._require_approved(context)
        text = self._ask(context, attempt=1, previous=None)
        report_id = self.store.create_report(finding_ids, text)
        return self.get(report_id)

    def edit(self, report_id: str, fields: Mapping[str, object], editor: str) -> Report:
        """The reviewer's change to the text. It is a new version that needs a new approval, and
        the earlier version stays. A change that leaves the text as it is saves nothing, so it
        doesn't undo an approval. Raises ReportInvalid for an unknown field or a text that is not
        a complete report (F6)."""
        report = self._open(report_id)
        current = self.store.current_text(report_id)
        unknown = sorted(set(fields) - set(TEXT_FIELDS))
        if unknown:
            raise ReportInvalid([f"{name} can't be edited here" for name in unknown])
        wrong = [name for name, value in fields.items() if not _right_type(name, value)]
        if wrong:
            raise ReportInvalid([f"{name} has the wrong type" for name in sorted(wrong)])
        changes = {
            name: tuple(value) if name in LIST_FIELDS else value for name, value in fields.items()
        }
        edited = current.with_fields(**changes)
        if edited == current:
            return self.get(report_id)
        context = self.store.finding_context(report.finding_ids)
        edited = edited.with_fields(source="reviewer_edit", author=editor, llm_call_id=None)
        found = problems(edited, context.cwes)
        if found:
            raise ReportInvalid(found)
        self.store.add_text(report_id, edited)
        return self.get(report_id)

    def redraft(self, report_id: str) -> Report:
        """A new draft from the model, as the next version. The earlier text goes into the
        request, so the answer is a new text and not the cached one. It needs a new approval."""
        report = self._open(report_id)
        context = self.store.finding_context(report.finding_ids)
        self._require_approved(context)
        previous = self.store.current_text(report_id)
        text = self._ask(context, attempt=previous.version + 1, previous=previous)
        self.store.add_text(report_id, text)
        return self.get(report_id)

    def approve_text(self, report_id: str, version: int, approver: str) -> Report:
        """A person's approval of one version of the text. It takes the version the reviewer
        read, so a newer text can't be approved unseen. Raises StaleVersion if it isn't the
        latest."""
        self._open(report_id)
        current = self.store.current_text(report_id)
        if version != current.version:
            raise StaleVersion(
                f"version {version} is not the latest, which is version {current.version}"
            )
        self.store.approve_text(report_id, version, approver, self.now())
        return self.get(report_id)

    def export(self, report_id: str, exported_by: str, format: str = "markdown") -> str:
        """The report's file text, written to exports_dir. Raises NotApproved, with every reason,
        unless every finding is decided with an approval and the current text is approved, and
        ReportInvalid if the text is not a complete report (F5, F6)."""
        try:
            report_format = self.formats[format]
        except KeyError:
            raise UnknownFormat(format) from None
        refusals = self.store.export_refusals(report_id)
        if refusals:
            raise NotApproved(refusals)
        stored = self.store.get_report(report_id)
        text = self.store.current_text(report_id)
        found = problems(text, self.store.finding_context(stored.finding_ids).cwes)
        if found:
            raise ReportInvalid(found)
        content = report_format.render(Report.of(report_id, stored.finding_ids, text, "draft"))
        path = self.exports_dir / f"{report_id}{report_format.file_extension}"
        self.exports_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
        self.store.mark_exported(report_id, text.version, str(path), exported_by, self.now())
        return content

    def get(self, report_id: str) -> Report:
        stored = self.store.get_report(report_id)
        return Report.of(
            report_id,
            stored.finding_ids,
            self.store.current_text(report_id),
            stored.status,
            stored.exported_at,
        )

    def versions(self, report_id: str) -> list[ReportText]:
        """Every version of the text, oldest first: the AI's drafts and the reviewer's edits."""
        return self.store.texts(report_id)

    # ----------------------------------------------------------------------------------------

    def _open(self, report_id: str) -> StoredReport:
        stored = self.store.get_report(report_id)
        if stored.status == "exported":
            raise ReportExported(f"report {report_id} was exported and can't change")
        return stored

    @staticmethod
    def _require_approved(context: FindingContext) -> None:
        reasons = [
            f"finding {finding_id} is {context.states.get(finding_id, 'unknown')}, not approved"
            for finding_id in context.finding_ids
            if context.states.get(finding_id) != "approved"
        ]
        if reasons:
            raise NotApproved(reasons)

    def _ask(
        self, context: FindingContext, attempt: int, previous: ReportText | None
    ) -> ReportText:
        response = self.client.ask(
            load_template(TEMPLATE),
            prompt_values(context, attempt, previous),
            context.code,
            model=self.model,
            max_tokens=self.max_tokens,
        )
        if response.stop_reason != StopReason.COMPLETE:
            raise ReportDraftError(f"the model's answer ended with {response.stop_reason.value}")
        if response.call_id is None:
            # Every AI decision must link to its logged call (requirement N3).
            raise ReportDraftError("the model's call was not logged, so its text can't be kept")
        return parse_draft(response.text, context, response.call_id)


def _right_type(name: str, value: object) -> bool:
    """Steps and references are lists of text, every other part is text."""
    if name in LIST_FIELDS:
        return isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value)
    return isinstance(value, str)
