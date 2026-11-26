"""The report and its text versions (docs/interfaces.md, "Report schema").

A report has one row per approved finding or duplicate group, and every draft and edit of its text
is a new version. The AI's text stays as an earlier version next to the reviewer's (requirement
F5, test 4).
"""

import re
from dataclasses import dataclass, replace
from datetime import datetime

from app.llm.types import CodeBlock

CWE_URL = "https://cwe.mitre.org/data/definitions/{number}.html"
CWE_ID = re.compile(r"^CWE-(\d+)$")
URL = re.compile(r"^https?://\S+$")
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
# Every character below U+0020 except tab and line breaks, and DEL. PostgreSQL refuses NUL.
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
LEVELS = {"none", "low", "medium", "high", "critical"}

# The parts of a report that the AI drafts and the reviewer can edit.
TEXT_FIELDS = ("title", "summary", "impact", "steps_to_reproduce", "fix", "references")
LIST_FIELDS = {"steps_to_reproduce", "references"}

# The longest a part can be, in characters, and the most steps and references a report has.
MAX_LENGTH = {"title": 200, "summary": 10_000, "impact": 10_000, "fix": 10_000}
MAX_ITEM_LENGTH = 2_000
MAX_ITEMS = 30


class ReportError(Exception):
    """A report operation that can't be done."""


class NotApproved(ReportError):
    """Nothing is drafted or exported for a finding or a text that no person approved (F5)."""

    def __init__(self, reasons: list[str]):
        self.reasons = reasons
        super().__init__("; ".join(reasons))


class ReportInvalid(ReportError):
    """Report text that is missing a part, or has a part that is empty or malformed (F6)."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("; ".join(problems))


class ReportDraftError(ReportError):
    """The model's answer can't be used as the text of a report. No draft is saved."""


class ReportExported(ReportError):
    """An exported report is final: the file has left Sieve."""


class StaleVersion(ReportError):
    """The reviewer read one version, and a newer one has been saved since."""


class UnknownReport(LookupError):
    """No report has this ID."""


class UnknownFormat(LookupError):
    """No report format has this name."""


@dataclass(frozen=True)
class Location:
    file: str
    start_line: int
    end_line: int

    def as_text(self) -> str:
        lines = str(self.start_line)
        return lines if self.end_line == self.start_line else f"{self.start_line}-{self.end_line}"

    def as_json(self) -> dict:
        return {"file": self.file, "start_line": self.start_line, "end_line": self.end_line}


@dataclass(frozen=True)
class Severity:
    """The CVSS v4.0 severity of the finding, computed from its vector, never chosen by the LLM."""

    vector: str
    score: float
    level: str


@dataclass(frozen=True)
class ReportText:
    """One version of a report's text."""

    version: int
    source: str  # llm_draft or reviewer_edit
    title: str
    summary: str
    impact: str
    steps_to_reproduce: tuple[str, ...]
    fix: str
    references: tuple[str, ...]
    severity: Severity
    locations: tuple[Location, ...]
    llm_call_id: str | None = None
    author: str | None = None
    approved_by: str | None = None
    approved_at: datetime | None = None
    created_at: datetime | None = None

    @property
    def approved(self) -> bool:
        return self.approved_at is not None

    def with_fields(self, **fields: object) -> "ReportText":
        return replace(self, **fields)


@dataclass(frozen=True)
class Report:
    """A report as the formats render it: its identity and its current text."""

    report_id: str
    finding_ids: tuple[str, ...]
    title: str
    summary: str
    impact: str
    steps_to_reproduce: tuple[str, ...]
    fix: str
    references: tuple[str, ...]
    severity: Severity
    locations: tuple[Location, ...]
    version: int
    approved_by: str | None
    approved_at: datetime | None
    status: str  # draft or exported
    exported_at: datetime | None = None

    @classmethod
    def of(
        cls,
        report_id: str,
        finding_ids: tuple[str, ...],
        text: ReportText,
        status: str,
        exported_at: datetime | None = None,
    ) -> "Report":
        return cls(
            report_id=report_id,
            finding_ids=finding_ids,
            title=text.title,
            summary=text.summary,
            impact=text.impact,
            steps_to_reproduce=text.steps_to_reproduce,
            fix=text.fix,
            references=text.references,
            severity=text.severity,
            locations=text.locations,
            version=text.version,
            approved_by=text.approved_by,
            approved_at=text.approved_at,
            status=status,
            exported_at=exported_at,
        )


@dataclass(frozen=True)
class RuleHit:
    """One analyzer result that the report is about."""

    tool: str
    rule_id: str
    message: str


@dataclass(frozen=True)
class FindingContext:
    """Everything the report of one finding, or of the approved members of a group, is drafted from.

    The store builds it from the finding, its verdict and its code. states gives the state of
    each finding (docs/finding-states.md), because only approved findings get a report.
    """

    finding_ids: tuple[str, ...]
    states: dict[str, str]
    rules: tuple[RuleHit, ...]
    cwes: tuple[str, ...]
    locations: tuple[Location, ...]
    code: tuple[CodeBlock, ...]
    reasoning: str
    cited_lines: tuple[Location, ...]
    severity: Severity
    justifications: dict[str, str]
    injection_suspected: bool = False


def cwe_references(cwes: tuple[str, ...]) -> tuple[str, ...]:
    """The CWE entry of each CWE, which every report's references include (F6, test 1)."""
    urls = []
    for cwe in cwes:
        match = CWE_ID.match(cwe)
        if match:
            urls.append(CWE_URL.format(number=int(match.group(1))))
    return tuple(urls)


def problems(text: ReportText, cwes: tuple[str, ...] = ()) -> list[str]:
    """Why a text is not a complete report: every part present and not empty, every reference a
    URL, the CWE entry of each of the finding's CWEs among the references (F6, test 1), no part
    longer than its limit, no control character, and no code fence left open."""
    found = []
    for name, limit in MAX_LENGTH.items():
        value = getattr(text, name)
        if not value.strip():
            found.append(f"{name} is empty")
        if len(value) > limit:
            found.append(f"{name} is longer than {limit} characters")
        if CONTROL.search(value):
            found.append(f"{name} has a control character")
    for name, label in (("steps_to_reproduce", "step"), ("references", "reference")):
        items = getattr(text, name)
        if len(items) > MAX_ITEMS:
            found.append(f"{name} has more than {MAX_ITEMS} entries")
        for number, item in enumerate(items, 1):
            if len(item) > MAX_ITEM_LENGTH:
                found.append(f"{label} {number} is longer than {MAX_ITEM_LENGTH} characters")
            if CONTROL.search(item):
                found.append(f"{label} {number} has a control character")
    if not text.steps_to_reproduce:
        found.append("steps_to_reproduce has no step")
    elif any(not step.strip() for step in text.steps_to_reproduce):
        found.append("steps_to_reproduce has an empty step")
    for name in ("summary", "impact", "fix"):
        if _open_fence(getattr(text, name)):
            found.append(f"{name} has a code fence that isn't closed")
    for number, step in enumerate(text.steps_to_reproduce, 1):
        if _open_fence(step):
            found.append(f"step {number} has a code fence that isn't closed")
    if not text.references:
        found.append("references has no entry")
    for reference in text.references:
        if not URL.match(reference):
            found.append(f"reference {reference!r} is not a URL")
    for url in cwe_references(cwes):
        if url not in text.references:
            found.append(f"references don't include {url}")
    if text.severity.level not in LEVELS:
        found.append(f"severity level {text.severity.level!r} is not a CVSS level")
    if not text.locations:
        found.append("locations is empty")
    return found


def _open_fence(text: str) -> bool:
    """Whether a Markdown code fence in the text is left open, which would turn every later
    section of the report into code. A fence closes with the same character, at least as many
    times, and nothing after it."""
    opened = None
    for line in text.splitlines():
        match = FENCE.match(line)
        if match is None:
            continue
        fence = match.group(1)
        if opened is None:
            opened = fence
        elif (
            fence[0] == opened[0] and len(fence) >= len(opened) and not line[match.end() :].strip()
        ):
            opened = None
    return opened is not None
