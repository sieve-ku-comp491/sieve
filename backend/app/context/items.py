"""The triage item: one finding, or one duplicate group with its members, and the code the triage
agent reads first (T3.3, docs/interfaces.md, Triage item).

The code is the function around the item's findings, found with tree-sitter
(app.context.functions), with its decorators or annotations. When no one function holds all the
findings, or the file's language isn't one we parse, it is the flagged lines with AROUND lines
before and after them. A function longer than MAX_LINES is cut the same way, and to MAX_LINES
at most. A line longer than MAX_LINE_CHARS, as in minified code, is cut around the flagged
column. The agent reads more code with its tools when it needs to.

Each finding's adapter masks the lines it masks in its own snippets, so a secret that Gitleaks
found never reaches a prompt (docs/finding-format.md, Gitleaks).
"""

from collections.abc import Sequence
from dataclasses import dataclass, field

from app.adapters import AdapterRegistry, Finding, FlowStep
from app.checkout import CheckoutReader
from app.context.functions import TreeSitterFunctionLookup
from app.context.injection import InjectionScanner
from app.dedup.functions import FunctionLookup, FunctionSpan

MAX_LINES = 200
AROUND = 20
MAX_LINE_CHARS = 500


@dataclass(frozen=True, order=True)
class Lines:
    file: str
    start_line: int
    end_line: int


@dataclass(frozen=True)
class Repo:
    """The checkout that the agent's tools read from."""

    scan_id: str
    commit: str


@dataclass
class CodeContext:
    code: str
    """The function's code, or the lines around the findings. Empty when the file can't be
    read."""
    location: Lines
    """Where code is."""
    function: FunctionSpan | None
    """The whole function around all the findings, also when code is only a part of it."""
    data_flow: list[FlowStep] = field(default_factory=list)
    """The path from the source to the flagged call, from the first finding that has one."""
    injection_lines: list[Lines] = field(default_factory=list)
    """The comments and strings that look like instructions to an AI (app.context.injection),
    in code and in the findings' data-flow steps and related locations."""

    @property
    def injection_suspected(self) -> bool:
        return bool(self.injection_lines)


@dataclass
class TriageItem:
    item_id: str
    """The finding's ID, or the duplicate group's."""
    findings: list[Finding]
    """The finding, or the group's members with the representative first."""
    context: CodeContext
    repo: Repo


class ContextCollector:
    """Builds the triage items of one scan from its checkout. Every file is read through the
    CheckoutReader, so no path can leave the checkout, and parsed once."""

    def __init__(
        self,
        reader: CheckoutReader,
        adapters: AdapterRegistry | None = None,
        lookup: FunctionLookup | None = None,
    ):
        self._reader = reader
        self._adapters = adapters if adapters is not None else AdapterRegistry()
        self._lookup = lookup if lookup is not None else TreeSitterFunctionLookup(reader)
        self._injections = InjectionScanner(reader)

    def item(self, item_id: str, findings: Sequence[Finding], repo: Repo) -> TriageItem:
        return TriageItem(item_id, list(findings), self.context(findings), repo)

    def context(self, findings: Sequence[Finding]) -> CodeContext:
        """The code context of one finding, or of a group's members, which are all in one
        file."""
        if not findings:
            raise ValueError("a triage item has at least one finding")
        flagged = [finding.location for finding in findings]
        file = flagged[0].file
        if any(location.file != file for location in flagged):
            raise ValueError(f"the findings of a triage item are in more than one file: {file}")
        first = min(location.start_line for location in flagged)
        last = max(location.end_line for location in flagged)
        functions = {self._lookup.enclosing_function(file, loc.start_line) for loc in flagged}
        function = functions.pop() if len(functions) == 1 else None
        start, end = _span(function, first, last)

        code = ""
        lines = self._reader.read_lines(file)
        if lines is not None:
            for finding in findings:
                lines = self._adapters.get(finding.tool).mask(lines, finding.location)
            end = min(end, len(lines))
            if end < start:
                start, end = first, last
            columns: dict[int, int] = {}
            for location in flagged:
                if location.start_column is not None:
                    columns.setdefault(location.start_line, location.start_column)
            code = "\n".join(
                _cut(lines[n - 1], columns.get(n)) for n in range(start, min(end, len(lines)) + 1)
            )

        places = [Lines(file, start, end)] + [
            Lines(step.file, step.start_line, step.end_line)
            for finding in findings
            for step in (*finding.data_flow, *finding.related_locations)
        ]
        injection_lines = sorted(
            {
                Lines(place.file, first_line, last_line)
                for place in places
                for first_line, last_line in self._injections.lines(
                    place.file, place.start_line, place.end_line
                )
            }
        )
        return CodeContext(
            code,
            Lines(file, start, end),
            function,
            next((list(finding.data_flow) for finding in findings if finding.data_flow), []),
            injection_lines,
        )


def _span(function: FunctionSpan | None, first: int, last: int) -> tuple[int, int]:
    """The lines of the context: the whole function when it isn't too long, else the flagged
    lines first to last with AROUND lines on each side, inside the function if there is one."""
    if function is not None and function.end_line - function.start_line < MAX_LINES:
        return function.start_line, function.end_line
    start, end = first - AROUND, last + AROUND
    if function is not None:
        start, end = max(start, function.start_line), min(end, function.end_line)
    start = max(1, start)
    return start, min(end, start + MAX_LINES - 1)


def _cut(line: str, column: int | None) -> str:
    """The line, or MAX_LINE_CHARS characters of it around column, with the cut marked."""
    if len(line) <= MAX_LINE_CHARS:
        return line
    start = 0
    if column is not None:
        start = min(max(0, column - 1 - MAX_LINE_CHARS // 2), len(line) - MAX_LINE_CHARS)
    end = start + MAX_LINE_CHARS
    before = f"[{start} characters cut] " if start else ""
    after = f" [{len(line) - end} characters cut]" if end < len(line) else ""
    return f"{before}{line[start:end]}{after}"
