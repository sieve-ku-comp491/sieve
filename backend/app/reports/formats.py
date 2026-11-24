"""Report formats: each turns a Report into the text of one exported file.

Markdown is the core format. A platform format, such as HackerOne's, is one more class here, and
needs no change to the report service (requirement N5, test 4; docs/class-diagrams.md).
"""

from typing import Protocol

from app.reports.models import Location, Report


class ReportFormat(Protocol):
    name: str
    file_extension: str

    def render(self, report: Report) -> str: ...


class MarkdownFormat:
    """One Markdown file per report, in the layout of docs/interfaces.md."""

    name = "markdown"
    file_extension = ".md"

    def render(self, report: Report) -> str:
        severity = report.severity
        lines = [
            f"# {_line(report.title)}",
            "",
            f"Severity: {severity.level.capitalize()} (CVSS 4.0 score {severity.score:.1f})",
            f"Vector: {severity.vector}",
            *(f"Location: {_where(location)}" for location in report.locations),
            "",
            "## Summary",
            "",
            report.summary.strip(),
            "",
            "## Impact",
            "",
            report.impact.strip(),
            "",
            "## Steps to reproduce",
            "",
            *(
                f"{number}. {_indent(step)}"
                for number, step in enumerate(report.steps_to_reproduce, 1)
            ),
            "",
            "## Fix",
            "",
            report.fix.strip(),
            "",
            "## References",
            "",
            *(f"- {reference}" for reference in report.references),
        ]
        return "\n".join(lines) + "\n"


def default_formats() -> dict[str, ReportFormat]:
    return {format.name: format for format in (MarkdownFormat(),)}


def _where(location: Location) -> str:
    """A file and its lines, as the report preview shows them (docs/ui-mockups.md)."""
    if location.start_line == location.end_line:
        return f"{_line(location.file)}, line {location.start_line}"
    return f"{_line(location.file)}, lines {location.start_line} to {location.end_line}"


def _line(text: str) -> str:
    """A title or a file name is one line, whatever the text has in it, so it can't start a
    section of its own."""
    return " ".join(text.split())


def _indent(step: str) -> str:
    """A step that has more than one line keeps its lines under the step's number."""
    first, *rest = step.strip().splitlines() or [""]
    return "\n".join([first, *(f"   {line}" if line.strip() else "" for line in rest)])
