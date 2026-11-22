"""Report formats: each turns a Report into the text of one exported file.

Markdown is the core format. A platform format, such as HackerOne's, is one more class here, and
needs no change to the report service (requirement N5, test 4; docs/class-diagrams.md).
"""

from typing import Protocol

from app.reports.models import Report


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


def _line(text: str) -> str:
    """A title is one line, whatever the text has in it."""
    return " ".join(text.split())


def _indent(step: str) -> str:
    """A step that has more than one line keeps its lines under the step's number."""
    first, *rest = step.strip().splitlines() or [""]
    return "\n".join([first, *(f"   {line}" if line.strip() else "" for line in rest)])
