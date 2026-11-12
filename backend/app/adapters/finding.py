"""The finding format of docs/finding-format.md."""

from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("error", "warning", "note", "none")
MAX_WARNINGS = 100
CONFIDENCES = ("high", "medium", "low")


@dataclass
class Location:
    file: str
    start_line: int
    end_line: int
    start_column: int | None = None
    end_column: int | None = None
    snippet: str | None = None


@dataclass
class FlowStep(Location):
    step: int = 0
    message: str | None = None


@dataclass
class Finding:
    scan_id: str
    run_id: str
    tool: str
    tool_version: str
    rule_id: str
    message: str
    tool_severity: str
    location: Location
    raw: dict[str, Any]
    rule_description: str | None = None
    rule_help_uri: str | None = None
    cwe: list[str] = field(default_factory=list)
    tool_score: float | None = None
    tool_confidence: str | None = None
    related_locations: list[Location] = field(default_factory=list)
    data_flow: list[FlowStep] = field(default_factory=list)
    fingerprint: str = ""
    fingerprint_ambiguous: bool = False
    context_hash: str = ""
    suppressed: bool = False
    tool_fingerprint: str | None = None
    language: str = "other"
    finding_id: str | None = None


@dataclass
class AdapterResult:
    """An adapter's output for one run: its findings, the results it dropped by reason, and
    warnings for the run's log."""

    findings: list[Finding] = field(default_factory=list)
    dropped: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    more_warnings: int = 0

    def drop(self, reason: str, warning: str | None = None) -> None:
        self.dropped[reason] = self.dropped.get(reason, 0) + 1
        if warning:
            self.warn(warning)

    def warn(self, warning: str) -> None:
        """Keeps the first MAX_WARNINGS warnings for the run's log and counts the rest."""
        if len(self.warnings) < MAX_WARNINGS:
            self.warnings.append(warning)
        else:
            self.more_warnings += 1

    @property
    def dropped_count(self) -> int:
        return sum(self.dropped.values())
