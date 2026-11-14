"""Duplicate groups of one scan, and the steps that form them (requirement F3).

Grouping runs a list of steps in order. Each step gets the scan's findings and the groups the
earlier steps formed, and returns the groups after its own work. The rule step comes first
(app.dedup.rules). The text-similarity step and the LLM step for the groups the rules leave
unclear come after it, in the same list.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Protocol

METHODS = ("rule", "similarity", "llm")
SEVERITY_ORDER = ("error", "warning", "note", "none")


class GroupingError(ValueError):
    """A group that can't be saved as it is, or a scan that can't be grouped."""


@dataclass(frozen=True)
class ScanFinding:
    """What the grouping steps read of a stored finding."""

    finding_id: str
    tool: str
    rule_id: str
    cwe: tuple[str, ...]
    message: str
    tool_severity: str
    file: str
    start_line: int
    end_line: int
    rule_description: str | None = None
    snippet: str | None = None
    language: str | None = None


@dataclass
class Group:
    """Findings of one scan that describe the same issue, and how they were put together: the
    rule that matched, the similarity score, or the LLM calls that decided it (F3, test 2)."""

    members: list[ScanFinding]
    method: str
    reason: str
    rule: str | None = None
    similarity: float | None = None
    llm_call_ids: list[str] = field(default_factory=list)
    group_id: str | None = None

    @property
    def representative(self) -> ScanFinding:
        """The member the review screen shows first: the highest analyzer severity, then the
        first by file, line, tool and rule."""
        return min(self.members, key=_shown_first)

    def check(self) -> None:
        """Refuses a group that doesn't say how it was formed, or has fewer than two members."""
        ids = [member.finding_id for member in self.members]
        if len(set(ids)) < 2:
            raise GroupingError(f"a group needs at least two findings, got {ids}")
        if len(set(ids)) != len(ids):
            raise GroupingError(f"a finding is in the group twice: {ids}")
        if self.method not in METHODS:
            raise GroupingError(f"unknown method {self.method!r}")
        if self.method == "rule" and not self.rule:
            raise GroupingError("a rule group needs the rule that matched")
        if self.method == "similarity" and (
            self.similarity is None or not 0 <= self.similarity <= 1
        ):
            raise GroupingError("a similarity group needs a score from 0 to 1")
        if self.method == "llm" and not self.llm_call_ids:
            raise GroupingError("an llm group needs the calls that decided it")
        reason = self.reason.strip()
        if not reason or "\n" in reason:
            raise GroupingError("a group needs a reason of one line")


class GroupingStep(Protocol):
    def group(self, findings: Sequence[ScanFinding], groups: list[Group]) -> list[Group]:
        """Returns the groups after this step: the groups it was given, possibly with more
        members, and the new groups it formed. findings are all the findings being grouped,
        including the ones already in a group."""
        ...


def group_findings(findings: Sequence[ScanFinding], steps: Iterable[GroupingStep]) -> list[Group]:
    """Runs the steps in order and checks the result: every group says how it was formed, and
    every finding is in at most one group."""
    known = {finding.finding_id for finding in findings}
    groups: list[Group] = []
    for step in steps:
        groups = step.group(findings, list(groups))
    seen: set[str] = set()
    for group in groups:
        group.check()
        for member in group.members:
            if member.finding_id not in known:
                raise GroupingError(f"finding {member.finding_id} is not one being grouped")
            if member.finding_id in seen:
                raise GroupingError(f"finding {member.finding_id} is in two groups")
            seen.add(member.finding_id)
    return groups


def _shown_first(finding: ScanFinding) -> tuple:
    severity = (
        SEVERITY_ORDER.index(finding.tool_severity)
        if finding.tool_severity in SEVERITY_ORDER
        else len(SEVERITY_ORDER)
    )
    return (
        severity,
        finding.file,
        finding.start_line,
        finding.end_line,
        finding.tool,
        finding.rule_id,
        finding.finding_id,
    )
