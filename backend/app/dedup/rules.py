"""The rule step of grouping: findings in the same function, or in the same file on nearby lines,
with related CWEs (requirement F3).

Two findings match when they are in the same file, some CWE of one is the same as or related to
some CWE of the other (RELATED_CWES in app.eval.metrics, the list the evaluation uses, and
COPIED_RULE_CWES below), and either:

- the function lookup knows a function for both and it is the same function
  (same_function_related_cwe), or
- it knows a function for neither, and their lines overlap or are at most NEARBY_LINES apart
  (nearby_lines_related_cwe). This is the case for languages the lookup doesn't parse, such as
  HTML templates, and for code outside any function.

When it knows a function for one and not for the other, or two different functions, they don't
match, however close their lines are. A finding without a CWE matches nothing here and is left
to the later steps.

Two findings of the same tool match only when their lines overlap, on top of the rules above. A
tool reports each place it matched as its own result, so two of its results whose lines don't
overlap are two places, such as one rule on two forms of a template, or two rules on a DEBUG and
a SECRET_KEY setting a few lines apart. Two rules of one tool on the same call still match. The
nearby lines and the same function are for findings of different tools, which often disagree on
the line.

A finding joins a group only if it matches every member, not just one, so a chain of findings a
few lines apart each can't grow into one long group. Findings are taken in order of file, line,
tool and rule, so the result doesn't depend on the order they were stored in.
"""

import re
from collections import defaultdict
from collections.abc import Sequence

from app.dedup.functions import FunctionLookup, FunctionSpan, NoFunctionLookup
from app.dedup.groups import Group, ScanFinding
from app.eval.metrics import related

# Kept small, because a wrong merge costs more than a missed one: the precision target of F3 is
# 0.9. Analyzers that flag the same call report the same line or lines of the same statement.
NEARBY_LINES = 3

# semgrep-rules has its own copies of three rules of eslint-plugin-security, tagged with other
# CWEs than the ESLint adapter's table (docs/finding-format.md), so the same issue found by both
# tools would not group. These pairs relate them for grouping only: RELATED_CWES also decides
# which test cases a finding counts for in the evaluation, where they don't belong.
COPIED_RULE_CWES = [
    frozenset(pair)
    for pair in (
        # detect-buffer-noassert: Semgrep CWE-119, ESLint CWE-125 and CWE-787.
        ("CWE-119", "CWE-125"),
        ("CWE-119", "CWE-787"),
        # detect-disable-mustache-escape: Semgrep CWE-116, ESLint CWE-79.
        ("CWE-116", "CWE-79"),
        # detect-non-literal-require: Semgrep CWE-95, ESLint CWE-829.
        ("CWE-95", "CWE-829"),
    )
]

SAME_FUNCTION = "same_function_related_cwe"
NEARBY = "nearby_lines_related_cwe"


class RuleStep:
    def __init__(self, lookup: FunctionLookup | None = None, nearby_lines: int = NEARBY_LINES):
        self._lookup = lookup if lookup is not None else NoFunctionLookup()
        self._nearby = nearby_lines

    def group(self, findings: Sequence[ScanFinding], groups: list[Group]) -> list[Group]:
        """Groups the findings that are in no group yet, and adds the new groups to groups."""
        taken = {member.finding_id for group in groups for member in group.members}
        by_file: dict[str, list[ScanFinding]] = defaultdict(list)
        for finding in findings:
            if finding.finding_id not in taken:
                by_file[finding.file].append(finding)

        new = []
        for file in sorted(by_file):
            functions = {
                f.finding_id: self._lookup.enclosing_function(file, f.start_line)
                for f in by_file[file]
            }
            clusters: list[list[ScanFinding]] = []
            for finding in sorted(by_file[file], key=_order):
                for cluster in clusters:
                    if all(self._match(finding, member, functions) for member in cluster):
                        cluster.append(finding)
                        break
                else:
                    clusters.append([finding])
            new += [_rule_group(c, functions[c[0].finding_id]) for c in clusters if len(c) > 1]
        return groups + new

    def _match(
        self, a: ScanFinding, b: ScanFinding, functions: dict[str, FunctionSpan | None]
    ) -> bool:
        if not any(_related(x, y) for x in a.cwe for y in b.cwe):
            return False
        return close(a, b, functions[a.finding_id], functions[b.finding_id], self._nearby)


def close(
    a: ScanFinding,
    b: ScanFinding,
    function_a: FunctionSpan | None,
    function_b: FunctionSpan | None,
    nearby_lines: int = NEARBY_LINES,
) -> bool:
    """Whether a and b are close enough in the code to be one issue, as the rules count it:
    findings of one tool only when their lines overlap, others in the same function, or, when no
    function is known for either, at most nearby_lines apart. The text-similarity and LLM steps
    use the same test."""
    if a.tool == b.tool and not _within(a, b, 0):
        return False
    if function_a is not None or function_b is not None:
        return function_a == function_b
    return _within(a, b, nearby_lines)


def _within(a: ScanFinding, b: ScanFinding, lines: int) -> bool:
    """True when the line ranges of a and b overlap or are at most lines apart."""
    return a.start_line - lines <= b.end_line and b.start_line - lines <= a.end_line


def _related(a: str, b: str) -> bool:
    return related(a, b) or frozenset((a, b)) in COPIED_RULE_CWES


def _rule_group(members: list[ScanFinding], function: FunctionSpan | None) -> Group:
    # Only the CWEs that relate a member to another one, not every tag the members carry.
    linked = {
        cwe
        for member in members
        for cwe in member.cwe
        for other in members
        if other is not member and any(_related(cwe, theirs) for theirs in other.cwe)
    }
    cwe_text = _join(sorted(linked, key=_cwe_number))
    if function is not None:
        return Group(
            members,
            "rule",
            f"Same function {function.name} (lines {function.start_line} to "
            f"{function.end_line}) and related CWEs ({cwe_text})",
            rule=SAME_FUNCTION,
        )
    first = min(member.start_line for member in members)
    last = max(member.end_line for member in members)
    lines = f"line {first}" if first == last else f"lines {first} to {last}"
    return Group(
        members,
        "rule",
        f"Same file, {lines}, and related CWEs ({cwe_text})",
        rule=NEARBY,
    )


def _order(finding: ScanFinding) -> tuple:
    return (
        finding.start_line,
        finding.end_line,
        finding.tool,
        finding.rule_id,
        finding.finding_id,
    )


def _cwe_number(cwe: str) -> tuple[int, str]:
    match = re.fullmatch(r"CWE-(\d+)", cwe)
    return (int(match.group(1)), cwe) if match else (1 << 31, cwe)


def _join(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]
