"""Fingerprints, context hashes and ambiguous flags (docs/finding-format.md, "Fingerprint")."""

import hashlib
import re
from collections import defaultdict

from app.adapters.finding import Finding

CONTEXT_WINDOW = 10


def normalize(lines: list[str]) -> str:
    """All whitespace removed, single quotes turned into double quotes, empty lines dropped, so
    that a code formatter doesn't change the result."""
    out = (re.sub(r"\s+", "", line).replace("'", '"') for line in lines)
    return "\n".join(line for line in out if line)


def fingerprint(tool: str, rule_id: str, file: str, lines: list[str], occurrence: int) -> str:
    key = "\x1f".join([tool, rule_id, file, normalize(lines), str(occurrence)])
    return "v1:" + hashlib.sha256(key.encode("utf-8", "surrogatepass")).hexdigest()[:32]


def context_hash(
    file_lines: list[str], start_line: int, end_line: int, window: int = CONTEXT_WINDOW
) -> str:
    lines = file_lines[max(0, start_line - 1 - window) : end_line + window]
    return (
        "c1:" + hashlib.sha256(normalize(lines).encode("utf-8", "surrogatepass")).hexdigest()[:32]
    )


class Fingerprinter:
    """Assigns fingerprints to all findings of one run at once, because a finding's occurrence
    number depends on the other findings with the same tool, rule, file and flagged code."""

    def assign(self, findings: list[Finding], file_lines: dict[str, list[str] | None]) -> None:
        """file_lines maps each file to its lines after masking, or None when the file couldn't
        be read. Then the finding's snippet stands in for the flagged lines, and the context
        hash stays empty, so no earlier review can hide the finding."""
        groups: dict[tuple[str, str, str, str], list[tuple[Finding, list[str]]]] = defaultdict(list)
        for finding in findings:
            location = finding.location
            lines = file_lines.get(location.file)
            if lines is None:
                flagged = (location.snippet or "").split("\n")
                finding.context_hash = ""
            else:
                flagged = lines[location.start_line - 1 : location.end_line]
                finding.context_hash = context_hash(lines, location.start_line, location.end_line)
            key = (finding.tool, finding.rule_id, location.file, normalize(flagged))
            groups[key].append((finding, flagged))

        for (tool, rule_id, file, _), members in groups.items():
            members.sort(key=lambda member: _position(member[0]))
            for occurrence, (finding, flagged) in enumerate(members):
                finding.fingerprint = fingerprint(tool, rule_id, file, flagged, occurrence)
                finding.fingerprint_ambiguous = len(members) > 1


def _position(finding: Finding) -> tuple[int, int, int, int]:
    location = finding.location
    return (
        location.start_line,
        location.start_column or 0,
        location.end_line,
        location.end_column or 0,
    )
