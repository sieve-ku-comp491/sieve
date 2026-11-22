"""Analyzer SARIF files as the findings CSV of the baseline run (docs/evaluation.md, "Baseline").

The baseline runs the analyzers directly, outside the pipeline, so the findings don't come from
the findings store. This turns each tool's SARIF file into the CSV that the false-positive check
reads. It reads the CWE, the path and the severity with the same adapter code as the pipeline
(app.adapters.BaseSarifAdapter), so a CWE tag is read the same way in both.
"""

import csv
import json
from dataclasses import dataclass
from pathlib import Path

from app.adapters import BaseSarifAdapter

COLUMNS = ["finding_id", "file", "cwe", "verdict", "tool", "severity"]


class SarifError(ValueError):
    """A SARIF file that can't be read as analyzer output."""


@dataclass(frozen=True)
class ToolFinding:
    """One result of one analyzer: where it is, its CWEs and the tool's own severity."""

    finding_id: str
    tool: str
    file: str
    cwes: tuple[str, ...]
    severity: str


@dataclass(frozen=True)
class SarifFindings:
    findings: list[ToolFinding]
    without_location: int
    outside_checkout: int


def read_sarif(tool: str, path: Path, strip_prefix: str = "") -> SarifFindings:
    """The findings of one SARIF file.

    A result with no location, or whose path is not inside the scanned folder, can't be matched
    to a test case. Both are counted, so the caller can see that something is missing.
    strip_prefix removes a leading folder from every path, for a tool that was started outside
    the scanned folder. A path without that prefix is an error, not a silent mismatch.
    """
    try:
        sarif = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise SarifError(f"{path}: {error}") from None
    adapter = BaseSarifAdapter()
    findings, no_location, outside = [], 0, 0
    for run in sarif.get("runs") or []:
        base_ids = run.get("originalUriBaseIds") or {}
        for result in run.get("results") or []:
            locations = result.get("locations") or []
            artifact = ((locations[0] if locations else {}).get("physicalLocation") or {}).get(
                "artifactLocation"
            ) or {}
            if not artifact.get("uri"):
                no_location += 1
                continue
            file = adapter.normalize_path(artifact["uri"], artifact.get("uriBaseId"), base_ids)
            if file and strip_prefix:
                if not file.startswith(strip_prefix):
                    raise SarifError(f"{path}: {file} doesn't start with {strip_prefix!r}")
                file = file[len(strip_prefix) :]
            if not file:
                outside += 1
                continue
            rule = adapter.find_rule(run, result)
            findings.append(
                ToolFinding(
                    finding_id=f"{tool}-{len(findings)}",
                    tool=tool,
                    file=file,
                    cwes=tuple(adapter.cwes(rule, result)),
                    severity=adapter.tool_severity(rule, result),
                )
            )
    return SarifFindings(findings, no_location, outside)


def write_findings(findings: list[ToolFinding], path: Path) -> None:
    """The CSV of metrics.read_findings, with the tool and its severity after the verdict."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(COLUMNS)
        for finding in findings:
            cwes = ";".join(finding.cwes)
            writer.writerow(
                [finding.finding_id, finding.file, cwes, "", finding.tool, finding.severity]
            )
