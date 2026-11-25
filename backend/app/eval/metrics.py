"""The evaluation's metrics, one function each (docs/evaluation.md, "Metrics").

Each function takes plain rows and returns plain numbers, so the same code scores the baseline
run (T6.2) and the full evaluation (T6.4).
"""

import csv
import statistics
from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from itertools import combinations
from pathlib import Path

from app.eval.expected import Expected, normalize_cwe

# CWEs that describe the same weakness at different levels. A finding tagged with one of them
# counts for a test case that expects another. Weak hashing (328) and broken crypto (327) are one
# group: Bandit and Semgrep tag MD5 and SHA-1 as CWE-327, while the Benchmark files those cases
# under 328. Each Benchmark case is its own file, so a hash finding can't count for a cipher case.
RELATED_CWES = [
    frozenset(group)
    for group in (
        {"CWE-22", "CWE-23", "CWE-36", "CWE-73"},
        {"CWE-77", "CWE-78", "CWE-88"},
        {"CWE-79", "CWE-80", "CWE-83", "CWE-87"},
        {"CWE-89", "CWE-564", "CWE-943"},
        {"CWE-94", "CWE-95"},
        {"CWE-326", "CWE-327", "CWE-328", "CWE-916"},
        {"CWE-330", "CWE-338"},
        {"CWE-611", "CWE-776"},
    )
]
VERDICTS = {"", "true_positive", "false_positive", "unsure"}
CVSS_METRICS = {
    "3": ("AV", "AC", "PR", "UI", "S", "C", "I", "A"),
    "4": ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"),
}


class MetricError(ValueError):
    """Input rows that can't be scored."""


def related(a: str, b: str) -> bool:
    return a == b or any(a in group and b in group for group in RELATED_CWES)


@dataclass(frozen=True)
class Finding:
    """One analyzer finding, with the triage verdict when there is one."""

    finding_id: str
    file: str
    cwes: frozenset[str]
    verdict: str = ""


def read_findings(path: Path) -> list[Finding]:
    """CSV columns: finding_id, file, cwe (several separated by ';'), verdict (empty if raw)."""
    findings = []
    for row in _read(path, ["finding_id", "file", "cwe", "verdict"]):
        verdict = row["verdict"].strip()
        if verdict not in VERDICTS:
            raise MetricError(f"{row['finding_id']}: unknown verdict {verdict!r}")
        cwes = frozenset(normalize_cwe(c) for c in row["cwe"].split(";") if c.strip())
        findings.append(Finding(row["finding_id"], row["file"], cwes, verdict))
    return findings


@dataclass(frozen=True)
class Confusion:
    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def tpr(self) -> float | None:
        return _ratio(self.tp, self.tp + self.fn)

    @property
    def fpr(self) -> float | None:
        return _ratio(self.fp, self.fp + self.tn)

    def as_dict(self) -> dict:
        score = None if self.tpr is None or self.fpr is None else self.tpr - self.fpr
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "tpr": _round(self.tpr),
            "fpr": _round(self.fpr),
            "score": _round(score),
        }


def confusion(cases: list[Expected], findings: Iterable[Finding]) -> Confusion:
    """Score each test case as a whole, the way the OWASP Benchmark does.

    A case is flagged when some finding in its file has the case's CWE or a related one.
    """
    by_file: dict[str, set[str]] = {}
    for finding in findings:
        by_file.setdefault(finding.file, set()).update(finding.cwes)
    tp = fp = fn = tn = 0
    for case in cases:
        flagged = any(related(case.cwe, cwe) for cwe in by_file.get(case.file, ()))
        if case.real:
            tp, fn = (tp + 1, fn) if flagged else (tp, fn + 1)
        else:
            fp, tn = (fp + 1, tn) if flagged else (fp, tn + 1)
    return Confusion(tp, fp, fn, tn)


def false_positive_check(cases: list[Expected], findings: list[Finding]) -> dict:
    """The raw analyzer output against the output after triage (requirement F4, test 3).

    Triage removes a finding only when its verdict is false_positive. Unsure findings stay,
    because the review screen still shows them. findings_without_case counts the findings whose
    file is no test case's file: a high number usually means the paths don't match, for example
    a path from another folder than the dataset's root, and the rates are then wrong.
    findings_without_cwe counts the findings with no CWE, which can never flag a case: a high
    number usually means an adapter didn't read the CWE of some rules.
    """
    if len({case.case_id for case in cases}) != len(cases):
        raise MetricError("each test case must appear once")
    kept = [finding for finding in findings if finding.verdict != "false_positive"]
    raw, triaged = confusion(cases, findings), confusion(cases, kept)
    case_files = {case.file for case in cases}
    result = {
        "cases": len(cases),
        "findings_without_case": sum(1 for finding in findings if finding.file not in case_files),
        "findings_without_cwe": sum(1 for finding in findings if not finding.cwes),
        "raw": raw.as_dict(),
        "triaged": triaged.as_dict(),
        "false_positives_removed": _round(_ratio(raw.fp - triaged.fp, raw.fp)),
        "true_positives_kept": _round(_ratio(triaged.tp, raw.tp)),
        "by_cwe": {},
    }
    for cwe in sorted({case.cwe for case in cases}, key=lambda c: int(c.removeprefix("CWE-"))):
        subset = [case for case in cases if case.cwe == cwe]
        result["by_cwe"][cwe] = {
            "raw": confusion(subset, findings).as_dict(),
            "triaged": confusion(subset, kept).as_dict(),
        }
    return result


def read_groups(path: Path) -> dict[str, str]:
    """CSV columns: finding_id, group. An empty group means the finding is on its own."""
    return {row["finding_id"]: row["group"].strip() for row in _read(path, ["finding_id", "group"])}


def merged_pairs(groups: dict[str, str]) -> set[frozenset[str]]:
    members: dict[str, list[str]] = {}
    for finding_id, group in groups.items():
        if group:
            members.setdefault(group, []).append(finding_id)
    return {frozenset(pair) for ids in members.values() for pair in combinations(sorted(ids), 2)}


def merge_precision_recall(labeled: dict[str, str], predicted: dict[str, str]) -> dict:
    """Precision and recall of merges, counted over pairs of findings (requirement F3, test 4).

    A pair is merged when both findings are in the same group. Precision is the share of merged
    pairs that the labels also merge, and recall the share of labeled pairs that were merged.
    """
    if set(labeled) != set(predicted):
        raise MetricError("the labeled and the predicted groups must cover the same findings")
    gold, merged = merged_pairs(labeled), merged_pairs(predicted)
    correct = len(gold & merged)
    return {
        "findings": len(labeled),
        "labeled_pairs": len(gold),
        "merged_pairs": len(merged),
        "correct_pairs": correct,
        "precision": _round(_ratio(correct, len(merged))),
        "recall": _round(_ratio(correct, len(gold))),
    }


def parse_vector(vector: str) -> tuple[str, dict[str, str]]:
    """'CVSS:3.1/AV:N/...' gives ('3', {'AV': 'N', ...}). 3.0 and 3.1 share one set of metrics."""
    prefix, _, rest = vector.strip().partition("/")
    family = {"CVSS:3.0": "3", "CVSS:3.1": "3", "CVSS:4.0": "4"}.get(prefix)
    if family is None:
        raise MetricError(f"not a CVSS 3 or 4 vector: {vector!r}")
    values = dict(part.split(":", 1) for part in rest.split("/") if ":" in part)
    missing = [name for name in CVSS_METRICS[family] if name not in values]
    if missing:
        raise MetricError(f"{vector!r} is missing base metrics {missing}")
    return family, values


def level(score: float) -> str:
    """The qualitative severity of a CVSS 3.x or 4.0 base score."""
    if not 0.0 <= score <= 10.0:
        raise MetricError(f"score out of range: {score}")
    if score == 0.0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def severity_agreement(rows: list[dict[str, str]]) -> dict:
    """The predicted CVSS against the published one (requirement F4, test 4).

    Rows have case_id, published_vector, published_score, predicted_vector and predicted_score,
    and both vectors in the same CVSS version, as the agent picks metrics in the CVE's version.
    A row with an empty predicted_vector is a CVE the agent gave no answer for: it is counted in
    no_prediction and left out of the averages.
    """
    if not rows:
        raise MetricError("no cases to score")
    answered = [row for row in rows if row["predicted_vector"].strip()]
    if not answered:
        raise MetricError("no case has a predicted vector")
    shares, errors, levels = [], [], []
    for row in answered:
        family, published = parse_vector(row["published_vector"])
        predicted_family, predicted = parse_vector(row["predicted_vector"])
        if family != predicted_family:
            raise MetricError(f"{row['case_id']}: published and predicted CVSS versions differ")
        names = CVSS_METRICS[family]
        shares.append(sum(published[name] == predicted[name] for name in names) / len(names))
        published_score, predicted_score = (
            float(row["published_score"]),
            float(row["predicted_score"]),
        )
        errors.append(abs(published_score - predicted_score))
        levels.append(level(published_score) == level(predicted_score))
    return {
        "cases": len(rows),
        "no_prediction": len(rows) - len(answered),
        "metrics_matched": _round(statistics.mean(shares)),
        "mean_score_error": _round(statistics.mean(errors)),
        "max_score_error": _round(max(errors)),
        "level_agreement": _round(sum(levels) / len(levels)),
    }


def read_severity(path: Path) -> list[dict[str, str]]:
    columns = [
        "case_id",
        "published_vector",
        "published_score",
        "predicted_vector",
        "predicted_score",
    ]
    return list(_read(path, columns))


def cost_and_time(rows: list[dict[str, str]]) -> dict:
    """API cost and time per finding (requirements N1 and N2). Rows have finding_id, cost_usd and
    seconds. The same rows from manual triage, with a cost of 0, give the baseline time."""
    if not rows:
        raise MetricError("no findings to measure")
    try:
        costs = [Decimal(row["cost_usd"]) for row in rows]
        seconds = [float(row["seconds"]) for row in rows]
    except (InvalidOperation, ValueError) as error:
        raise MetricError(f"cost_usd and seconds must be numbers: {error}") from None
    return {
        "findings": len(rows),
        "total_cost_usd": str(sum(costs)),
        "mean_cost_usd": str(round(sum(costs) / len(costs), 6)),
        "median_cost_usd": str(statistics.median(costs)),
        "total_seconds": _round(sum(seconds)),
        "mean_seconds": _round(statistics.mean(seconds)),
        "median_seconds": _round(statistics.median(seconds)),
    }


def read_costs(path: Path) -> list[dict[str, str]]:
    return list(_read(path, ["finding_id", "cost_usd", "seconds"]))


def _read(path: Path, columns: list[str]) -> Iterable[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = [column for column in columns if column not in (reader.fieldnames or [])]
        if missing:
            raise MetricError(f"{path}: missing columns {missing}")
        yield from reader


def _ratio(part: float, whole: float) -> float | None:
    return part / whole if whole else None


def _round(value: float | None) -> float | None:
    return None if value is None else round(value, 4)
