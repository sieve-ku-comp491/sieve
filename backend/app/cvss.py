"""CVSS v4.0 base scores, computed from the vector with FIRST's algorithm (the cvss package).

The AI and the reviewer choose the vector. The score and the level always come from here, so
nobody chooses a score by hand (docs/ui-mockups.md, finding detail).
"""

from dataclasses import dataclass

from cvss import CVSS4
from cvss.exceptions import CVSS4Error

BASE_METRICS = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")
PREFIX = "CVSS:4.0/"


@dataclass(frozen=True)
class Severity:
    vector: str
    score: float
    level: str


class VectorError(ValueError):
    pass


def score_v4(vector: str) -> Severity:
    """The score and level of a CVSS v4.0 vector with the 11 base metrics and nothing else,
    each given once. The vector comes back in the standard order of the metrics."""
    if not vector.startswith(PREFIX):
        raise VectorError(f"a CVSS v4.0 vector starts with {PREFIX}")
    parts = vector[len(PREFIX) :].split("/")
    names = [part.partition(":")[0] for part in parts]
    if sorted(names) != sorted(BASE_METRICS):
        raise VectorError("give each of the 11 base metrics once, and no other metric")
    try:
        cvss = CVSS4(vector)
    except CVSS4Error as error:
        raise VectorError(str(error)) from error
    return Severity(cvss.clean_vector(), float(cvss.base_score), level(float(cvss.base_score)))


def level(score: float) -> str:
    """The qualitative level of a score, as in the CVSS v4.0 specification, section 6."""
    if score == 0:
        return "none"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    return "critical"
