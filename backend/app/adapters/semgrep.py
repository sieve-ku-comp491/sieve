"""Semgrep's SARIF output as findings (docs/finding-format.md, "Example: Semgrep on PyGoat")."""

from app.adapters.base import BaseSarifAdapter

CONFIDENCE_TAGS = {
    "HIGH CONFIDENCE": "high",
    "MEDIUM CONFIDENCE": "medium",
    "LOW CONFIDENCE": "low",
}


class SemgrepAdapter(BaseSarifAdapter):
    """Semgrep puts the CWE and the confidence in its rule tags. Its precision property is
    "very-high" on every rule, so the adapter ignores it."""

    tool = "semgrep"

    def confidence(self, rule: dict, result: dict) -> str | None:
        for tag in (rule.get("properties") or {}).get("tags") or []:
            if isinstance(tag, str) and tag.upper() in CONFIDENCE_TAGS:
                return CONFIDENCE_TAGS[tag.upper()]
        return None

    def tool_fingerprint(self, result: dict) -> str | None:
        """Semgrep without a login to its platform writes "requires login" as the fingerprint
        of every result, so there is nothing stable to keep."""
        return None
