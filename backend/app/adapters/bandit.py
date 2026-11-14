"""Bandit's SARIF output as findings (docs/finding-format.md, "Bandit")."""

from app.adapters.base import BaseSarifAdapter

CONFIDENCES = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


class BanditAdapter(BaseSarifAdapter):
    """Bandit puts the CWE in a rule tag in CodeQL's form, which the shared mapping reads, and
    the confidence in each result's properties. Its level comes from the issue's severity:
    error for HIGH, note for LOW, and no level, so the SARIF default warning, for MEDIUM."""

    tool = "bandit"

    def confidence(self, rule: dict, result: dict) -> str | None:
        """From the result's issue_confidence. The rule's precision is the confidence of the
        rule's first result in the run, not a property of the rule, so the adapter ignores it."""
        value = (result.get("properties") or {}).get("issue_confidence")
        return CONFIDENCES.get(value.upper()) if isinstance(value, str) else None

    def snippet(self, region: dict) -> str | None:
        """Bandit 1.9.4's snippet is only the first flagged line, and when the flagged code
        starts more than one line above the line Bandit reports, such as a key in a dictionary,
        it is a line from further down. So the snippet is always read from the checkout."""
        return None
