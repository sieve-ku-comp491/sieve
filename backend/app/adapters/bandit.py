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

    def region(self, physical: dict) -> dict:
        """The line Bandit reports, the one in its JSON output, with its columns. The SARIF
        region can start further up: for a key in a dictionary, at the dictionary's first line.
        SARIF doesn't give Bandit's line, but contextRegion starts one line above it, so when
        that line isn't the region's start line, the location is that line alone.

        When contextRegion starts at line 1, Bandit's line is 1 or 2 and the two can't be told
        apart, so the region stays as it is. It still holds Bandit's line, since it starts at
        line 1 or 2 and SARIF's endLine is the code's second line.

        For a call flagged because of one argument, Bandit's line is the argument's while the
        columns are where the call starts and ends, on other lines. When the start column is
        past the end column, the line has no columns."""
        region = super().region(physical)
        context = physical.get("contextRegion")
        context_start = context.get("startLine") if isinstance(context, dict) else None
        start = region.get("startLine")
        if type(context_start) is not int or type(start) is not int or context_start < 2:
            return region
        line = context_start + 1
        if line == start:
            return region
        moved = {**region, "startLine": line, "endLine": line}
        first, last = region.get("startColumn"), region.get("endColumn")
        if type(first) is int and type(last) is int and first > last:
            del moved["startColumn"], moved["endColumn"]
        return moved

    def snippet(self, region: dict) -> str | None:
        """Bandit 1.9.4's snippet is only the first flagged line, and when the flagged code
        starts more than one line above the line Bandit reports, such as a key in a dictionary,
        it is a line from further down. So the snippet is always read from the checkout."""
        return None
