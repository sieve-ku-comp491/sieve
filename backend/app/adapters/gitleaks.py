"""Gitleaks' SARIF output as findings (docs/finding-format.md).

A Gitleaks finding must never store the secret it found. The plug-in runs Gitleaks with
--redact, and this adapter also replaces every flagged line with REDACTED, so the snippet, the
fingerprint and the context hash are made from the masked lines, and BaseSarifAdapter removes
the tool's own snippets from raw.
"""

from app.adapters.base import BaseSarifAdapter
from app.adapters.finding import Location

HARD_CODED_CREDENTIALS = "CWE-798"
REDACTED = "REDACTED"


class GitleaksAdapter(BaseSarifAdapter):
    """Gitleaks gives no CWE, no level and no stable fingerprint: its partialFingerprints hold
    commit fields that are empty when it scans files instead of Git history."""

    tool = "gitleaks"

    def cwes(self, rule: dict, result: dict) -> list[str]:
        return [HARD_CODED_CREDENTIALS]

    def mask(self, lines: list[str], location: Location) -> list[str]:
        """Whole lines from start_line to end_line, not the reported columns: Gitleaks 8.30.1
        reports columns that are off by one, and private keys span several lines."""
        masked = list(lines)
        for index in range(location.start_line - 1, min(location.end_line, len(masked))):
            masked[index] = REDACTED
        return masked
