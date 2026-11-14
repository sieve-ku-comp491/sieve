"""ESLint's SARIF output as findings, from the @microsoft/eslint-formatter-sarif formatter
(docs/finding-format.md, "CWE")."""

from app.adapters.base import BaseSarifAdapter

# The rules of eslint-plugin-security 4.2.1, which carry no CWE. The plug-in's configuration
# registers the plug-in as "security", so ESLint reports its rules with that prefix.
RULE_CWES = {
    "security/detect-bidi-characters": ["CWE-451"],
    "security/detect-buffer-noassert": ["CWE-125", "CWE-787"],
    "security/detect-child-process": ["CWE-78"],
    "security/detect-disable-mustache-escape": ["CWE-79"],
    "security/detect-eval-with-expression": ["CWE-95"],
    "security/detect-invisible-characters": ["CWE-1007"],
    "security/detect-new-buffer": ["CWE-908"],
    "security/detect-no-csrf-before-method-override": ["CWE-352"],
    "security/detect-non-literal-fs-filename": ["CWE-22"],
    "security/detect-non-literal-regexp": ["CWE-1333"],
    "security/detect-non-literal-require": ["CWE-829"],
    "security/detect-object-injection": ["CWE-915"],
    "security/detect-possible-timing-attacks": ["CWE-208"],
    "security/detect-pseudoRandomBytes": ["CWE-338"],
    "security/detect-unsafe-regex": ["CWE-1333"],
}


class EslintAdapter(BaseSarifAdapter):
    """The formatter writes no CWE, confidence or fingerprint, so only the CWEs come from our
    own mapping. A result of a rule outside the mapping keeps an empty CWE list."""

    tool = "eslint"

    def cwes(self, rule: dict, result: dict) -> list[str]:
        rule_id = result.get("ruleId") or rule.get("id")
        mapped = RULE_CWES.get(rule_id, []) if isinstance(rule_id, str) else []
        numbers = {int(cwe[4:]) for cwe in [*super().cwes(rule, result), *mapped]}
        return [f"CWE-{number}" for number in sorted(numbers)]
