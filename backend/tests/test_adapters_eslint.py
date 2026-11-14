"""The ESLint adapter on real ESLint output from Juice Shop (tests/adapter_fixture/README.md)."""

import json
import re
from pathlib import Path

import pytest

from app.adapters import AdapterRegistry, EslintAdapter
from app.adapters.eslint import RULE_CWES
from app.checkout import CheckoutReader
from app.runner import SarifValidator
from app.runner.runner import PluginRun

FIXTURE = Path(__file__).parent / "adapter_fixture"
SARIF = FIXTURE / "eslint-juice-shop.sarif"
DOCS = Path(__file__).resolve().parents[2] / "docs"
RUN = PluginRun(
    "run-0031",
    "scan-0009",
    "eslint",
    "sieve-plugin-eslint:10.14.0-security4.2.1",
    "10.14.0",
    "eslint-plugin-security 4.2.1",
)

STATS = "frontend/filter-bundle-stats-for-diagram.mts"
COMPOSER = "frontend/src/assets/private/EffectComposer.js"
OBJECT = "security/detect-object-injection"

# Every result in the fixture, worked out by hand from the SARIF file and the flagged lines in
# juice-shop/, with the CWE table in docs/finding-format.md and the fingerprint method there:
# rule, CWEs, file, start line, end line, start column, end column, fingerprint, ambiguous.
EXPECTED = [
    (
        "security/detect-unsafe-regex",
        ["CWE-1333"],
        STATS,
        11, 11, 24, 60,
        "v1:c9b5b1fd9afe395242b0f405ade2791a",
        False,
    ),
    (OBJECT, ["CWE-915"], STATS, 15, 15, 12, 29, "v1:f75c995a222631f6a54cff7f3e3fe24b", False),
    (OBJECT, ["CWE-915"], STATS, 23, 23, 16, 34, "v1:cb35b9fd901ffecdddf85382424ec91f", False),
    (OBJECT, ["CWE-915"], COMPOSER, 67, 67, 11, 27, "v1:63f4de2d7da5f6b866ff532a69c34c05", False),
    # Two results on the same line: the same first four values, so occurrences 0 and 1, in
    # column order, and both ambiguous.
    (
        OBJECT,
        ["CWE-915"],
        "routes/basket.ts",
        28, 28, 11, 29,
        "v1:212c60af39b70b2afa46a89de90cbd45",
        True,
    ),
    (
        OBJECT,
        ["CWE-915"],
        "routes/basket.ts",
        28, 28, 44, 62,
        "v1:4c14d6313e2ed070ac68bed112f1194d",
        True,
    ),
    (
        "security/detect-eval-with-expression",
        ["CWE-95"],
        "routes/captcha.ts",
        22, 22, 20, 36,
        "v1:d905ef8d26884ace0d526870df455282",
        False,
    ),
    (
        "security/detect-possible-timing-attacks",
        ["CWE-208"],
        "routes/changePassword.ts",
        28, 31, 5, 6,
        "v1:f9da3d0edf25d24b64c2251c5af9e10d",
        False,
    ),
    (
        "security/detect-non-literal-fs-filename",
        ["CWE-22"],
        "routes/profileImageUrlUpload.ts",
        29, 29, 30, 152,
        "v1:4a41901d0e503d8b34d488b5fc198a67",
        False,
    ),
]  # fmt: skip


@pytest.fixture(scope="module")
def result():
    sarif = SarifValidator().validate(SARIF)
    return EslintAdapter().to_findings(sarif, RUN, CheckoutReader(FIXTURE / "juice-shop"))


def test_every_result_against_the_values_worked_out_by_hand(result):
    assert result.dropped == {} and result.warnings == []
    rows = [
        (
            f.rule_id,
            f.cwe,
            f.location.file,
            f.location.start_line,
            f.location.end_line,
            f.location.start_column,
            f.location.end_column,
            f.fingerprint,
            f.fingerprint_ambiguous,
        )
        for f in result.findings
    ]
    assert rows == EXPECTED
    # The formatter sets level "warning" on every result, because the recommended set turns
    # every rule on as "warn".
    assert {f.tool_severity for f in result.findings} == {"warning"}


def test_one_finding_in_full(result):
    raw = json.loads(SARIF.read_text(encoding="utf-8"))
    (finding,) = [f for f in result.findings if f.location.file == "routes/captcha.ts"]
    assert (finding.scan_id, finding.run_id, finding.finding_id) == ("scan-0009", "run-0031", None)
    assert (finding.tool, finding.tool_version) == ("eslint", "10.14.0")
    assert finding.rule_description == (
        'Detects "eval(variable)" which can allow an attacker to run arbitrary code inside your '
        "process."
    )
    assert finding.rule_help_uri == (
        "https://github.com/eslint-community/eslint-plugin-security/blob/main/docs/rules/"
        "detect-eval-with-expression.md"
    )
    assert finding.message == "eval with argument of type Identifier"
    assert finding.tool_score is None and finding.tool_confidence is None
    # The formatter writes no snippet, so it comes from the file.
    assert finding.location.snippet == (
        "    const answer = eval(expression).toString() // eslint-disable-line no-eval"
    )
    assert finding.context_hash == "c1:a968d56d61c416a77ad97a1bc89f03d3"
    assert finding.related_locations == [] and finding.data_flow == []
    assert finding.suppressed is False and finding.tool_fingerprint is None
    assert finding.language == "typescript"
    assert finding.raw == raw["runs"][0]["results"][6]


def test_snippet_of_a_finding_over_several_lines(result):
    (finding,) = [f for f in result.findings if f.location.file == "routes/changePassword.ts"]
    assert finding.location.snippet == (
        "    if (token === null) {\n"
        "      next(new Error('Blocked illegal activity by ' + connection.remoteAddress))\n"
        "      return\n"
        "    }"
    )


def test_language_from_the_extension(result):
    languages = {f.location.file: f.language for f in result.findings}
    assert languages[STATS] == "typescript"
    assert languages[COMPOSER] == "javascript"


def test_cwe_mapping_covers_the_15_rules_of_eslint_plugin_security():
    rules = {
        "detect-bidi-characters",
        "detect-buffer-noassert",
        "detect-child-process",
        "detect-disable-mustache-escape",
        "detect-eval-with-expression",
        "detect-invisible-characters",
        "detect-new-buffer",
        "detect-no-csrf-before-method-override",
        "detect-non-literal-fs-filename",
        "detect-non-literal-regexp",
        "detect-non-literal-require",
        "detect-object-injection",
        "detect-possible-timing-attacks",
        "detect-pseudoRandomBytes",
        "detect-unsafe-regex",
    }
    assert set(RULE_CWES) == {f"security/{rule}" for rule in rules}


def test_cwe_mapping_matches_docs_finding_format():
    text = (DOCS / "finding-format.md").read_text(encoding="utf-8")
    table = text.split("| Rule | CWE |", 1)[1].split("\n\n", 1)[0]
    documented = {}
    for row in table.splitlines()[2:]:
        rules, cwes = row.strip("|").split("|")
        for rule in re.findall(r"`([\w-]+)`", rules):
            documented[f"security/{rule}"] = re.findall(r"CWE-\d+", cwes)
    assert documented == RULE_CWES


def test_rule_outside_the_mapping_has_no_cwe():
    adapter = EslintAdapter()
    assert adapter.cwes({"id": "no-eval"}, {"ruleId": "no-eval"}) == []
    assert adapter.cwes({}, {"ruleId": "security/detect-buffer-noassert"}) == [
        "CWE-125",
        "CWE-787",
    ]


def test_cwes_the_tool_gives_are_kept():
    rule = {"id": "security/detect-child-process", "properties": {"tags": ["CWE-77"]}}
    assert EslintAdapter().cwes(rule, {"ruleId": rule["id"]}) == ["CWE-77", "CWE-78"]


def test_registry():
    assert isinstance(AdapterRegistry().get("eslint"), EslintAdapter)
