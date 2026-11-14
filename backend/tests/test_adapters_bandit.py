"""The Bandit adapter on real Bandit output from PyGoat (tests/adapter_fixture/README.md).

The expected values were worked out by hand from bandit-pygoat.sarif and the two PyGoat files:
rule, CWE tag, lines, columns, level and issue_confidence read from the SARIF file, and the
fingerprints and context hashes computed with the formulas printed in docs/finding-format.md
on the flagged lines read from the files, not with the adapter.
"""

import json
from pathlib import Path

import pytest

from app.adapters import AdapterRegistry, BanditAdapter
from app.checkout import CheckoutReader
from app.runner import SarifValidator
from app.runner.runner import PluginRun

FIXTURE = Path(__file__).parent / "adapter_fixture"
SARIF = FIXTURE / "bandit-pygoat.sarif"
DEPENDENCY = "dockerized_labs/dependency_attack_lab/app.py"
SQL = "dockerized_labs/sql_injection_lab/app.py"
RUN = PluginRun(
    "run-0022", "scan-0007", "bandit", "sieve-plugin-bandit:1.9.4", "1.9.4", "bandit 1.9.4"
)


@pytest.fixture(scope="module")
def result():
    sarif = SarifValidator().validate(SARIF)
    return BanditAdapter().to_findings(sarif, RUN, CheckoutReader(FIXTURE / "pygoat"))


def test_every_result_becomes_a_finding(result):
    assert len(result.findings) == 9
    assert result.dropped == {} and result.warnings == []
    assert len({f.fingerprint for f in result.findings}) == 9


def test_every_finding_against_values_worked_out_by_hand(result):
    mapped = [
        (
            f.location.file,
            f.rule_id,
            f.location.start_line,
            f.location.end_line,
            f.location.start_column,
            f.location.end_column,
            f.cwe,
            f.tool_severity,
            f.tool_confidence,
        )
        for f in result.findings
    ]
    assert mapped == [
        (DEPENDENCY, "B105", 7, 7, 12, 24, ["CWE-259"], "note", "medium"),
        (DEPENDENCY, "B105", 10, 11, 5, 18, ["CWE-259"], "note", "medium"),
        (DEPENDENCY, "B105", 10, 11, 5, 17, ["CWE-259"], "note", "medium"),
        (DEPENDENCY, "B201", 198, 198, 5, 51, ["CWE-94"], "error", "medium"),
        (DEPENDENCY, "B104", 198, 198, 18, 27, ["CWE-605"], "warning", "medium"),
        (SQL, "B105", 7, 7, 12, 24, ["CWE-259"], "note", "medium"),
        (SQL, "B608", 51, 51, 15, 51, ["CWE-89"], "warning", "low"),
        (SQL, "B201", 78, 78, 5, 51, ["CWE-94"], "error", "medium"),
        (SQL, "B104", 78, 78, 18, 27, ["CWE-605"], "warning", "medium"),
    ]
    # The two passwords on lines 10 to 11 share the rule, file and flagged lines, so they
    # differ only by occurrence: 0 for end column 17, 1 for end column 18.
    hashed = [(f.fingerprint, f.fingerprint_ambiguous, f.context_hash) for f in result.findings]
    assert hashed == [
        ("v1:04aae30795c108cb0d2bb16e285ac8b3", False, "c1:faff7a316f5fc201462d4158447461f7"),
        ("v1:8115b134c8aab362bbf29e467c4010b2", True, "c1:eaa74c15ef08d8ce3d51a2579a85f1fe"),
        ("v1:05234c55e87b42b297f11493949f9a33", True, "c1:eaa74c15ef08d8ce3d51a2579a85f1fe"),
        ("v1:caf0a3560d4bcd680cc57c8993dea22c", False, "c1:12242be1c741299bc997a83a8bbfb495"),
        ("v1:797082852b1fa08ad44715bc08ac3020", False, "c1:12242be1c741299bc997a83a8bbfb495"),
        ("v1:2025c07dc5c11b23a2717bfb3ba165ce", False, "c1:78544297998f178d7d0c6354062a577e"),
        ("v1:72bfefef5553de2b4fc4bf64f0705a46", False, "c1:20f73abff2b3d987049ad74d37789210"),
        ("v1:3d69b5d6c08757f7578eddabecc4bf08", False, "c1:3b1d0504c6ab699a201f353ae2f08c13"),
        ("v1:0a9f1cecd2beec44c51c6253ed3e2c2e", False, "c1:3b1d0504c6ab699a201f353ae2f08c13"),
    ]


def test_the_sql_injection_finding(result):
    """Every field of the B608 finding on the f-string query in the SQL injection lab."""
    raw = json.loads(SARIF.read_text(encoding="utf-8"))
    (finding,) = [f for f in result.findings if f.rule_id == "B608"]
    assert finding.scan_id == "scan-0007" and finding.run_id == "run-0022"
    assert finding.finding_id is None
    assert (finding.tool, finding.tool_version) == ("bandit", "1.9.4")
    # Bandit's rules have a name and a help link, but no description.
    assert finding.rule_description is None
    assert finding.rule_help_uri == (
        "https://bandit.readthedocs.io/en/1.9.4/plugins/b608_hardcoded_sql_expressions.html"
    )
    assert finding.message == (
        "Possible SQL injection vector through string-based query construction."
    )
    # No level in the result, so the SARIF default. Bandit leaves it out for MEDIUM severity.
    assert finding.tool_severity == "warning"
    assert finding.tool_score is None
    assert finding.tool_confidence == "low"
    location = finding.location
    assert (location.file, location.start_line, location.end_line) == (SQL, 51, 51)
    # Read from the checkout, so without the line break that Bandit's snippet ends with.
    assert location.snippet == (
        "            f\"SELECT * FROM users WHERE username='{username}' AND password='{password}'\""
    )
    assert finding.related_locations == [] and finding.data_flow == []
    assert finding.suppressed is False
    assert finding.tool_fingerprint is None
    assert finding.language == "python"
    (raw_result,) = [r for r in raw["runs"][0]["results"] if r["ruleId"] == "B608"]
    assert finding.raw == raw_result


def test_snippets_come_from_the_checkout_not_from_bandit(result):
    """For the dictionary on lines 10 to 14, Bandit 1.9.4 reports lines 10 to 11 for both
    passwords and writes line 17 as the snippet. The finding keeps the lines Bandit reports and
    the code on those lines, and the two findings are marked ambiguous."""
    dictionary = [
        f for f in result.findings if f.location.file == DEPENDENCY and f.location.start_line == 10
    ]
    assert [f.message for f in dictionary] == [
        "Possible hardcoded password: 'SuperSecret123!'",
        "Possible hardcoded password: 'token_abc123'",
    ]
    for finding in dictionary:
        raw_region = finding.raw["locations"][0]["physicalLocation"]["region"]
        assert raw_region["snippet"]["text"] == "class MaliciousDependency:\n"
        expected = 'SENSITIVE_DATA = {\n    "api_key": "sk_live_123456",'  # gitleaks:allow
        assert finding.location.snippet == expected
        assert finding.fingerprint_ambiguous is True


def test_confidence_comes_from_the_result_not_the_rule():
    adapter = BanditAdapter()
    rule = {"properties": {"precision": "high"}}
    assert adapter.confidence(rule, {"properties": {"issue_confidence": "LOW"}}) == "low"
    assert adapter.confidence(rule, {"properties": {"issue_confidence": "medium"}}) == "medium"
    assert adapter.confidence(rule, {"properties": {"issue_confidence": "UNDEFINED"}}) is None
    assert adapter.confidence(rule, {"properties": {"issue_confidence": 3}}) is None
    assert adapter.confidence(rule, {}) is None


def test_a_rule_without_a_cwe():
    """Bandit writes the tag external/cwe/cwe-None for an issue without a CWE."""
    rule = {"properties": {"tags": ["security", "external/cwe/cwe-None"]}}
    assert BanditAdapter().cwes(rule, {}) == []


def test_registry():
    assert isinstance(AdapterRegistry().get("bandit"), BanditAdapter)
