"""The Semgrep adapter on real Semgrep output from PyGoat (tests/adapter_fixture/README.md)."""

import json
from pathlib import Path

import pytest

from app.adapters import AdapterError, AdapterRegistry, SemgrepAdapter
from app.checkout import CheckoutReader
from app.runner import SarifValidator
from app.runner.runner import PluginRun

FIXTURE = Path(__file__).parent / "adapter_fixture"
LAB = "dockerized_labs/sql_injection_lab/app.py"
RUN = PluginRun(
    "run-0021",
    "scan-0007",
    "semgrep",
    "sieve-plugin-semgrep:1.183.0-16b9e6d",
    "1.183.0",
    "semgrep-rules@16b9e6d",
)


@pytest.fixture(scope="module")
def result():
    sarif = SarifValidator().validate(FIXTURE / "semgrep-pygoat.sarif")
    return SemgrepAdapter().to_findings(sarif, RUN, CheckoutReader(FIXTURE / "pygoat"))


def find(result, rule_id, line):
    (finding,) = [
        f for f in result.findings if f.rule_id == rule_id and f.location.start_line == line
    ]
    return finding


def test_every_result_becomes_a_finding(result):
    assert len(result.findings) == 9
    assert result.dropped == {} and result.warnings == []
    assert len({f.fingerprint for f in result.findings}) == 9


def test_the_example_in_docs_finding_format(result):
    """Every value of the example in docs/finding-format.md, "In our format", except the IDs."""
    raw = json.loads((FIXTURE / "semgrep-pygoat.sarif").read_text(encoding="utf-8"))
    finding = find(result, "python.lang.security.audit.formatted-sql-query", 57)
    assert finding.scan_id == "scan-0007" and finding.run_id == "run-0021"
    assert finding.finding_id is None
    assert finding.tool == "semgrep"
    assert finding.tool_version == "1.183.0"
    assert finding.rule_description == (
        "Detected possible formatted SQL query. Use parameterized queries instead."
    )
    assert finding.rule_help_uri is None
    assert finding.cwe == ["CWE-89"]
    assert finding.message == (
        "Detected possible formatted SQL query. Use parameterized queries instead."
    )
    assert finding.tool_severity == "warning"
    assert finding.tool_score is None
    assert finding.tool_confidence == "low"
    location = finding.location
    assert (location.file, location.start_line, location.end_line) == (LAB, 57, 57)
    assert (location.start_column, location.end_column) == (22, 42)
    assert location.snippet == "            result = c.execute(sql_query).fetchone()"
    assert finding.related_locations == [] and finding.data_flow == []
    assert finding.fingerprint == "v1:418dc3c913dc63ec1ee12209f03b55f1"
    assert finding.fingerprint_ambiguous is False
    assert finding.context_hash == "c1:a5b7da088c06eb2371e6939f52ee1e61"
    assert finding.suppressed is False
    assert finding.tool_fingerprint is None
    assert finding.language == "python"
    (raw_result,) = [
        r
        for r in raw["runs"][0]["results"]
        if r["ruleId"] == finding.rule_id
        and r["locations"][0]["physicalLocation"]["region"]["startLine"] == 57
    ]
    assert finding.raw == raw_result


def test_the_same_bug_six_times(result):
    """The table in docs/finding-format.md: one SQL injection, six results from five rules,
    with the CWEs Semgrep gives, even where they look wrong."""
    rows = sorted(
        (f.rule_id, f.location.start_line, f.location.end_line, f.cwe)
        for f in result.findings
        if f.location.start_line in range(46, 58) and "sql" in f.rule_id
    )
    cursor = "python.django.security.injection.sql.sql-injection-db-cursor-execute"
    assert rows == [
        (cursor, 46, 69, ["CWE-89"]),
        (cursor, 47, 69, ["CWE-89"]),
        ("python.django.security.injection.tainted-sql-string", 50, 52, ["CWE-915"]),
        ("python.flask.security.injection.tainted-sql-string", 50, 52, ["CWE-704"]),
        ("python.lang.security.audit.formatted-sql-query", 57, 57, ["CWE-89"]),
        ("python.sqlalchemy.security.sqlalchemy-execute-raw-query", 57, 57, ["CWE-89"]),
    ]


def test_confidence_comes_from_the_rule_tags(result):
    rules = json.loads((FIXTURE / "semgrep-pygoat.sarif").read_text(encoding="utf-8"))
    tags = {
        rule["id"]: rule["properties"]["tags"]
        for rule in rules["runs"][0]["tool"]["driver"]["rules"]
    }
    for finding in result.findings:
        expected = {
            "HIGH CONFIDENCE": "high",
            "MEDIUM CONFIDENCE": "medium",
            "LOW CONFIDENCE": "low",
        }
        (confidence,) = [expected[t] for t in tags[finding.rule_id] if t in expected]
        assert finding.tool_confidence == confidence
        # Semgrep's precision property is the same on every rule and is not used.
        assert finding.tool_score is None


def test_fingerprint_stays_when_code_is_added_above(tmp_path):
    """docs/finding-format.md: three lines added at the top move the finding from line 57 to
    line 60, and its fingerprint and context hash stay the same."""
    lines = (FIXTURE / "pygoat" / LAB).read_text(encoding="utf-8")
    shifted = tmp_path / LAB
    shifted.parent.mkdir(parents=True)
    shifted.write_text("# a\n# b\n# c\n" + lines, encoding="utf-8")
    sarif = json.loads((FIXTURE / "semgrep-pygoat.sarif").read_text(encoding="utf-8"))
    for item in sarif["runs"][0]["results"]:
        region = item["locations"][0]["physicalLocation"]["region"]
        region["startLine"] += 3
        region["endLine"] += 3
    moved = SemgrepAdapter().to_findings(sarif, RUN, CheckoutReader(tmp_path))
    finding = find(moved, "python.lang.security.audit.formatted-sql-query", 60)
    assert finding.fingerprint == "v1:418dc3c913dc63ec1ee12209f03b55f1"
    assert finding.context_hash == "c1:a5b7da088c06eb2371e6939f52ee1e61"


def test_registry():
    registry = AdapterRegistry()
    assert isinstance(registry.get("semgrep"), SemgrepAdapter)
    with pytest.raises(AdapterError):
        registry.get("bandit")


def test_the_repo_manifest_names_this_adapter():
    from app.runner import PluginRegistry

    plugins = PluginRegistry.load(Path(__file__).resolve().parents[2] / "plugins")
    registry = AdapterRegistry()
    for manifest in plugins.all():
        assert registry.get(manifest.adapter).tool == manifest.name
