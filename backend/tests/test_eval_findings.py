"""Analyzer SARIF files as the findings CSV of the baseline run."""

import json

import pytest

from app.eval.findings import SarifError, ToolFinding, read_sarif, write_findings
from app.eval.metrics import read_findings


def result(rule_id, uri, level=None, base_id=None):
    artifact = {"uri": uri}
    if base_id:
        artifact["uriBaseId"] = base_id
    found = {"ruleId": rule_id, "locations": [{"physicalLocation": {"artifactLocation": artifact}}]}
    if level:
        found["level"] = level
    return found


def write_sarif(path, results, rules):
    run = {"tool": {"driver": {"name": "t", "rules": rules}}, "results": results}
    path.write_text(json.dumps({"version": "2.1.0", "runs": [run]}))


SEMGREP_RULE = {
    "id": "python.sql",
    "properties": {"tags": ["CWE-89: SQL Injection", "LOW CONFIDENCE", "security"]},
    "defaultConfiguration": {"level": "warning"},
}
BANDIT_RULE = {"id": "B602", "properties": {"tags": ["security", "external/cwe/cwe-78"]}}


def test_semgrep_and_bandit_cwe_tags_and_mounts(tmp_path):
    semgrep = tmp_path / "semgrep.sarif"
    write_sarif(
        semgrep,
        [result("python.sql", "/src/testcode/Case1.py", base_id="%SRCROOT%")],
        [SEMGREP_RULE],
    )
    bandit = tmp_path / "bandit.sarif"
    write_sarif(bandit, [result("B602", "testcode/Case2.py", level="error")], [BANDIT_RULE])

    (first,) = read_sarif("semgrep", semgrep).findings
    assert first == ToolFinding("semgrep-0", "semgrep", "testcode/Case1.py", ("CWE-89",), "warning")
    (second,) = read_sarif("bandit", bandit).findings
    assert second == ToolFinding("bandit-0", "bandit", "testcode/Case2.py", ("CWE-78",), "error")


def test_results_that_cant_be_placed_are_counted(tmp_path):
    path = tmp_path / "x.sarif"
    no_location = {"ruleId": "B602", "locations": []}
    outside = result("B602", "../../etc/passwd")
    write_sarif(path, [no_location, outside, result("B602", "a.py")], [BANDIT_RULE])
    read = read_sarif("bandit", path)
    assert len(read.findings) == 1
    assert (read.without_location, read.outside_checkout) == (1, 1)


def test_strip_prefix_and_a_path_without_it(tmp_path):
    path = tmp_path / "x.sarif"
    write_sarif(path, [result("B602", "src/testcode/Case1.py")], [BANDIT_RULE])
    assert read_sarif("bandit", path, "src/").findings[0].file == "testcode/Case1.py"
    with pytest.raises(SarifError, match="doesn't start with"):
        read_sarif("bandit", path, "other/")


def test_a_file_that_isnt_sarif(tmp_path):
    path = tmp_path / "x.sarif"
    path.write_text("not json")
    with pytest.raises(SarifError):
        read_sarif("bandit", path)


def test_the_csv_is_what_the_false_positive_check_reads(tmp_path):
    findings = [
        ToolFinding("semgrep-0", "semgrep", "a.py", ("CWE-22", "CWE-23"), "error"),
        ToolFinding("bandit-0", "bandit", "b.py", (), "note"),
    ]
    path = tmp_path / "out/findings.csv"
    write_findings(findings, path)
    assert path.read_text().splitlines() == [
        "finding_id,file,cwe,verdict,tool,severity",
        "semgrep-0,a.py,CWE-22;CWE-23,,semgrep,error",
        "bandit-0,b.py,,,bandit,note",
    ]
    first, second = read_findings(path)
    assert first.cwes == {"CWE-22", "CWE-23"} and first.verdict == ""
    assert second.cwes == frozenset()
