"""The Gitleaks adapter on real Gitleaks output (tests/adapter_fixture/README.md)."""

import copy
import dataclasses
import json
import re
from pathlib import Path

import pytest

from app.adapters import AdapterRegistry, GitleaksAdapter, context_hash
from app.checkout import CheckoutReader
from app.runner import SarifValidator
from app.runner.runner import PluginRun

FIXTURE = Path(__file__).parent / "adapter_fixture"
AUTH = "dockerized_labs/auth_failure_lab/app.py"
DEPENDENCY = "dockerized_labs/dependency_attack_lab/app.py"
RULE = "generic-api-key"
RUN = PluginRun(
    "run-0031",
    "scan-0009",
    "gitleaks",
    "sieve-plugin-gitleaks:8.30.1",
    "8.30.1",
    "gitleaks 8.30.1 built-in rules",
)


def convert(sarif: dict, root: Path):
    return GitleaksAdapter().to_findings(sarif, RUN, CheckoutReader(root))


@pytest.fixture(scope="module")
def result():
    sarif = SarifValidator().validate(FIXTURE / "gitleaks-pygoat.sarif")
    return convert(sarif, FIXTURE / "pygoat")


def test_every_result_becomes_a_finding(result):
    assert len(result.findings) == 5
    assert result.dropped == {} and result.warnings == []


def test_the_pygoat_findings_worked_out_by_hand(result):
    """Rule, file and lines read from gitleaks-pygoat.sarif. Gitleaks gives no CWE and no level,
    so every finding gets CWE-798 and the SARIF default level, warning. The fingerprints were
    computed with the code in docs/finding-format.md from the flagged line masked as REDACTED,
    with the occurrence counted by line among the findings of the same rule and file."""
    rows = sorted(
        (
            f.rule_id,
            f.cwe,
            f.location.file,
            f.location.start_line,
            f.location.end_line,
            f.tool_severity,
            f.fingerprint,
            f.fingerprint_ambiguous,
        )
        for f in result.findings
    )
    cwe = ["CWE-798"]
    assert rows == [
        (RULE, cwe, AUTH, 53, 53, "warning", "v1:5ac0e5465ea967fe7cb496afe6c1e725", True),
        (RULE, cwe, AUTH, 59, 59, "warning", "v1:1d4dd8871183a4323a6ef9b834e79c29", True),
        (RULE, cwe, AUTH, 65, 65, "warning", "v1:872e0713b6aa7b1cc26ab521150bdffe", True),
        (RULE, cwe, AUTH, 71, 71, "warning", "v1:717025399633db90c743e18c1d8f707d", True),
        (RULE, cwe, DEPENDENCY, 11, 11, "warning", "v1:ecd5b8ffe6ad04d0f377ebd8a8c4f5d9", False),
    ]


def test_the_other_fields(result):
    finding = next(f for f in result.findings if f.location.file == DEPENDENCY)
    assert (finding.scan_id, finding.run_id) == ("scan-0009", "run-0031")
    assert (finding.tool, finding.tool_version) == ("gitleaks", "8.30.1")
    assert finding.rule_description == (
        "Detected a Generic API Key, potentially exposing access to various services and "
        "sensitive operations."
    )
    assert finding.rule_help_uri is None
    assert finding.message == f"generic-api-key has detected secret for file /src/{DEPENDENCY}."
    assert (finding.location.start_column, finding.location.end_column) == (7, 32)
    assert finding.tool_score is None and finding.tool_confidence is None
    assert finding.tool_fingerprint is None
    assert finding.suppressed is False
    assert finding.language == "python"
    assert finding.related_locations == [] and finding.data_flow == []


def test_snippet_and_context_hash_come_from_the_masked_lines(result):
    """The context hashes were computed with the code in docs/finding-format.md over the
    file with every flagged line replaced by REDACTED, so the window around line 53 also
    has line 59 masked."""
    hashes = {(f.location.file, f.location.start_line): f.context_hash for f in result.findings}
    assert hashes == {
        (AUTH, 53): "c1:aea7afe42c9505771adc7fe9ae2225dc",
        (AUTH, 59): "c1:32fa7839466c65e20da2652ea52c64c9",
        (AUTH, 65): "c1:359483f03db63ab2e3cccbd2e6ae0919",
        (AUTH, 71): "c1:b99956590819accc5b79ba797785921e",
        (DEPENDENCY, 11): "c1:a99fa39ab06a11c4ef032f33506f0472",
    }
    unmasked = CheckoutReader(FIXTURE / "pygoat").read_lines(DEPENDENCY)
    assert context_hash(unmasked, 11, 11) != hashes[(DEPENDENCY, 11)]
    for finding in result.findings:
        assert finding.location.snippet == "REDACTED"
        region = finding.raw["locations"][0]["physicalLocation"]["region"]
        assert "snippet" not in region


def fake_key() -> str:
    text = (FIXTURE / "fake-key" / "settings.py").read_text(encoding="utf-8")
    (key,) = re.findall(r'^api_key = "(\w+)"$', text, re.MULTILINE)
    return key


def stored_text(out) -> str:
    """Everything the adapter returns, every field of every finding and raw included."""
    findings = [dataclasses.asdict(f) for f in out.findings]
    return json.dumps([findings, out.dropped, out.warnings], ensure_ascii=False) + repr(out)


@pytest.mark.parametrize("redacted", [True, False])
def test_the_fake_key_is_in_no_field_of_the_finding(redacted):
    """Requirement N4, test 5. gitleaks-fake-key.sarif is the plug-in's real output on
    fake-key/, made with --redact. Without --redact, Gitleaks writes the secret as the
    snippet, so the second case puts the key there and the result must be the same."""
    key = fake_key()
    sarif = SarifValidator().validate(FIXTURE / "gitleaks-fake-key.sarif")
    region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["snippet"]["text"] == "REDACTED"
    if not redacted:
        region["snippet"]["text"] = key

    out = convert(sarif, FIXTURE / "fake-key")

    (finding,) = out.findings
    assert (finding.rule_id, finding.cwe) == (RULE, ["CWE-798"])
    assert (finding.location.file, finding.location.start_line) == ("settings.py", 6)
    assert finding.location.snippet == "REDACTED"
    assert finding.fingerprint == "v1:a4fe4bb8c3d2058ce1ce7046b8958c2e"
    assert finding.context_hash == "c1:fa61fa4923bd439a247d45f6a0e21ab4"
    text = stored_text(out)
    pieces = {key[i : i + 8] for i in range(len(key) - 7)}
    assert not [piece for piece in pieces if piece in text]


def gitleaks_result(uri: str, start: int, end: int, snippet: str) -> dict:
    return {
        "ruleId": "private-key",
        "message": {"text": f"private-key has detected secret for file {uri}."},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": start, "endLine": end, "snippet": {"text": snippet}},
                }
            }
        ],
    }


def sarif_of(*results: dict) -> dict:
    driver = {"name": "gitleaks", "rules": [{"id": "private-key"}]}
    return {"version": "2.1.0", "runs": [{"tool": {"driver": driver}, "results": list(results)}]}


# Masking goes by line number only, so plain words stand in for a secret over several lines.
KEY_LINES = ["text = (", '    "first part"', '    "middle part"', '    "last part"', ")"]


def test_every_line_of_a_secret_over_several_lines_is_masked(tmp_path):
    (tmp_path / "key.py").write_text("\n".join(KEY_LINES) + "\n", encoding="utf-8")
    sarif = sarif_of(gitleaks_result("/src/key.py", 2, 4, "\n".join(KEY_LINES[1:4])))
    out = convert(sarif, tmp_path)
    (finding,) = out.findings
    assert finding.location.snippet == "REDACTED\nREDACTED\nREDACTED"
    assert "part" not in stored_text(out)
    masked = ["text = (", "REDACTED", "REDACTED", "REDACTED", ")"]
    assert finding.context_hash == context_hash(masked, 2, 4)


def test_an_end_line_past_the_end_of_the_file_masks_up_to_the_end(tmp_path):
    (tmp_path / "key.py").write_text("\n".join(KEY_LINES) + "\n", encoding="utf-8")
    sarif = sarif_of(gitleaks_result("/src/key.py", 3, 99, KEY_LINES[2]))
    out = convert(sarif, tmp_path)
    (finding,) = out.findings
    assert (finding.location.start_line, finding.location.end_line) == (3, 5)
    assert finding.location.snippet == "REDACTED\nREDACTED\nREDACTED"
    assert "part" not in stored_text(out)


def test_the_cwe_is_798_whatever_the_rule_says():
    rule = {"id": "jwt", "properties": {"tags": ["CWE-89"]}}
    assert GitleaksAdapter().cwes(rule, {"taxa": []}) == ["CWE-798"]


def test_registry():
    assert isinstance(AdapterRegistry().get("gitleaks"), GitleaksAdapter)


def test_raw_is_the_sarif_result_without_its_snippet(result):
    sarif = json.loads((FIXTURE / "gitleaks-pygoat.sarif").read_text(encoding="utf-8"))
    expected = copy.deepcopy(sarif["runs"][0]["results"])
    for item in expected:
        del item["locations"][0]["physicalLocation"]["region"]["snippet"]
    assert sorted(json.dumps(f.raw, sort_keys=True) for f in result.findings) == sorted(
        json.dumps(item, sort_keys=True) for item in expected
    )
