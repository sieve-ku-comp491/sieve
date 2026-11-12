"""The SARIF check that every successful run passes before an adapter reads its file."""

import json

import pytest

from app.runner import InvalidSarif, SarifValidator
from app.runner.sarif import result_count, tool_versions

MINIMAL = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t"}}, "results": []}]}

SEMGREP_LIKE = {
    "version": "2.1.0",
    "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "Semgrep OSS",
                    "semanticVersion": "1.183.0",
                    "rules": [
                        {
                            "id": "python.lang.security.audit.formatted-sql-query",
                            "defaultConfiguration": {"level": "warning"},
                            "properties": {"tags": ["CWE-89: SQL Injection", "LOW CONFIDENCE"]},
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "python.lang.security.audit.formatted-sql-query",
                    "message": {"text": "Detected possible formatted SQL query."},
                    "fingerprints": {"matchBasedId/v1": "requires login"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "/src/app.py"},
                                "region": {"startLine": 57, "startColumn": 22, "endLine": 57},
                            }
                        }
                    ],
                }
            ],
        }
    ],
}


def write(tmp_path, data) -> object:
    path = tmp_path / "results.sarif"
    path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
    return path


def test_valid_files_pass(tmp_path):
    assert SarifValidator().validate(write(tmp_path, MINIMAL)) == MINIMAL
    assert SarifValidator().validate(write(tmp_path, SEMGREP_LIKE)) == SEMGREP_LIKE


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        ("{not json", "invalid_sarif"),
        ([], "invalid_sarif"),
        ({"version": "2.0.0", "runs": []}, "invalid_sarif"),
        ({"runs": []}, "invalid_sarif"),
        ({"version": "2.1.0"}, "invalid_sarif"),
        ({"version": "2.1.0", "runs": [{"results": []}]}, "invalid_sarif"),
        ({"version": "2.1.0", "runs": [{"tool": {"driver": {}}}]}, "invalid_sarif"),
        (
            {
                "version": "2.1.0",
                "runs": [{"tool": {"driver": {"name": "t"}}, "results": [{"ruleId": "r"}]}],
            },
            "invalid_sarif",
        ),
    ],
    ids=[
        "not json",
        "a list",
        "old version",
        "no version",
        "no runs",
        "no tool",
        "no driver name",
        "result without message",
    ],
)
def test_invalid_files_fail(tmp_path, data, reason):
    with pytest.raises(InvalidSarif) as error:
        SarifValidator().validate(write(tmp_path, data))
    assert error.value.reason == reason


def test_not_utf8(tmp_path):
    path = tmp_path / "results.sarif"
    path.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(InvalidSarif) as error:
        SarifValidator().validate(path)
    assert error.value.reason == "invalid_sarif"


@pytest.mark.parametrize("runs", [[], [MINIMAL["runs"][0], MINIMAL["runs"][0]], None])
def test_exactly_one_run(tmp_path, runs):
    with pytest.raises(InvalidSarif) as error:
        SarifValidator().validate(write(tmp_path, {"version": "2.1.0", "runs": runs}))
    assert error.value.reason == "invalid_sarif"


def test_missing_file(tmp_path):
    with pytest.raises(InvalidSarif) as error:
        SarifValidator().validate(tmp_path / "results.sarif")
    assert error.value.reason == "missing_sarif"


def test_size_limit(tmp_path):
    path = write(tmp_path, MINIMAL)
    with pytest.raises(InvalidSarif) as error:
        SarifValidator(max_bytes=10).validate(path)
    assert error.value.reason == "invalid_sarif"


def test_schema_error_says_where(tmp_path):
    bad = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": 5}}}]}
    with pytest.raises(InvalidSarif, match="runs/0/tool/driver/name"):
        SarifValidator().validate(write(tmp_path, bad))


def test_counts_and_versions():
    assert result_count(SEMGREP_LIKE) == 1
    assert result_count(MINIMAL) == 0
    assert tool_versions(SEMGREP_LIKE) == ["Semgrep OSS 1.183.0"]
    assert tool_versions(MINIMAL) == ["t no version"]
