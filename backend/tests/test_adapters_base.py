"""The SARIF mapping shared by all adapters (docs/finding-format.md), on small SARIF files."""

import pytest

from app.adapters import BaseSarifAdapter, Location
from app.checkout import CheckoutReader
from app.runner.runner import PluginRun

RUN = PluginRun("run-1", "scan-1", "tool", "image:1", "2.0.0", "rules@1")


class Adapter(BaseSarifAdapter):
    tool = "tool"


@pytest.fixture
def checkout(tmp_path):
    root = tmp_path / "checkout"
    (root / "app").mkdir(parents=True)
    (root / "app/views.py").write_text("a = 1\nquery(x)\nquery(x)\nb = 2\n", encoding="utf-8")
    (root / "templates").mkdir()
    (root / "templates/page.html").write_text("<p>{{ x|safe }}</p>\n", encoding="utf-8")
    (root / "docs dir").mkdir()
    (root / "docs dir/conf.yml").write_text("key: value\n", encoding="utf-8")
    return root


def result(uri="/src/app/views.py", line=2, **extra):
    item = {
        "ruleId": "r1",
        "message": {"text": "found it"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }
        ],
    }
    item.update(extra)
    return item


def sarif(*results, rules=None, **run_extra):
    run = {"tool": {"driver": {"name": "T", "rules": rules or [{"id": "r1"}]}}}
    run.update(run_extra)
    run["results"] = list(results)
    return {"version": "2.1.0", "runs": [run]}


def convert(checkout, document):
    return Adapter().to_findings(document, RUN, CheckoutReader(checkout))


def test_defaults(checkout):
    (finding,) = convert(checkout, sarif(result())).findings
    assert finding.tool == "tool" and finding.tool_version == "2.0.0"
    assert finding.scan_id == "scan-1" and finding.run_id == "run-1"
    assert finding.tool_severity == "warning"
    assert finding.cwe == [] and finding.tool_confidence is None and finding.tool_score is None
    assert finding.location == Location("app/views.py", 2, 2, None, None, None)
    assert finding.language == "python"
    assert finding.fingerprint.startswith("v1:") and finding.context_hash.startswith("c1:")


@pytest.mark.parametrize(
    ("uri", "base", "expected"),
    [
        ("/src/app/views.py", None, "app/views.py"),
        ("file:///src/app/views.py", None, "app/views.py"),
        ("file:/src/app/views.py", None, "app/views.py"),
        ("app/views.py", None, "app/views.py"),
        ("/src/docs%20dir/conf.yml", None, "docs dir/conf.yml"),
        ("views.py", "APP", "app/views.py"),
        ("app/views.py", "%SRCROOT%", "app/views.py"),
    ],
)
def test_paths(checkout, uri, base, expected):
    item = result(uri)
    if base:
        item["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"] = base
    bases = {"APP": {"uri": "app/", "uriBaseId": "ROOT"}, "ROOT": {"uri": "file:///src/"}}
    (finding,) = convert(checkout, sarif(item, originalUriBaseIds=bases)).findings
    assert finding.location.file == expected


@pytest.mark.parametrize(
    "uri",
    [
        "/etc/passwd",
        "file:///etc/passwd",
        "/src/../etc/passwd",
        "app/../../outside.py",
        "/src/app/missing.py",
        "/src/app",
        "https://example.com/app/views.py",
    ],
)
def test_paths_outside_the_checkout_are_dropped(checkout, uri):
    out = convert(checkout, sarif(result(uri)))
    assert out.findings == []
    assert out.dropped == {"path_outside_checkout": 1}
    assert len(out.warnings) == 1 and "r1" in out.warnings[0]


def test_a_link_out_of_the_checkout_is_dropped(checkout, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("API_KEY=x\n", encoding="utf-8")
    try:
        (checkout / "app/link.py").symlink_to(secret)
    except OSError:
        pytest.skip("this machine can't create symbolic links")
    out = convert(checkout, sarif(result("/src/app/link.py", line=1)))
    assert out.findings == [] and out.dropped == {"path_outside_checkout": 1}


def test_results_without_a_line_or_file_are_dropped(checkout):
    no_line = result()
    del no_line["locations"][0]["physicalLocation"]["region"]
    no_file = result()
    no_file["locations"] = []
    out = convert(checkout, sarif(no_line, no_file))
    assert out.findings == []
    assert out.dropped == {"no_line": 1, "no_location": 1}


def test_only_failing_results_are_kept(checkout):
    out = convert(
        checkout,
        sarif(result(), result(kind="fail"), result(kind="pass"), result(kind="notApplicable")),
    )
    assert len(out.findings) == 2
    assert out.dropped == {"kind_pass": 1, "kind_notApplicable": 1}
    assert out.dropped_count == 2


def test_rule_lookup_by_index_by_id_and_in_an_extension(checkout):
    rules = [
        {"id": "a", "shortDescription": {"text": "rule a"}},
        {"id": "b", "fullDescription": {"text": "rule b"}, "helpUri": "https://b"},
    ]
    extension = {"name": "pack", "rules": [{"id": "x", "fullDescription": {"text": "rule x"}}]}
    by_index = result(ruleIndex=1)
    del by_index["ruleId"]
    by_id = result(ruleId="a")
    in_extension = result(ruleId="x", rule={"id": "x", "toolComponent": {"index": 0}})
    document = sarif(by_index, by_id, in_extension, rules=rules)
    document["runs"][0]["tool"]["extensions"] = [extension]
    findings = convert(checkout, document).findings
    assert [(f.rule_id, f.rule_description) for f in findings] == [
        ("b", "rule b"),
        ("a", "rule a"),
        ("x", "rule x"),
    ]
    assert findings[0].rule_help_uri == "https://b"


def test_cwe_from_tags_relationships_and_taxa(checkout):
    rule = {
        "id": "r1",
        "properties": {
            "tags": [
                "CWE-089: SQL Injection",
                "external/cwe/cwe-079",
                "security",
                "OWASP-A03:2021 - Injection",
            ]
        },
        "relationships": [
            {"target": {"id": "22", "toolComponent": {"name": "CWE"}}},
            {"target": {"id": "A03", "toolComponent": {"name": "OWASP"}}},
        ],
    }
    item = result(
        taxa=[
            {"id": "CWE-89", "toolComponent": {"name": "cwe"}},
            {"id": "78", "toolComponent": {"name": "CWE"}},
        ]
    )
    (finding,) = convert(checkout, sarif(item, rules=[rule])).findings
    assert finding.cwe == ["CWE-22", "CWE-78", "CWE-79", "CWE-89"]


def test_severity_score_and_message(checkout):
    rule = {
        "id": "r1",
        "defaultConfiguration": {"level": "error"},
        "properties": {"security-severity": "7.5"},
        "messageStrings": {"default": {"text": "{0} flows into {1}, see {2}"}},
    }
    from_rule = result(message={"id": "default", "arguments": ["input", "query"]})
    from_result = result(level="note")
    findings = convert(checkout, sarif(from_rule, from_result, rules=[rule])).findings
    assert findings[0].tool_severity == "error" and findings[1].tool_severity == "note"
    assert findings[0].tool_score == 7.5
    assert findings[0].message == "input flows into query, see {2}"


def test_suppressed_results_are_kept(checkout):
    item = result(suppressions=[{"kind": "inSource"}])
    (finding,) = convert(checkout, sarif(item)).findings
    assert finding.suppressed is True


def test_related_locations_and_data_flow(checkout):
    step = {
        "location": {
            "physicalLocation": {
                "artifactLocation": {"uri": "/src/app/views.py"},
                "region": {"startLine": 1},
            },
            "message": {"text": "source"},
        }
    }
    outside = {
        "location": {
            "physicalLocation": {
                "artifactLocation": {"uri": "/etc/passwd"},
                "region": {"startLine": 1},
            }
        }
    }
    item = result(
        relatedLocations=[
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "/src/app/views.py"},
                    "region": {"startLine": 4, "endLine": 4},
                }
            }
        ],
        codeFlows=[
            {"threadFlows": [{"locations": [step, outside, step]}]},
            {"threadFlows": [{"locations": [step]}]},
        ],
    )
    out = convert(checkout, sarif(item))
    (finding,) = out.findings
    assert [(r.file, r.start_line) for r in finding.related_locations] == [("app/views.py", 4)]
    assert [(s.step, s.start_line, s.message) for s in finding.data_flow] == [
        (1, 1, "source"),
        (2, 1, "source"),
    ]
    assert len(out.warnings) == 1


def test_identical_code_is_ambiguous_and_numbered_by_position(checkout):
    """Lines 2 and 3 hold the same code, so the two findings differ only by occurrence."""
    first, second, other = result(line=2), result(line=3), result(line=1)
    out = convert(checkout, sarif(second, first, other))
    by_line = {f.location.start_line: f for f in out.findings}
    assert by_line[2].fingerprint_ambiguous and by_line[3].fingerprint_ambiguous
    assert not by_line[1].fingerprint_ambiguous
    assert len({f.fingerprint for f in out.findings}) == 3
    # The order in the SARIF file doesn't matter, only the position in the file.
    again = convert(checkout, sarif(first, second, other))
    assert {f.location.start_line: f.fingerprint for f in again.findings} == {
        line: f.fingerprint for line, f in by_line.items()
    }


def test_snippet_stands_in_for_a_file_that_cant_be_read(checkout, monkeypatch):
    item = result()
    item["locations"][0]["physicalLocation"]["region"]["snippet"] = {"text": "query(x)"}
    readable = convert(checkout, sarif(item)).findings[0]
    monkeypatch.setattr(CheckoutReader, "read_lines", lambda self, path: None)
    unreadable = convert(checkout, sarif(item)).findings[0]
    assert unreadable.fingerprint == readable.fingerprint


@pytest.mark.parametrize(
    ("uri", "language"),
    [
        ("/src/app/views.py", "python"),
        ("/src/templates/page.html", "html"),
        ("/src/docs%20dir/conf.yml", "other"),
    ],
)
def test_language_from_the_extension(checkout, uri, language):
    (finding,) = convert(checkout, sarif(result(uri, line=1))).findings
    assert finding.language == language


def test_masking_adapter_hashes_and_stores_only_masked_lines(checkout):
    class Masking(Adapter):
        masks_snippets = True

        def mask(self, lines, location):
            masked = list(lines)
            for index in range(location.start_line - 1, location.end_line):
                masked[index] = "REDACTED"
            return masked

    item = result()
    item["locations"][0]["physicalLocation"]["region"]["snippet"] = {"text": "query(x)"}
    (finding,) = Masking().to_findings(sarif(item), RUN, CheckoutReader(checkout)).findings
    assert finding.location.snippet == "REDACTED"
    (plain,) = convert(checkout, sarif(item)).findings
    assert plain.location.snippet == "query(x)"
    assert finding.fingerprint != plain.fingerprint
