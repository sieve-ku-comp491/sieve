"""The SARIF mapping shared by all adapters (docs/finding-format.md), on small SARIF files."""

import time

import pytest

from app.adapters import BaseSarifAdapter, Location
from app.adapters.base import MAX_TEXT
from app.adapters.finding import MAX_WARNINGS
from app.checkout import CheckoutReader
from app.runner.runner import PluginRun

RUN = PluginRun("run-1", "scan-1", "tool", "image:1", "2.0.0", "rules@1")


class Adapter(BaseSarifAdapter):
    tool = "tool"


@pytest.fixture
def checkout(tmp_path):
    root = tmp_path / "checkout"
    files = {
        "app/views.py": "a = 1\nquery(x)\nquery(x)\nb = 2\n",
        "app/same_line.py": "query(x); query(x)\n",
        "app/Upper.PY": "eval(x)\n",
        "templates/page.html": "<p>{{ x|safe }}</p>\n",
        "docs dir/conf.yml": "key: value\n",
        "odd/h#x.py": "eval(x)\n",
        "odd/q?x.py": "eval(x)\n",
        "odd/p%41.py": "eval(x)\n",
        "odd/%00/app.py": "eval(x)\n",
    }
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
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


def region(item):
    return item["locations"][0]["physicalLocation"]["region"]


def sarif(*results, rules=None, **run_extra):
    run = {"tool": {"driver": {"name": "T", "rules": [{"id": "r1"}] if rules is None else rules}}}
    run.update(run_extra)
    run["results"] = list(results)
    return {"version": "2.1.0", "runs": [run]}


def convert(checkout, document, adapter=None):
    return (adapter or Adapter()).to_findings(document, RUN, CheckoutReader(checkout))


# Fields ----------------------------------------------------------------------------------


def test_defaults(checkout):
    (finding,) = convert(checkout, sarif(result())).findings
    assert finding.tool == "tool" and finding.tool_version == "2.0.0"
    assert finding.scan_id == "scan-1" and finding.run_id == "run-1"
    assert finding.finding_id is None
    assert finding.tool_severity == "warning"
    assert finding.cwe == [] and finding.tool_confidence is None and finding.tool_score is None
    # Without a SARIF snippet, the snippet comes from the checkout.
    assert finding.location == Location("app/views.py", 2, 2, None, None, "query(x)")
    assert finding.language == "python" and finding.suppressed is False
    assert finding.fingerprint.startswith("v1:") and finding.context_hash.startswith("c1:")


def test_raw_is_a_copy_without_nul_characters(checkout):
    item = result(message={"text": "a\x00b"})
    (finding,) = convert(checkout, sarif(item)).findings
    assert finding.raw is not item and finding.raw["message"]["text"] == "ab"
    assert finding.message == "ab"
    finding.raw["ruleId"] = "changed"
    assert item["ruleId"] == "r1"


@pytest.mark.parametrize(
    ("level", "expected"),
    [
        ("error", "error"),
        ("note", "note"),
        ("none", "none"),
        ("high", "warning"),
        (None, "warning"),
    ],
)
def test_severity(checkout, level, expected):
    item = result() if level is None else result(level=level)
    (finding,) = convert(checkout, sarif(item)).findings
    assert finding.tool_severity == expected


def test_severity_from_the_rule_default(checkout):
    rules = [{"id": "r1", "defaultConfiguration": {"level": "error"}}]
    (finding,) = convert(checkout, sarif(result(), rules=rules)).findings
    assert finding.tool_severity == "error"


@pytest.mark.parametrize(("value", "score"), [("7.5", 7.5), (0, 0.0), ("11", None), ("n/a", None)])
def test_score(checkout, value, score):
    rules = [{"id": "r1", "properties": {"security-severity": value}}]
    (finding,) = convert(checkout, sarif(result(), rules=rules)).findings
    assert finding.tool_score == score


def test_cwe_from_tags_relationships_and_taxa(checkout):
    rule = {
        "id": "r1",
        "properties": {
            "tags": [
                "CWE-089: SQL Injection",
                "CWE-1333: Inefficient Regular Expression Complexity",
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
    assert finding.cwe == ["CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-1333"]


@pytest.mark.parametrize(
    ("suppressions", "suppressed"),
    [
        ([{"kind": "inSource"}], True),
        ([{"kind": "external", "status": "accepted"}], True),
        ([{"kind": "external", "status": "rejected"}], False),
        ([{"kind": "external", "status": "underReview"}], False),
        ([], False),
    ],
)
def test_suppressed_results_are_kept(checkout, suppressions, suppressed):
    (finding,) = convert(checkout, sarif(result(suppressions=suppressions))).findings
    assert finding.suppressed is suppressed


def test_help_uri_only_for_web_links(checkout):
    rules = [
        {"id": "r1", "helpUri": "https://semgrep.dev/r/r1"},
        {"id": "r2", "helpUri": "javascript:alert(1)"},
    ]
    findings = convert(checkout, sarif(result(), result(ruleId="r2"), rules=rules)).findings
    assert [f.rule_help_uri for f in findings] == ["https://semgrep.dev/r/r1", None]


@pytest.mark.parametrize(
    ("uri", "language"),
    [
        ("/src/app/views.py", "python"),
        ("/src/app/Upper.PY", "python"),
        ("/src/templates/page.html", "html"),
        ("/src/docs dir/conf.yml", "other"),
    ],
)
def test_language_from_the_extension(checkout, uri, language):
    (finding,) = convert(checkout, sarif(result(uri, line=1))).findings
    assert finding.language == language


# Messages --------------------------------------------------------------------------------


def test_messages(checkout):
    rule = {
        "id": "r1",
        "messageStrings": {
            "default": {"text": "{0} flows into {1}, see {2}"},
            "braces": {"text": "use {{0}} not {0}"},
        },
    }
    driver_strings = {"global": {"text": "from the driver: {0}"}}
    items = [
        result(message={"id": "default", "arguments": ["input", "query"]}),
        result(message={"id": "braces", "arguments": ["eval"]}),
        result(message={"text": "'{0}' is tainted", "arguments": ["x"]}),
        result(message={"id": "global", "arguments": ["y"]}),
        result(message={"id": "missing"}),
    ]
    document = sarif(*items, rules=[rule])
    document["runs"][0]["tool"]["driver"]["globalMessageStrings"] = driver_strings
    assert [f.message for f in convert(checkout, document).findings] == [
        "input flows into query, see {2}",
        "use {0} not eval",
        "'x' is tainted",
        "from the driver: y",
        "",
    ]


def test_a_message_that_expands_without_limit_is_cut(checkout):
    rule = {"id": "r1", "messageStrings": {"m": {"text": "{0}" * 100_000}}}
    item = result(message={"id": "m", "arguments": ["x" * 5_000]})
    (finding,) = convert(checkout, sarif(item, rules=[rule])).findings
    assert len(finding.message) <= MAX_TEXT + 10


# Rules -----------------------------------------------------------------------------------


def test_rule_lookup(checkout):
    rules = [
        {"id": "a", "shortDescription": {"text": "rule a"}},
        {"id": "b", "fullDescription": {"text": "rule b"}, "helpUri": "https://b"},
    ]
    extension = {"name": "pack", "rules": [{"id": "x", "fullDescription": {"text": "rule x"}}]}
    by_index = result(ruleIndex=1)
    del by_index["ruleId"]
    by_reference_index = result(rule={"index": 1})
    del by_reference_index["ruleId"]
    out_of_range = result(ruleIndex=9, ruleId="a")
    disagreeing = result(ruleIndex=1, ruleId="a")
    hierarchical = result(ruleId="a/sub")
    extension_by_index = result(ruleId="x", rule={"id": "x", "toolComponent": {"index": 0}})
    extension_by_name = result(ruleId="x", rule={"id": "x", "toolComponent": {"name": "pack"}})
    unknown_component = result(ruleId="a", rule={"id": "a", "toolComponent": {"name": "nope"}})
    document = sarif(
        by_index,
        by_reference_index,
        out_of_range,
        disagreeing,
        hierarchical,
        extension_by_index,
        extension_by_name,
        unknown_component,
        rules=rules,
    )
    document["runs"][0]["tool"]["extensions"] = [extension]
    findings = convert(checkout, document).findings
    assert [(f.rule_id, f.rule_description) for f in findings] == [
        ("b", "rule b"),
        ("b", "rule b"),
        ("a", "rule a"),
        ("a", "rule a"),
        ("a/sub", "rule a"),
        ("x", "rule x"),
        ("x", "rule x"),
        ("a", None),
    ]
    assert findings[0].rule_help_uri == "https://b"


def test_a_result_without_a_rule_is_dropped(checkout):
    item = result()
    del item["ruleId"]
    out = convert(checkout, sarif(item, rules=[]))
    assert out.findings == [] and out.dropped == {"no_rule": 1}


def test_only_failing_results_are_kept(checkout):
    out = convert(
        checkout,
        sarif(result(), result(kind="fail"), result(kind="pass"), result(kind="notApplicable")),
    )
    assert len(out.findings) == 2
    assert out.dropped == {"kind_pass": 1, "kind_notApplicable": 1}
    assert out.dropped_count == 2


def test_every_run_is_read(checkout):
    document = sarif(result())
    document["runs"].append(sarif(result(line=3))["runs"][0])
    assert [f.location.start_line for f in convert(checkout, document).findings] == [2, 3]


# Paths -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("uri", "base", "expected"),
    [
        ("/src/app/views.py", None, "app/views.py"),
        ("file:///src/app/views.py", None, "app/views.py"),
        ("file:/src/app/views.py", None, "app/views.py"),
        ("file://localhost/src/app/views.py", None, "app/views.py"),
        ("app/views.py", None, "app/views.py"),
        ("views.py", "APP", "app/views.py"),
        ("app/views.py", "%SRCROOT%", "app/views.py"),
        # Semgrep writes raw file names: nothing in them is a URI fragment, query or escape.
        ("/src/docs dir/conf.yml", None, "docs dir/conf.yml"),
        ("/src/odd/h#x.py", None, "odd/h#x.py"),
        ("/src/odd/q?x.py", None, "odd/q?x.py"),
        ("/src/odd/p%41.py", None, "odd/p%41.py"),
        ("/src/odd/%00/app.py", None, "odd/%00/app.py"),
        # file: URIs are decoded, and so is a relative reference that only exists decoded.
        ("file:///src/docs%20dir/conf.yml", None, "docs dir/conf.yml"),
        ("docs%20dir/conf.yml", None, "docs dir/conf.yml"),
    ],
)
def test_paths(checkout, uri, base, expected):
    item = result(uri, line=1)
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
        "https://example.com/src/app/views.py",
        "file://otherhost/src/app/views.py",
        "app/views.py\x00x",
        "app/views.py%00",
        "app/\ud800.py",
        "file://[oops/src/app/views.py",
        "//[oops/app/views.py",
        "C:/Windows/win.ini",
        "app\\views.py",
    ],
)
def test_paths_outside_the_checkout_are_dropped(checkout, uri):
    """None of these may crash the run: the good result next to it is still mapped."""
    out = convert(checkout, sarif(result(uri), result()))
    assert [f.location.file for f in out.findings] == ["app/views.py"]
    assert out.dropped == {"path_outside_checkout": 1}
    assert len(out.warnings) == 1 and "r1" in out.warnings[0]


@pytest.mark.parametrize(
    "bases",
    [
        {"A": {"uri": "x/", "uriBaseId": "B"}, "B": {"uri": "y/", "uriBaseId": "A"}},
        {"A": {"uri": "file://[x/src/app/"}},
        {"A": {"uri": "file:///etc/"}},
    ],
)
def test_bad_bases_are_dropped(checkout, bases):
    item = result("views.py")
    item["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"] = "A"
    out = convert(checkout, sarif(item, originalUriBaseIds=bases))
    assert out.findings == [] and out.dropped == {"path_outside_checkout": 1}


def test_a_link_out_of_the_checkout_is_dropped(checkout, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("API_KEY=x\n", encoding="utf-8")
    try:
        (checkout / "app/link.py").symlink_to(secret)
    except OSError:
        pytest.skip("this machine can't create symbolic links")
    out = convert(checkout, sarif(result("/src/app/link.py", line=1)))
    assert out.findings == [] and out.dropped == {"path_outside_checkout": 1}


# Lines -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("region_value", "reason"),
    [
        (None, "no_line"),
        ({"startLine": 0}, "no_line"),
        ({"startLine": 10**40}, "no_line"),
        ({"charOffset": 3}, "no_line"),
        ({"startLine": 9}, "line_outside_file"),
    ],
)
def test_results_without_a_usable_line_are_dropped(checkout, region_value, reason):
    item = result()
    physical = item["locations"][0]["physicalLocation"]
    if region_value is None:
        del physical["region"]
    else:
        physical["region"] = region_value
    out = convert(checkout, sarif(item))
    assert out.findings == [] and out.dropped == {reason: 1}


def test_results_without_a_file_are_dropped(checkout):
    item = result()
    item["locations"] = []
    out = convert(checkout, sarif(item))
    assert out.findings == [] and out.dropped == {"no_location": 1}


def test_end_line_is_kept_inside_the_file(checkout):
    before = result()
    region(before)["endLine"] = 1
    after = result()
    region(after)["endLine"] = 99
    first, second = convert(checkout, sarif(before, after)).findings
    assert (first.location.start_line, first.location.end_line) == (2, 2)
    assert (second.location.start_line, second.location.end_line) == (2, 4)


# Related locations and code flows --------------------------------------------------------


def test_related_locations_and_data_flow(checkout):
    def at(uri, line, message=None):
        location = {
            "physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}
        }
        if message:
            location["message"] = {"text": message}
        return {"location": location}

    item = result(
        relatedLocations=[
            at("/src/app/views.py", 4)["location"],
            at("/etc/passwd", 1)["location"],
        ],
        codeFlows=[
            {
                "threadFlows": [
                    {
                        "locations": [
                            at("/src/app/views.py", 1, "source"),
                            at("/etc/passwd", 1),
                            at("/src/app/views.py", 2, "sink"),
                        ]
                    }
                ]
            },
            {"threadFlows": [{"locations": [at("/src/app/views.py", 4)]}]},
        ],
    )
    out = convert(checkout, sarif(item))
    (finding,) = out.findings
    assert [(r.file, r.start_line, r.snippet) for r in finding.related_locations] == [
        ("app/views.py", 4, "b = 2")
    ]
    # A step that was left out keeps its gap, so the path shows that something is missing.
    assert [(s.step, s.start_line, s.message, s.snippet) for s in finding.data_flow] == [
        (1, 1, "source", "a = 1"),
        (3, 2, "sink", "query(x)"),
    ]
    assert len(out.warnings) == 2
    assert any("related location" in w for w in out.warnings)
    assert any("flow step 2" in w for w in out.warnings)


def test_warnings_are_capped(checkout):
    outside = {"physicalLocation": {"artifactLocation": {"uri": "/etc/passwd"}}}
    item = result(ruleId="r" * 100_000, relatedLocations=[outside] * 500)
    out = convert(checkout, sarif(item, rules=[]))
    assert len(out.warnings) == MAX_WARNINGS and out.more_warnings == 500 - MAX_WARNINGS
    assert all(len(w) < 400 for w in out.warnings)


# Fingerprints ----------------------------------------------------------------------------


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


def test_occurrences_on_one_line_are_ordered_by_column(checkout):
    left = result("/src/app/same_line.py", line=1)
    region(left)["startColumn"] = 1
    right = result("/src/app/same_line.py", line=1)
    region(right)["startColumn"] = 11
    forward = convert(checkout, sarif(left, right)).findings
    backward = convert(checkout, sarif(right, left)).findings
    assert {f.location.start_column: f.fingerprint for f in forward} == {
        f.location.start_column: f.fingerprint for f in backward
    }
    assert forward[0].fingerprint != forward[1].fingerprint


def test_snippet_stands_in_for_a_file_that_cant_be_read(checkout, monkeypatch):
    item = result()
    region(item)["endLine"] = 3
    region(item)["snippet"] = {"text": "query(x)\nquery(x)"}
    readable = convert(checkout, sarif(item))
    monkeypatch.setattr(CheckoutReader, "read_lines", lambda self, path: None)
    unreadable = convert(checkout, sarif(item))
    (before,), (after,) = readable.findings, unreadable.findings
    assert after.fingerprint == before.fingerprint
    # Without the file there is no context, so no earlier review can hide the finding.
    assert before.context_hash.startswith("c1:") and after.context_hash == ""
    assert len(unreadable.warnings) == 1


# Untrusted values ------------------------------------------------------------------------


def test_long_numbers_dont_crash_the_run(checkout):
    rules = [
        {
            "id": "r1",
            "properties": {"tags": ["CWE-" + "9" * 5000, "external/cwe/cwe-" + "9" * 5000]},
        },
        {"id": "r2", "messageStrings": {"m": {"text": "{" + "9" * 5000 + "}"}}},
    ]
    items = [
        result(taxa=[{"id": "9" * 5000, "toolComponent": {"name": "CWE"}}]),
        result(ruleId="r2", message={"id": "m", "arguments": ["x"]}),
    ]
    out = convert(checkout, sarif(*items, rules=rules))
    assert len(out.findings) == 2 and out.findings[0].cwe == []


def test_cwe_patterns_stay_fast_on_long_tags(checkout):
    tags = ["CWE-" + "0" * 50_000 + "_", "external/cwe/cwe-" + "0" * 50_000 + "x"]
    rules = [{"id": "r1", "properties": {"tags": tags}}]
    started = time.monotonic()
    convert(checkout, sarif(*[result() for _ in range(10)], rules=rules))
    assert time.monotonic() - started < 2


def test_one_result_that_breaks_the_mapping_is_dropped(checkout):
    class Broken(Adapter):
        def confidence(self, rule, result):
            if result["message"]["text"] == "boom":
                raise RuntimeError("unexpected")
            return None

    out = convert(checkout, sarif(result(message={"text": "boom"}), result()), Broken())
    assert len(out.findings) == 1 and out.dropped == {"unreadable_result": 1}


# Masking ---------------------------------------------------------------------------------


class Masking(Adapter):
    def mask(self, lines, location):
        masked = list(lines)
        for index in range(location.start_line - 1, location.end_line):
            masked[index] = "REDACTED"
        return masked


def test_masking_reaches_every_stored_snippet_and_raw(checkout):
    item = result(
        relatedLocations=[
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "/src/app/views.py"},
                    "region": {"startLine": 2, "snippet": {"text": "query(x)"}},
                }
            }
        ]
    )
    region(item)["snippet"] = {"text": "query(x)"}
    (finding,) = convert(checkout, sarif(item), Masking()).findings
    assert finding.location.snippet == "REDACTED"
    assert finding.related_locations[0].snippet == "REDACTED"
    assert "query(x)" not in repr(finding.raw)
    (plain,) = convert(checkout, sarif(item)).findings
    assert plain.location.snippet == "query(x)" and "query(x)" in repr(plain.raw)
    assert finding.fingerprint != plain.fingerprint
