"""The rule step of grouping and the checks on groups (requirement F3, tests 1 and 2).

The function lookup is a fake that knows the functions listed in each test, until the
tree-sitter lookup of T3.3 is there. The PyGoat case uses the six SQL injection results of
tests/adapter_fixture, with rules, lines and CWEs read from semgrep-pygoat.sarif, and the
function lab() at lines 42 to 71 of dockerized_labs/sql_injection_lab/app.py, from its
@app.route decorator to its last line. The same-tool cases use Semgrep results of the full
PyGoat run at commit 2aa4cc1 (docs/finding-format.md): rules, lines and CWEs read from its SARIF
file, and the lines checked in the PyGoat source.
"""

import pytest

from app.dedup import (
    NEARBY,
    SAME_FUNCTION,
    FunctionSpan,
    Group,
    GroupingError,
    RuleStep,
    ScanFinding,
    group_findings,
)
from app.eval.metrics import related

APP = "app/views.py"
LAB = "dockerized_labs/sql_injection_lab/app.py"


class FakeLookup:
    def __init__(self, functions: dict[str, list[FunctionSpan]]):
        self._functions = functions
        self.asked: list[tuple[str, int]] = []

    def enclosing_function(self, file: str, line: int) -> FunctionSpan | None:
        self.asked.append((file, line))
        inside = [f for f in self._functions.get(file, []) if f.start_line <= line <= f.end_line]
        return min(inside, key=lambda f: f.end_line - f.start_line, default=None)


def finding(fid, line, cwe, *, tool="semgrep", rule="rule", file=APP, end=None, severity="warning"):
    return ScanFinding(
        finding_id=fid,
        tool=tool,
        rule_id=rule,
        cwe=tuple(cwe),
        message="m",
        tool_severity=severity,
        file=file,
        start_line=line,
        end_line=end or line,
    )


def members(groups):
    return [sorted(m.finding_id for m in g.members) for g in groups]


PING = FunctionSpan("run_ping", 10, 14)
LOOKUP = FakeLookup({APP: [PING, FunctionSpan("run_trace", 16, 20)]})


def test_semgrep_and_bandit_on_one_line_of_one_function_are_one_group():
    """F3, test 1, first half."""
    semgrep = finding("s", 12, ["CWE-78"], rule="python.lang.security.audit.subprocess-shell-true")
    bandit = finding("b", 12, ["CWE-77"], tool="bandit", rule="B602", severity="error")

    (group,) = group_findings([semgrep, bandit], [RuleStep(LOOKUP)])

    assert members([group]) == [["b", "s"]]
    assert (group.method, group.rule, group.similarity, group.llm_call_ids) == (
        "rule",
        SAME_FUNCTION,
        None,
        [],
    )
    assert group.reason == (
        "Same function run_ping (lines 10 to 14) and related CWEs (CWE-77 and CWE-78)"
    )
    assert group.representative.finding_id == "b"


def test_one_rule_in_two_functions_is_not_grouped_even_on_close_lines():
    """F3, test 1, second half: lines 14 and 16 are within NEARBY_LINES, but the functions
    differ."""
    a = finding("a", 14, ["CWE-78"], rule="python.lang.security.audit.subprocess-shell-true")
    b = finding("b", 16, ["CWE-78"], rule="python.lang.security.audit.subprocess-shell-true")
    assert group_findings([a, b], [RuleStep(LOOKUP)]) == []


def test_findings_of_two_tools_far_apart_in_one_function_are_grouped():
    lookup = FakeLookup({APP: [FunctionSpan("handler", 1, 80)]})
    groups = group_findings(
        [finding("a", 5, ["CWE-89"]), finding("b", 70, ["CWE-89"], tool="bandit")],
        [RuleStep(lookup)],
    )
    assert members(groups) == [["a", "b"]]
    assert groups[0].rule == SAME_FUNCTION


def test_findings_of_one_tool_in_one_function_are_grouped_only_when_their_lines_overlap():
    lookup = FakeLookup({APP: [FunctionSpan("handler", 1, 80)]})
    findings = [
        finding("a", 5, ["CWE-89"], rule="formatted-sql-query"),
        finding("b", 5, ["CWE-89"], rule="sqlalchemy-execute-raw-query"),
        finding("c", 6, ["CWE-89"], rule="formatted-sql-query"),
    ]
    assert members(group_findings(findings, [RuleStep(lookup)])) == [["a", "b"]]


def test_two_semgrep_rules_on_two_settings_a_line_apart_are_not_grouped():
    """dockerized_labs/sde/app.py sets SECRET_KEY on line 6 and DEBUG on line 7, outside any
    function. Semgrep tags both rules CWE-489, but they are two settings to check."""
    file = "dockerized_labs/sde/app.py"
    findings = [
        finding("k", 6, ["CWE-489"], file=file, rule="avoid_hardcoded_config_SECRET_KEY"),
        finding("d", 7, ["CWE-489"], file=file, rule="avoid_hardcoded_config_DEBUG"),
    ]
    assert group_findings(findings, [RuleStep()]) == []


def test_one_rule_on_several_forms_is_not_grouped():
    """django-no-csrf-token on the four forms of dockerized_labs/ssrf_lab/templates/lab1.html,
    each three lines after the one before."""
    file = "dockerized_labs/ssrf_lab/templates/lab1.html"
    forms = [
        finding(str(start), start, ["CWE-352"], file=file, end=start + 3, rule="no-csrf-token")
        for start in (16, 20, 24, 28)
    ]
    assert group_findings(forms, [RuleStep()]) == []


def test_four_semgrep_rules_on_one_call_are_one_group():
    """The subprocess.Popen call on lines 29 to 31 of dockerized_labs/command_injection_lab/app.py:
    two rules report the whole call, two report line 30, all tagged CWE-78."""
    file = "dockerized_labs/command_injection_lab/app.py"
    findings = [
        finding("1", 29, ["CWE-78"], file=file, end=31, rule="subprocess-injection"),
        finding("2", 29, ["CWE-78"], file=file, end=31, rule="dangerous-subprocess-use-audit"),
        finding("3", 30, ["CWE-78"], file=file, rule="dangerous-subprocess-use"),
        finding("4", 30, ["CWE-78"], file=file, rule="subprocess-shell-true"),
    ]
    (group,) = group_findings(findings, [RuleStep()])
    assert members([group]) == [["1", "2", "3", "4"]]
    assert group.reason == "Same file, lines 29 to 31, and related CWEs (CWE-78)"


def test_a_finding_outside_any_function_is_not_grouped_with_one_inside():
    """Line 15 is between run_ping and run_trace, so the lookup finds no function for it."""
    groups = group_findings(
        [finding("a", 14, ["CWE-78"]), finding("b", 15, ["CWE-78"])], [RuleStep(LOOKUP)]
    )
    assert groups == []


def test_without_functions_nearby_lines_with_related_cwes_are_grouped():
    findings = [
        finding("a", 20, ["CWE-22"], file="templates/a.html"),
        finding("b", 23, ["CWE-23"], file="templates/a.html", tool="bandit"),
        finding("c", 27, ["CWE-22"], file="templates/a.html"),
    ]
    (group,) = group_findings(findings, [RuleStep()])
    assert members([group]) == [["a", "b"]]
    assert group.rule == NEARBY
    assert group.reason == "Same file, lines 20 to 23, and related CWEs (CWE-22 and CWE-23)"


def test_a_group_grows_only_with_findings_that_match_every_member():
    """b is within 3 lines of a and of c, but a and c are 6 apart, so c starts its own group
    with d instead of joining a and b."""
    findings = [
        finding("a", 10, ["CWE-79"]),
        finding("b", 13, ["CWE-79"], tool="bandit"),
        finding("c", 16, ["CWE-79"]),
        finding("d", 16, ["CWE-79"], tool="bandit"),
    ]
    assert members(group_findings(findings, [RuleStep()])) == [["a", "b"], ["c", "d"]]


def test_unrelated_cwes_other_files_and_missing_cwes_are_not_grouped():
    findings = [
        finding("a", 5, ["CWE-89"]),
        finding("b", 5, ["CWE-79"]),
        finding("c", 5, ["CWE-89"], file="app/other.py"),
        finding("d", 5, []),
    ]
    assert group_findings(findings, [RuleStep()]) == []


def test_the_reason_names_only_the_cwes_that_relate_members():
    findings = [finding("a", 5, ["CWE-20", "CWE-78"]), finding("b", 5, ["CWE-88"])]
    (group,) = group_findings(findings, [RuleStep()])
    assert group.reason == "Same file, line 5, and related CWEs (CWE-78 and CWE-88)"


def test_the_six_sql_injection_results_of_pygoat():
    """docs/finding-format.md, "The same bug, reported six times". The four tagged CWE-89 are
    one group. The two tagged CWE-915 and CWE-704 are left to the later steps: these CWEs are
    wrong for SQL injection and the rules can't tell."""
    findings = [
        finding("1", 46, ["CWE-89"], file=LAB, end=69, rule="django.sql-injection-db-cursor"),
        finding("2", 47, ["CWE-89"], file=LAB, end=69, rule="django.sql-injection-db-cursor"),
        finding("3", 50, ["CWE-915"], file=LAB, end=52, rule="django.tainted-sql-string"),
        finding("4", 50, ["CWE-704"], file=LAB, end=52, rule="flask.tainted-sql-string"),
        finding("5", 57, ["CWE-89"], file=LAB, rule="formatted-sql-query"),
        finding("6", 57, ["CWE-89"], file=LAB, rule="sqlalchemy-execute-raw-query"),
    ]
    lookup = FakeLookup({LAB: [FunctionSpan("lab", 42, 71)]})

    (group,) = group_findings(findings, [RuleStep(lookup)])

    assert members([group]) == [["1", "2", "5", "6"]]
    assert group.reason == "Same function lab (lines 42 to 71) and related CWEs (CWE-89)"
    assert sorted(lookup.asked) == [(LAB, line) for line in (46, 47, 50, 50, 57, 57)]

    # Without the lookup, 46-69 and 47-69 overlap 50-52 and 57, so the same four are grouped
    # by nearby lines instead.
    (group,) = group_findings(findings, [RuleStep()])
    assert members([group]) == [["1", "2", "5", "6"]]
    assert (group.rule, group.reason) == (
        NEARBY,
        "Same file, lines 46 to 69, and related CWEs (CWE-89)",
    )


def test_the_order_of_the_findings_does_not_change_the_groups():
    findings = [
        finding("a", 10, ["CWE-79"]),
        finding("b", 13, ["CWE-79"], tool="bandit"),
        finding("c", 16, ["CWE-79"]),
    ]
    forward = members(group_findings(findings, [RuleStep()]))
    assert members(group_findings(findings[::-1], [RuleStep()])) == forward == [["a", "b"]]


@pytest.mark.parametrize(
    ("rule", "semgrep_cwe", "eslint_cwe", "cwe_text"),
    [
        (
            "detect-buffer-noassert",
            "CWE-119",
            ["CWE-125", "CWE-787"],
            "CWE-119, CWE-125 and CWE-787",
        ),
        ("detect-disable-mustache-escape", "CWE-116", ["CWE-79"], "CWE-79 and CWE-116"),
        ("detect-non-literal-require", "CWE-95", ["CWE-829"], "CWE-95 and CWE-829"),
    ],
)
def test_semgrep_copies_of_eslint_rules_group_with_them(rule, semgrep_cwe, eslint_cwe, cwe_text):
    """The CWEs of the Semgrep copies are from the rule files of semgrep-rules at the pinned
    commit, the ESLint ones from the adapter's table in docs/finding-format.md."""
    semgrep = finding("s", 12, [semgrep_cwe], file="server.js", rule=f"javascript.{rule}")
    eslint = finding("e", 12, eslint_cwe, file="server.js", tool="eslint", rule=f"security/{rule}")

    (group,) = group_findings([semgrep, eslint], [RuleStep()])

    assert members([group]) == [["e", "s"]]
    assert group.reason == f"Same file, line 12, and related CWEs ({cwe_text})"
    # The evaluation doesn't relate them.
    assert not any(related(semgrep_cwe, cwe) for cwe in eslint_cwe)


class PairStep:
    """Stands in for the text-similarity step: groups two given findings."""

    def __init__(self, a, b, **fields):
        self.pair, self.fields = (a, b), fields

    def group(self, findings, groups):
        chosen = [f for f in findings if f.finding_id in self.pair]
        return groups + [Group(chosen, **self.fields)]


def test_later_steps_get_the_findings_and_the_rule_groups():
    findings = [
        finding("a", 5, ["CWE-89"]),
        finding("b", 5, ["CWE-89"]),
        finding("c", 40, ["CWE-915"]),
        finding("d", 41, ["CWE-704"]),
    ]
    similarity = PairStep(
        "c", "d", method="similarity", similarity=0.912, reason="Similar messages, score 0.912"
    )
    groups = group_findings(findings, [RuleStep(), similarity])
    assert members(groups) == [["a", "b"], ["c", "d"]]
    assert [g.method for g in groups] == ["rule", "similarity"]


def test_a_finding_in_two_groups_is_refused():
    findings = [finding("a", 5, ["CWE-89"]), finding("b", 5, ["CWE-89"])]
    step = PairStep("a", "b", method="similarity", similarity=0.9, reason="r")
    with pytest.raises(GroupingError, match="in two groups"):
        group_findings(findings, [RuleStep(), step])


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"method": "rule", "reason": "r"}, "rule that matched"),
        ({"method": "similarity", "reason": "r"}, "score from 0 to 1"),
        ({"method": "similarity", "similarity": 1.2, "reason": "r"}, "score from 0 to 1"),
        ({"method": "llm", "reason": "r"}, "calls that decided it"),
        ({"method": "guess", "reason": "r"}, "unknown method"),
        ({"method": "rule", "rule": "x", "reason": " "}, "reason of one line"),
        ({"method": "rule", "rule": "x", "reason": "two\nlines"}, "reason of one line"),
    ],
)
def test_a_group_must_say_how_it_was_formed(fields, message):
    group = Group([finding("a", 1, []), finding("b", 1, [])], **fields)
    with pytest.raises(GroupingError, match=message):
        group.check()


def test_a_group_needs_two_different_findings():
    with pytest.raises(GroupingError, match="at least two"):
        Group([finding("a", 1, [])], "rule", "r", rule="x").check()
    with pytest.raises(GroupingError, match="at least two"):
        Group([finding("a", 1, []), finding("a", 1, [])], "rule", "r", rule="x").check()
