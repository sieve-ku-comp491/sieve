"""The text-similarity step of grouping (requirement F3).

The PyGoat cases use the nine Semgrep results in tests/adapter_fixture (the pygoat_findings
fixture in conftest.py), so the texts are the analyzer's own.
"""

import random

import pytest

from app.dedup import (
    ASK_FROM,
    GROUP_AT,
    SAME_FUNCTION,
    FunctionSpan,
    Group,
    RuleStep,
    ScanFinding,
    SimilarityStep,
    TextScorer,
    group_findings,
)
from app.dedup.similarity import Item, pair_score, words


class FakeLookup:
    def __init__(self, functions: list[FunctionSpan]):
        self._functions = functions

    def enclosing_function(self, file: str, line: int) -> FunctionSpan | None:
        inside = [f for f in self._functions if f.start_line <= line <= f.end_line]
        return min(inside, key=lambda f: f.end_line - f.start_line, default=None)


def named(findings: list[ScanFinding], rule: str) -> list[ScanFinding]:
    return [f for f in findings if f.rule_id.endswith(rule)]


def finding(fid, line, message, *, tool="semgrep", rule="rule", cwe=(), end=None):
    return ScanFinding(
        finding_id=fid,
        tool=tool,
        rule_id=rule,
        cwe=tuple(cwe),
        message=message,
        tool_severity="warning",
        file="app/views.py",
        start_line=line,
        end_line=end or line,
    )


def test_two_copies_of_one_rule_group_by_their_messages(pygoat_findings):
    """django's and flask's tainted-sql-string on lines 50 to 52 are tagged CWE-915 and CWE-704,
    which the rules can't relate, and say the same thing."""
    groups = group_findings(pygoat_findings, [RuleStep(), SimilarityStep()])

    (similar,) = [g for g in groups if g.method == "similarity"]
    assert sorted(m.rule_id for m in similar.members) == [
        "python.django.security.injection.tainted-sql-string",
        "python.flask.security.injection.tainted-sql-string",
    ]
    assert similar.similarity >= GROUP_AT
    assert similar.rule is None
    assert similar.reason == (
        f"Same file, lines 50 to 52, similar analyzer messages "
        f"(text similarity {similar.similarity:.2f})"
    )
    # They can't join the rules' group: one tool's findings need overlapping lines, and line 57
    # doesn't overlap 50 to 52.
    (rules,) = [g for g in groups if g.method == "rule"]
    assert len(rules.members) == 4


def test_two_issues_on_one_line_stay_apart(pygoat_findings):
    """Flask's debug=True and host 0.0.0.0 on line 78 are different issues."""
    (debug,) = named(pygoat_findings, "debug-enabled")
    (host,) = named(pygoat_findings, "avoid_app_run_with_bad_host")
    assert TextScorer(pygoat_findings).similarity(debug, host) < ASK_FROM

    groups = group_findings(pygoat_findings, [RuleStep(), SimilarityStep()])
    grouped = {m.finding_id for g in groups for m in g.members}
    assert debug.finding_id not in grouped and host.finding_id not in grouped


def test_a_finding_joins_a_group_whose_members_it_is_like():
    lookup = FakeLookup([FunctionSpan("login", 10, 30)])
    text = "SQL query built by formatting the user name into the string"
    findings = [
        finding("s", 12, text, rule="python.formatted-sql", cwe=["CWE-89"]),
        finding("b", 14, text, tool="bandit", rule="B608", cwe=["CWE-89"]),
        finding("t", 12, text + " from a request", rule="python.tainted-sql", cwe=["CWE-704"]),
    ]

    (group,) = group_findings(findings, [RuleStep(lookup), SimilarityStep(lookup)])

    assert sorted(m.finding_id for m in group.members) == ["b", "s", "t"]
    assert (group.method, group.rule) == ("similarity", SAME_FUNCTION)
    assert group.reason.startswith(
        "Same function login (lines 10 to 30), related CWEs and similar analyzer messages"
    )


@pytest.mark.parametrize(
    ("first", "second", "lookup"),
    [
        # Other tools in two functions.
        (
            finding("a", 12, "SQL query built from the user name"),
            finding("b", 22, "SQL query built from the user name", tool="bandit"),
            FakeLookup([FunctionSpan("f", 10, 15), FunctionSpan("g", 20, 25)]),
        ),
        # One tool on lines that don't overlap.
        (
            finding("a", 12, "SQL query built from the user name"),
            finding("b", 14, "SQL query built from the user name"),
            None,
        ),
        # Other tools further apart than the nearby lines.
        (
            finding("a", 12, "SQL query built from the user name"),
            finding("b", 20, "SQL query built from the user name", tool="bandit"),
            None,
        ),
    ],
)
def test_alike_texts_group_only_when_close_in_the_code(first, second, lookup):
    assert TextScorer([first, second]).similarity(first, second) == 1.0
    assert group_findings([first, second], [SimilarityStep(lookup)]) == []


def test_a_pair_scores_its_least_alike_findings():
    a, b, c = (finding(x, 12, x, tool=x) for x in "abc")
    scores = {frozenset("ab"): 0.9, frozenset("ac"): 0.7, frozenset("bc"): 0.4}

    class Scorer:
        def similarity(self, x, y):
            return scores[frozenset((x.finding_id, y.finding_id))]

    functions = {"a": None, "b": None, "c": None}
    assert pair_score(Item([a]), Item([b, c]), Scorer(), functions, 3) == 0.7
    assert pair_score(Item([a, b]), Item([c]), Scorer(), functions, 3) == 0.4


def test_the_groups_do_not_depend_on_the_order_of_the_findings(pygoat_findings):
    expected = group_findings(pygoat_findings, [RuleStep(), SimilarityStep()])
    shuffled = list(pygoat_findings)
    random.Random(7).shuffle(shuffled)
    again = group_findings(shuffled, [RuleStep(), SimilarityStep()])
    assert [(g.method, [m.finding_id for m in g.members]) for g in again] == [
        (g.method, [m.finding_id for m in g.members]) for g in expected
    ]


def test_groups_from_earlier_steps_are_kept():
    earlier = Group(
        [finding("x", 40, "hard-coded secret key"), finding("y", 40, "secret", tool="bandit")],
        "rule",
        "Same file, line 40, and related CWEs (CWE-798)",
        rule="nearby_lines_related_cwe",
    )
    findings = [*earlier.members, finding("z", 90, "debug mode is on")]
    assert SimilarityStep().group(findings, [earlier]) == [earlier]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("SQLAlchemy raw query", ["sql", "alchemy", "raw", "query"]),
        ("Detected possible formatted SQL queries", ["format", "sql", "query"]),
        ("SQLi through the request", ["sql", "injection", "through", "request"]),
        ("python.flask.security.audit.debug-enabled", ["flask", "debug", "enabl"]),
    ],
)
def test_words(text, expected):
    assert words(text) == expected


def test_identical_texts_score_one_and_unrelated_texts_zero():
    a = finding("a", 1, "Hard-coded password in the settings")
    b = finding("b", 1, "Hard-coded password in the settings")
    c = finding("c", 1, "Cookie without the secure flag")
    scorer = TextScorer([a, b, c])
    assert scorer.similarity(a, b) == 1.0
    assert scorer.similarity(a, c) == 0.0
