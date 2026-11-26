"""The LLM step of grouping (requirements F3 and N3), with a fake provider.

The unclear pair is two real Semgrep results on PyGoat's lab(): sql-injection-db-cursor-execute
on lines 46 to 69, tagged CWE-89, and django's tainted-sql-string on lines 50 to 52, tagged
CWE-915. The rules can't relate the CWEs, and their texts are alike but not enough for the
similarity step.
"""

import json
from dataclasses import replace
from decimal import Decimal

import pytest

from app.dedup import (
    ASK_FROM,
    GROUP_AT,
    Group,
    LLMStep,
    RuleStep,
    ScanFinding,
    SimilarityStep,
    TextScorer,
    group_findings,
)
from app.dedup.llm import parse_answer
from app.llm.budget import Budget
from app.llm.cache import InMemoryResponseCache
from app.llm.call_log import InMemoryCallLog
from app.llm.catalog import Catalog, ModelInfo, Price
from app.llm.client import LLMClient
from app.llm.fake import FakeProvider
from app.llm.provider import ProviderError
from app.llm.types import StopReason

PRICE = Price(
    input=Decimal("1.00"),
    output=Decimal("2.00"),
    cache_read=Decimal("0.10"),
    cache_write=Decimal("1.25"),
)
# Every close pair is unclear, so a test sets the order of the questions with its texts alone.
EVERY = {"ask_from": 0.0, "group_at": 1.01}


def made(fid: str, file: str, tool: str, message: str) -> ScanFinding:
    return ScanFinding(
        finding_id=fid,
        tool=tool,
        rule_id=f"{fid}-rule",
        cwe=(),
        message=message,
        tool_severity="warning",
        file=file,
        start_line=10,
        end_line=10,
    )


class Judge(FakeProvider):
    """Calls the bandit and the eslint finding two issues, and any other pair one."""

    def complete(self, request):
        content = request.messages[-1].content
        apart = "bandit" in content and "eslint" in content and "semgrep" not in content
        self._replies = [answer("no" if apart else "yes")]
        return super().complete(request)


def named(findings, rule):
    return [f for f in findings if f.rule_id.endswith(rule)]


def make_client(provider: FakeProvider, budget: str = "1.00") -> tuple[LLMClient, InMemoryCallLog]:
    models = {name: ModelInfo(name, "fake", PRICE) for name in ("cheap", "strong")}
    log = InMemoryCallLog()
    client = LLMClient(
        providers={"fake": provider},
        catalog=Catalog(models, checked_on="test"),
        budget=Budget(Decimal(budget)),
        call_log=log,
        cache=InMemoryResponseCache(),
    )
    return client, log


def answer(same: str, reason: str = "Both are the query built from the login form.") -> str:
    return json.dumps({"same_issue": same, "reason": reason})


@pytest.fixture
def unclear(pygoat_findings):
    (cursor,) = [
        f for f in named(pygoat_findings, "sql-injection-db-cursor-execute") if f.start_line == 46
    ]
    (tainted,) = named(pygoat_findings, "django.security.injection.tainted-sql-string")
    return [cursor, tainted]


def test_the_pair_is_unclear(unclear):
    assert ASK_FROM <= TextScorer(unclear).similarity(*unclear) < GROUP_AT
    assert group_findings(unclear, [RuleStep(), SimilarityStep()]) == []


def test_a_yes_from_the_cheaper_model_groups_the_pair(unclear):
    provider = FakeProvider(replies=[answer("yes")])
    client, log = make_client(provider)

    (group,) = group_findings(unclear, [RuleStep(), SimilarityStep(), LLMStep(client, "cheap")])

    assert [request.model for request in provider.requests] == ["cheap"]
    assert group.method == "llm"
    assert group.llm_call_ids == [record.id for record in log.records]
    assert group.reason == (
        "Same file, lines 46 to 69, and a model judged them one issue: "
        "Both are the query built from the login form."
    )
    # The prompt carries the flagged lines only as code in the data block.
    system, user = provider.requests[0].messages
    assert "data block" in system.content and "same_issue" in system.content
    assert "c.execute(sql_query)" not in system.content
    assert "tainted-sql-string" in user.content and "sql_query" in user.content


def test_unsure_goes_to_the_stronger_model(unclear):
    provider = FakeProvider(replies=[answer("unsure"), answer("yes")])
    client, log = make_client(provider)

    (group,) = LLMStep(client, "cheap", "strong").group(unclear, [])

    assert [request.model for request in provider.requests] == ["cheap", "strong"]
    assert group.llm_call_ids == [record.id for record in log.records]
    assert len(group.llm_call_ids) == 2


def test_a_no_keeps_the_pair_apart(unclear):
    provider = FakeProvider(replies=[answer("no", "One builds the query, the other runs it.")])
    client, _ = make_client(provider)
    step = LLMStep(client, "cheap", "strong")

    assert step.group(unclear, []) == []
    assert [request.model for request in provider.requests] == ["cheap"]
    # The pair is kept apart, so it isn't asked again, from the cache or otherwise.
    assert step.questions == 1


def test_an_answer_that_cannot_be_read_counts_as_unsure(unclear):
    provider = FakeProvider(replies=["Sure, they look the same.", "```json\n{}\n```"])
    client, _ = make_client(provider)

    assert LLMStep(client, "cheap", "strong").group(unclear, []) == []
    assert [request.model for request in provider.requests] == ["cheap", "strong"]


def test_clear_pairs_are_not_asked(pygoat_findings):
    provider = FakeProvider()
    client, _ = make_client(provider)
    step = LLMStep(client, "cheap", "strong")

    groups = group_findings(pygoat_findings, [RuleStep(), SimilarityStep(), step])

    # The rules' group and the similarity group of PyGoat, and nothing left in between.
    assert sorted(g.method for g in groups) == ["rule", "similarity"]
    assert provider.requests == [] and step.questions == 0


def test_a_budget_that_runs_out_stops_the_step_and_keeps_the_groups(unclear):
    earlier = Group(unclear, "rule", "Same file, lines 46 to 69", rule="nearby_lines_related_cwe")
    provider = FakeProvider(replies=[answer("yes")])
    client, _ = make_client(provider, budget="0.000001")
    step = LLMStep(client, "cheap", "strong")

    assert step.group(unclear, []) == []
    assert step.stopped.startswith("BudgetExceeded")
    assert provider.requests == []
    assert step.group(unclear, [earlier]) == [earlier]


def test_a_provider_error_stops_the_step(unclear):
    provider = FakeProvider(error=ProviderError("the API is down", retryable=False))
    client, _ = make_client(provider)
    step = LLMStep(client, "cheap", "strong")

    assert step.group(unclear, []) == []
    assert step.stopped == "ProviderError: the API is down"


def test_at_most_max_questions_are_asked(unclear):
    provider = FakeProvider(replies=[answer("no")])
    client, _ = make_client(provider)
    step = LLMStep(client, "cheap", max_questions=0)

    assert step.group(unclear, []) == []
    assert provider.requests == []
    assert step.stopped == "asked the most questions per scan, 0"


def test_a_stop_holds_in_every_file(unclear):
    """The unclear pair in a second file: after the provider fails, nothing more is asked."""
    copies = [replace(f, finding_id=f"{f.finding_id}-copy", file="copy/app.py") for f in unclear]
    provider = FakeProvider(error=ProviderError("the API is down", retryable=False))
    client, _ = make_client(provider)
    step = LLMStep(client, "cheap", "strong")

    assert step.group([*unclear, *copies], []) == []
    assert len(provider.requests) == 1


def test_the_highest_pair_of_the_scan_is_asked_first():
    """With one question allowed, the pair asked is the more alike one, in the second file."""
    sql = "SQL query built from the request"
    findings = [
        made("a1", "a.py", "semgrep", "alpha beta gamma"),
        made("a2", "a.py", "bandit", "delta epsilon zeta"),
        made("b1", "b.py", "semgrep", sql),
        made("b2", "b.py", "bandit", sql),
    ]
    provider = FakeProvider(replies=[answer("yes")])
    client, _ = make_client(provider)
    step = LLMStep(client, "cheap", max_questions=1, **EVERY)

    (group,) = step.group(findings, [])

    assert sorted(m.finding_id for m in group.members) == ["b1", "b2"]
    assert step.stopped == "asked the most questions per scan, 1"


def test_a_third_finding_cannot_join_what_the_model_kept_apart():
    """Three tools on one line, every pair alike. The model calls bandit and eslint two issues
    and bandit and semgrep one, so eslint can't join their group through semgrep."""
    sql = "SQL query built from the request"
    findings = [made(t[0], "a.py", t, sql) for t in ("bandit", "eslint", "semgrep")]
    client, _ = make_client(Judge())
    step = LLMStep(client, "cheap", **EVERY)

    (group,) = step.group(findings, [])

    assert sorted(m.finding_id for m in group.members) == ["b", "s"]
    assert step.questions == 2


def test_an_llm_group_that_joins_another_keeps_every_call():
    """Two pairs become groups, and then one group of all four, which links the calls of both
    earlier decisions too (N3, test 1)."""
    sql, shell = "SQL query built from the request", "Shell command run with user input"
    findings = [
        made("q1", "a.py", "semgrep", sql),
        made("q2", "a.py", "bandit", sql),
        made("c1", "a.py", "eslint", shell),
        made("c2", "a.py", "gitleaks", shell),
    ]
    provider = FakeProvider(replies=[answer("yes")] * 3)
    client, log = make_client(provider)

    (group,) = LLMStep(client, "cheap", **EVERY).group(findings, [])

    assert sorted(m.finding_id for m in group.members) == ["c1", "c2", "q1", "q2"]
    assert group.method == "llm"
    assert group.llm_call_ids == [record.id for record in log.records]
    assert len(group.llm_call_ids) == 3


def test_an_answer_that_was_cut_off_counts_as_unsure(unclear):
    provider = FakeProvider(
        replies=[answer("yes"), answer("yes")], stop_reason=StopReason.MAX_TOKENS
    )
    client, _ = make_client(provider)

    assert LLMStep(client, "cheap", "strong").group(unclear, []) == []
    assert [request.model for request in provider.requests] == ["cheap", "strong"]


def test_the_effort_and_the_token_limit_reach_every_call(unclear):
    provider = FakeProvider(replies=[answer("unsure"), answer("no")])
    client, _ = make_client(provider)

    LLMStep(client, "cheap", "strong", effort="low", max_tokens=1234).group(unclear, [])

    assert [(r.effort, r.max_tokens) for r in provider.requests] == [("low", 1234)] * 2


def test_each_scan_starts_the_counters_again(unclear):
    provider = FakeProvider(replies=[answer("no")])
    client, _ = make_client(provider)
    step = LLMStep(client, "cheap", max_questions=1)

    for _ in range(2):
        assert step.group(unclear, []) == []
        assert (step.questions, step.stopped) == (1, None)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('{"same_issue": "yes", "reason": "Same query."}', ("yes", "Same query.")),
        ('{"same_issue": "No", "reason": "  Two\\n  places. "}', ("no", "Two places.")),
        ('{"same_issue": true}', ("yes", None)),
        ('```json\n{"same_issue": "unsure", "reason": ""}\n```', ("unsure", None)),
        ('{"same_issue": "maybe"}', ("unsure", None)),
        ("[]", ("unsure", None)),
        ("not JSON", ("unsure", None)),
    ],
)
def test_parse_answer(text, expected):
    assert parse_answer(text) == expected


def test_a_long_reason_is_cut_to_one_line():
    answer_, reason = parse_answer(json.dumps({"same_issue": "yes", "reason": "word\n" * 200}))
    assert answer_ == "yes" and "\n" not in reason and len(reason) == 300
