"""The pilot triage: choosing the sample, reading replies and running it within a budget."""

import json
import random
from decimal import Decimal

from app.adapters import Finding, Location
from app.eval import pilot
from app.eval.expected import Expected
from app.eval.metrics import false_positive_check, read_costs, read_findings
from app.llm.budget import Budget
from app.llm.cache import InMemoryResponseCache
from app.llm.call_log import InMemoryCallLog
from app.llm.catalog import Catalog, ModelInfo, Price
from app.llm.client import LLMClient
from app.llm.fake import FakeProvider
from app.llm.templates import load_template
from app.llm.types import StopReason

PRICE = Price(Decimal("1.00"), Decimal("2.00"), Decimal("0.10"), Decimal("1.25"))


def case(case_id, cwe, real=True):
    return Expected(
        "benchmark-python", case_id, cwe, f"testcode/{case_id}.py", None, None, "", "c", real
    )


def finding(case_id, cwe, rule="r1", line=3):
    return Finding(
        scan_id="s",
        run_id="r",
        tool="bandit",
        tool_version="",
        rule_id=rule,
        message=f"{rule} found something",
        tool_severity="warning",
        location=Location(f"testcode/{case_id}.py", line, line),
        raw={},
        cwe=[cwe],
    )


def test_the_sample_takes_one_finding_per_case_from_each_cwe_in_turn():
    cases = [case(f"Case{i}", "CWE-89") for i in range(5)] + [case("Case9", "CWE-78")]
    findings = [finding(f"Case{i}", "CWE-89") for i in range(5)]
    findings += [finding("Case0", "CWE-89", rule="r2"), finding("Case9", "CWE-77")]
    # A finding whose CWE isn't the case's doesn't flag it, nor does one outside any case.
    findings += [finding("Case1", "CWE-22"), finding("Other", "CWE-89")]

    rows = pilot.choose("benchmark-python", {"bandit": findings}, cases, 3, random.Random(1))

    assert len(rows) == 3
    assert len({row.case_id for row in rows}) == 3
    assert "Case9" in {row.case_id for row in rows}
    assert all(row.cwe in ("CWE-89", "CWE-77") for row in rows)
    again = pilot.choose("benchmark-python", {"bandit": findings}, cases, 3, random.Random(1))
    assert rows == again


def test_a_cwe_with_few_cases_gives_all_of_them():
    cases = [case("Case1", "CWE-78"), case("Case2", "CWE-89"), case("Case3", "CWE-89")]
    findings = [finding(c.case_id, c.cwe) for c in cases]
    rows = pilot.choose("benchmark-python", {"bandit": findings}, cases, 10, random.Random(1))
    assert sorted(row.case_id for row in rows) == ["Case1", "Case2", "Case3"]


def test_the_sample_and_its_answers_round_trip(tmp_path):
    cases = [case("Case1", "CWE-89"), case("Case2", "CWE-89", real=False), case("Case3", "CWE-78")]
    findings = [finding("Case1", "CWE-89"), finding("Case2", "CWE-89")]
    rows = pilot.choose("benchmark-python", {"bandit": findings}, cases, 5, random.Random(1))
    pilot.write_sample(rows, tmp_path / "sample.csv")
    assert pilot.read_sample(tmp_path / "sample.csv") == rows
    assert pilot.write_expected(rows, cases, tmp_path / "expected.csv") == 2


def test_the_model_gets_the_finding_but_not_the_case_or_its_answer():
    (row,) = pilot.choose(
        "benchmark-python",
        {"bandit": [finding("Case1", "CWE-89")]},
        [case("Case1", "CWE-89")],
        1,
        random.Random(1),
    )
    assert row.values() == {
        "tool": "bandit",
        "rule_id": "r1",
        "rule_description": "",
        "cwe": ["CWE-89"],
        "message": "r1 found something",
        "file": "testcode/Case1.py",
        "start_line": 3,
        "end_line": 3,
    }


def test_replies_that_arent_one_json_object_with_a_verdict_count_as_unsure():
    complete = StopReason.COMPLETE
    good = json.dumps({"verdict": "false_positive", "reasoning": "x", "cited_lines": []})
    assert pilot.parse_reply(good, complete) == pilot.Verdict("false_positive", True)
    assert pilot.parse_reply(f"```json\n{good}\n```", complete) == pilot.Verdict("unsure", False)
    assert pilot.parse_reply('{"verdict": "maybe"}', complete) == pilot.Verdict("unsure", False)
    assert pilot.parse_reply("[1]", complete) == pilot.Verdict("unsure", False)
    assert pilot.parse_reply(good, StopReason.MAX_TOKENS) == pilot.Verdict("unsure", False)


def make_sample(tmp_path, count):
    checkout = tmp_path / "copy"
    (checkout / "testcode").mkdir(parents=True)
    cases = []
    for i in range(count):
        (checkout / "testcode" / f"Case{i}.py").write_text(f"x = {i}\nrun(x)\n")
        cases.append(case(f"Case{i}", "CWE-89", real=i % 2 == 0))
    findings = [finding(c.case_id, "CWE-89") for c in cases]
    rows = pilot.choose("benchmark-python", {"bandit": findings}, cases, count, random.Random(1))
    return rows, cases, {"benchmark-python": checkout}


def make_client(replies, budget="1.00"):
    provider = FakeProvider(replies=replies)
    client = LLMClient(
        providers={"fake": provider},
        catalog=Catalog({"fake-model": ModelInfo("fake-model", "fake", PRICE)}, checked_on="t"),
        budget=Budget(budget),
        call_log=InMemoryCallLog(),
        cache=InMemoryResponseCache(),
    )
    return client, provider


def reply(verdict):
    return json.dumps({"verdict": verdict, "reasoning": "r", "cited_lines": []})


def test_a_run_writes_one_row_per_finding_for_both_metrics(tmp_path):
    rows, cases, checkouts = make_sample(tmp_path, 4)
    replies = [reply("false_positive"), reply("true_positive"), "not json", reply("unsure")]
    client, provider = make_client(replies)
    template = load_template(pilot.TEMPLATE)
    results = tmp_path / "out" / "results.csv"

    assert pilot.triage(rows, checkouts, client, template, "fake-model", results, 4) == 4

    request = provider.requests[0]
    assert "Case" in request.messages[1].content  # the file name, through the data block
    assert '"real"' not in request.messages[1].content
    assert request.max_tokens == pilot.MAX_TOKENS
    costs = read_costs(results)
    assert len(costs) == 4 and all(Decimal(row["cost_usd"]) > 0 for row in costs)
    verdicts = [f.verdict for f in read_findings(results)]
    assert verdicts == ["false_positive", "true_positive", "unsure", "unsure"]
    scored = false_positive_check(cases, read_findings(results))
    assert scored["raw"]["tp"] + scored["raw"]["fp"] == 4


def test_a_run_continues_without_paying_twice_and_stops_at_the_budget(tmp_path):
    rows, _, checkouts = make_sample(tmp_path, 3)
    template = load_template(pilot.TEMPLATE)
    results = tmp_path / "results.csv"
    client, _ = make_client([reply("unsure")] * 3)
    assert pilot.triage(rows, checkouts, client, template, "fake-model", results, 1) == 1

    client, provider = make_client([reply("unsure")] * 3, budget="0.000001")
    messages = []
    count = pilot.triage(
        rows, checkouts, client, template, "fake-model", results, 3, say=messages.append
    )
    assert count == 0 and provider.requests == []
    assert messages[0].startswith(f"stopped before {rows[1].finding_id}")
    assert len(read_costs(results)) == 1


def test_results_are_split_by_benchmark(tmp_path):
    rows, _, checkouts = make_sample(tmp_path, 2)
    client, _ = make_client([reply("unsure")] * 2)
    results = tmp_path / "results.csv"
    pilot.triage(rows, checkouts, client, load_template(pilot.TEMPLATE), "fake-model", results, 2)
    paths = pilot.split_by_dataset(results)
    assert list(paths) == ["benchmark-python"]
    assert len(read_findings(paths["benchmark-python"])) == 2


def test_worst_cases_send_nothing(tmp_path):
    rows, _, checkouts = make_sample(tmp_path, 2)
    client, provider = make_client([])
    costs = pilot.worst_cases(
        rows, checkouts, client, load_template(pilot.TEMPLATE), "fake-model", 2
    )
    assert len(costs) == 2 and all(cost > 0 for cost in costs)
    assert provider.requests == []
