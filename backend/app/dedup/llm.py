"""The LLM step of grouping: a model decides the pairs that text similarity leaves unclear
(requirements F3 and N3).

After the rule and similarity steps, the pairs of findings or groups that are close in the code
and whose text similarity is from ASK_FROM up to GROUP_AT go to a model, the highest score
first. The cheaper model answers first, and only an answer of unsure, or one that can't be read,
goes to the stronger model. A pair the model calls the same issue becomes one group, which
records every call behind the decision, so the duplicate_group_llm_calls rows link it to them.

The prompt carries what the rules saw of each finding: the analyzer, rule, CWEs, message, file
and lines, and the flagged lines as code in the data block. The step asks at most
max_questions pairs, and it stops asking, keeping the groups it has, when the run's budget
can't cover the next call or the provider fails. stopped then says why.
"""

import json
import re
from collections.abc import Sequence

from app.dedup.functions import FunctionLookup, FunctionSpan, NoFunctionLookup
from app.dedup.groups import Group, ScanFinding
from app.dedup.rules import NEARBY_LINES
from app.dedup.similarity import (
    ASK_FROM,
    GROUP_AT,
    Item,
    TextScorer,
    best_pair,
    earlier,
    functions_of,
    items_by_file,
    joined,
    merge,
    where,
)
from app.llm.budget import BudgetExceeded
from app.llm.client import LLMClient
from app.llm.provider import ProviderError
from app.llm.templates import load_template
from app.llm.types import CodeBlock

TEMPLATE = "duplicate_check"
MAX_QUESTIONS = 50
MAX_TOKENS = 2000
REASON_LENGTH = 300
ANSWERS = ("yes", "no", "unsure")
FENCE = re.compile(r"^\s*```(?:json)?\s*\n(.*?)\n\s*```\s*$", re.DOTALL | re.IGNORECASE)


class LLMStep:
    """Asks a model about the pairs the earlier steps leave unclear."""

    def __init__(
        self,
        client: LLMClient,
        cheap_model: str,
        strong_model: str | None = None,
        lookup: FunctionLookup | None = None,
        nearby_lines: int = NEARBY_LINES,
        ask_from: float = ASK_FROM,
        group_at: float = GROUP_AT,
        max_questions: int = MAX_QUESTIONS,
    ):
        self._client = client
        self._models = [model for model in (cheap_model, strong_model) if model]
        self._lookup = lookup if lookup is not None else NoFunctionLookup()
        self._nearby = nearby_lines
        self._ask_from = ask_from
        self._group_at = group_at
        self._max_questions = max_questions
        self._template = load_template(TEMPLATE)
        self.questions = 0
        self.stopped: str | None = None

    def group(self, findings: Sequence[ScanFinding], groups: list[Group]) -> list[Group]:
        scorer = TextScorer(findings)
        asked: set[frozenset[str]] = set()
        result: list[Group] = []
        for items in items_by_file(findings, groups).values():
            functions = functions_of(self._lookup, items)
            while self.stopped is None and (
                found := best_pair(items, scorer, functions, self._nearby, self._unclear, asked)
            ):
                if self.questions >= self._max_questions:
                    self.stopped = f"asked the most questions per scan, {self._max_questions}"
                    break
                _, i, j = found
                asked.add(items[i].key() | items[j].key())
                self.questions += 1
                try:
                    answer, reason, calls = self._ask(items[i], items[j])
                except (BudgetExceeded, ProviderError) as error:
                    self.stopped = f"{type(error).__name__}: {error}"
                    break
                if answer == "yes" and calls:
                    group = self._group(items[i], items[j], reason, calls, functions)
                    items = merge(items, i, j, group)
            result += [item.group for item in items if item.group is not None]
        return result

    def _unclear(self, score: float) -> bool:
        return self._ask_from <= score < self._group_at

    def _ask(self, first: Item, second: Item) -> tuple[str, str | None, list[str]]:
        values = {
            "first": [_describe(member) for member in first.members],
            "second": [_describe(member) for member in second.members],
        }
        code = _code([*first.members, *second.members])
        calls: list[str] = []
        for model in self._models:
            response = self._client.ask(
                self._template, values, code, model=model, max_tokens=MAX_TOKENS
            )
            if response.call_id:
                calls.append(response.call_id)
            answer, reason = parse_answer(response.text)
            if answer != "unsure":
                return answer, reason, calls
        return "unsure", None, calls

    def _group(
        self,
        first: Item,
        second: Item,
        reason: str | None,
        calls: list[str],
        functions: dict[str, FunctionSpan | None],
    ) -> Group:
        members = joined(first, second)
        before = earlier(first, second)
        said = f": {reason}" if reason else ""
        return Group(
            members,
            "llm",
            f"{where(members, functions)}, and a model judged them one issue{said}",
            rule=next((group.rule for group in before if group.rule), None),
            similarity=next(
                (group.similarity for group in before if group.similarity is not None), None
            ),
            llm_call_ids=[*(c for group in before for c in group.llm_call_ids), *calls],
        )


def parse_answer(text: str) -> tuple[str, str | None]:
    """The model's decision, yes, no or unsure, and its reason on one line. An answer that
    can't be read counts as unsure."""
    match = FENCE.match(text)
    try:
        data = json.loads(match.group(1) if match else text)
    except ValueError:
        return "unsure", None
    if not isinstance(data, dict):
        return "unsure", None
    answer = data.get("same_issue")
    if isinstance(answer, bool):
        answer = "yes" if answer else "no"
    if not isinstance(answer, str) or answer.strip().lower() not in ANSWERS:
        return "unsure", None
    reason = data.get("reason")
    if isinstance(reason, str) and reason.strip():
        reason = " ".join(reason.split())[:REASON_LENGTH]
    else:
        reason = None
    return answer.strip().lower(), reason


def _describe(finding: ScanFinding) -> dict:
    return {
        "tool": finding.tool,
        "rule": finding.rule_id,
        "cwe": list(finding.cwe),
        "message": finding.message,
        "file": finding.file,
        "lines": f"{finding.start_line}-{finding.end_line}",
    }


def _code(findings: list[ScanFinding]) -> list[CodeBlock]:
    """The flagged lines of the findings, once for each place."""
    blocks: dict[tuple[str, int, int], CodeBlock] = {}
    for finding in findings:
        place = (finding.file, finding.start_line, finding.end_line)
        if finding.snippet and place not in blocks:
            blocks[place] = CodeBlock(*place, finding.snippet)
    return list(blocks.values())
