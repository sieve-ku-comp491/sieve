"""The text-similarity step of grouping, after the rules (requirement F3).

Two findings that are close in the code, as the rules count it (rules.close), can still describe
the same issue when their CWEs don't relate: Semgrep tags two of its SQL injection rules on
PyGoat CWE-915 and CWE-704, for example. This step compares what the analyzers say about each
finding, its rule ID and its message, and groups the findings whose texts are alike.

The score is the cosine similarity of the two texts' TF-IDF vectors, with the document frequency
counted over the scan's findings, so a word that many findings share, such as the name of the
framework, counts for little. A group and a finding, or two of either, join only when every pair
of their findings is close and the lowest pair score reaches GROUP_AT, so a group can't grow
through a chain of pairs, as in the rules. A score from ASK_FROM up to GROUP_AT is unclear, and
the LLM step (app.dedup.llm) asks a model about those pairs.
"""

import math
import re
from collections import Counter, defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from app.dedup.functions import FunctionLookup, FunctionSpan, NoFunctionLookup
from app.dedup.groups import Group, ScanFinding
from app.dedup.rules import NEARBY_LINES, close

# Kept high, because a wrong merge costs more than a missed one (F3's precision target is 0.9).
# Two copies of one Semgrep rule for two frameworks score 1.0 on PyGoat, while two different
# issues on one line of it score below 0.3. To be tuned against the labeled groups of T6.3.
GROUP_AT = 0.6
ASK_FROM = 0.3

# Words, with camelCase and acronyms split: SQLAlchemy gives SQL and Alchemy.
WORD = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+")
# Words of one or two letters are left out, apart from these.
SHORT_WORDS = frozenset({"os", "io", "ip", "db", "sql", "xml", "url", "dom", "jwt", "ssl", "tls"})
# Abbreviations that analyzers write out elsewhere.
EXPANSIONS = {
    "sqli": ("sql", "injection"),
    "xss": ("cross", "site", "script"),
    "xxe": ("xml", "external", "entity"),
    "ssrf": ("server", "side", "request", "forgery"),
    "csrf": ("cross", "site", "request", "forgery"),
    "rce": ("remote", "code", "execution"),
}
ABBREVIATION = re.compile(r"\b(" + "|".join(EXPANSIONS) + r")\b", re.IGNORECASE)
# English filler and the words of analyzer boilerplate, which say nothing about the issue.
STOP_WORDS = frozenset(
    """
    the and for are but not you your all any can had her was one our out has his how its may
    new now old see way who did get let put say she too use that with have this will from they
    been were said each which their there when what where would could should might must into
    than then them these those also only such here more most other some very just over under
    about after before while because however therefore instead without within whether either
    use used uses using detect detected found finding findings possible possibly potential
    potentially consider make sure ensure avoid avoiding usually likely issue issues rule rules
    warning error note security vulnerability vulnerable code value values data result results
    function method call calls line lines file files semgrep bandit eslint spotbugs gitleaks
    plugin http https www com org html information please read refer docs documentation
    python java javascript typescript lang audit
    """.split()
)


def words(text: str) -> list[str]:
    """The words of an analyzer's text that can tell two issues apart, lower case and stemmed."""
    # Before the split, which would cut "SQLi" into "SQ" and "Li".
    text = ABBREVIATION.sub(lambda match: " ".join(EXPANSIONS[match.group(0).lower()]), text)
    found: list[str] = []
    for raw in WORD.findall(text):
        word = raw.lower()
        if len(word) < 3 and word not in SHORT_WORDS:
            continue
        stem = _stem(word)
        if word not in STOP_WORDS and stem not in STOP_WORDS:
            found.append(stem)
    return found


def _stem(word: str) -> str:
    """A light stemmer, enough to match "constructed" with "construct" and "queries" with
    "query"."""
    for suffix, replacement in (("ies", "y"), ("ing", ""), ("ed", ""), ("s", "")):
        if (
            word.endswith(suffix)
            and len(word) - len(suffix) >= 3
            and not word.endswith(("ss", "us", "is"))
        ):
            word = word[: -len(suffix)] + replacement
            break
    # formatted -> formatt -> format, running -> runn -> run
    if len(word) > 3 and word[-1] == word[-2] and word[-1] not in "aeioulsz":
        word = word[:-1]
    return word


def _text(finding: ScanFinding) -> str:
    parts = [finding.rule_id, finding.message]
    # A description that repeats the message or only names the rule adds nothing: Semgrep's is
    # its message again, or "Semgrep Finding: <rule ID>" for a rule without a full description.
    description = finding.rule_description
    if description and description != finding.message and finding.rule_id not in description:
        parts.append(description)
    return " ".join(parts)


class TextScorer:
    """The TF-IDF cosine similarity of two findings' texts, from 0 to 1, with the document
    frequency counted over the findings it is made with."""

    def __init__(self, findings: Sequence[ScanFinding]):
        counts = {f.finding_id: Counter(words(_text(f))) for f in findings}
        frequency = Counter(word for words_of in counts.values() for word in words_of)
        documents = len(counts)
        self._idf = {w: math.log((documents + 1) / (n + 1)) + 1 for w, n in frequency.items()}
        self._vectors = {finding_id: self._vector(c) for finding_id, c in counts.items()}

    def _vector(self, counts: Counter) -> dict[str, float]:
        vector = {word: n * self._idf[word] for word, n in counts.items()}
        norm = math.sqrt(sum(v * v for v in vector.values()))
        return {word: v / norm for word, v in vector.items()} if norm else {}

    def similarity(self, a: ScanFinding, b: ScanFinding) -> float:
        va, vb = self._vectors[a.finding_id], self._vectors[b.finding_id]
        if len(va) > len(vb):
            va, vb = vb, va
        return round(min(1.0, sum(v * vb.get(word, 0.0) for word, v in va.items())), 3)


@dataclass
class Item:
    """A group from an earlier step, or a finding in no group yet."""

    members: list[ScanFinding]
    group: Group | None = None

    def key(self) -> frozenset[str]:
        return frozenset(member.finding_id for member in self.members)


def items_by_file(findings: Sequence[ScanFinding], groups: list[Group]) -> dict[str, list[Item]]:
    """The groups so far and the findings in no group, by file, in the rules' order. A group's
    members are always in one file."""
    items: dict[str, list[Item]] = defaultdict(list)
    taken: set[str] = set()
    for group in groups:
        items[group.members[0].file].append(Item(list(group.members), group))
        taken.update(member.finding_id for member in group.members)
    for finding in findings:
        if finding.finding_id not in taken:
            items[finding.file].append(Item([finding]))
    for file_items in items.values():
        file_items.sort(key=lambda item: min(_order(member) for member in item.members))
    return dict(sorted(items.items()))


def functions_of(lookup: FunctionLookup, items: list[Item]) -> dict[str, FunctionSpan | None]:
    return {
        member.finding_id: lookup.enclosing_function(member.file, member.start_line)
        for item in items
        for member in item.members
    }


def pair_score(
    first: Item,
    second: Item,
    scorer: TextScorer,
    functions: dict[str, FunctionSpan | None],
    nearby_lines: int,
) -> float | None:
    """The lowest text similarity between a finding of first and one of second, or None when
    some pair isn't close enough in the code to be one issue."""
    lowest = 1.0
    for a in first.members:
        for b in second.members:
            if not close(a, b, functions[a.finding_id], functions[b.finding_id], nearby_lines):
                return None
            lowest = min(lowest, scorer.similarity(a, b))
    return lowest


def best_pair(
    items: list[Item],
    scorer: TextScorer,
    functions: dict[str, FunctionSpan | None],
    nearby_lines: int,
    accept: Callable[[float], bool],
    skip: set[frozenset[str]] = frozenset(),
) -> tuple[float, int, int] | None:
    """The pair of items with the highest score that accept allows, the first one in order on a
    tie, or None."""
    best: tuple[float, int, int] | None = None
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            if (items[i].key() | items[j].key()) in skip:
                continue
            score = pair_score(items[i], items[j], scorer, functions, nearby_lines)
            if score is not None and accept(score) and (best is None or score > best[0]):
                best = (score, i, j)
    return best


def merge(items: list[Item], i: int, j: int, group: Group) -> list[Item]:
    """The items with i and j replaced by one item for group, kept in order."""
    merged = Item(group.members, group)
    rest = [item for k, item in enumerate(items) if k not in (i, j)]
    return sorted([*rest, merged], key=lambda item: min(_order(member) for member in item.members))


def joined(first: Item, second: Item) -> list[ScanFinding]:
    return sorted([*first.members, *second.members], key=_order)


def earlier(first: Item, second: Item) -> tuple[Group, ...]:
    return tuple(item.group for item in (first, second) if item.group is not None)


def where(members: list[ScanFinding], functions: dict[str, FunctionSpan | None]) -> str:
    """Where the members are, for a group's reason."""
    spans = {functions[member.finding_id] for member in members}
    if len(spans) == 1 and (span := next(iter(spans))) is not None:
        return f"Same function {span.name} (lines {span.start_line} to {span.end_line})"
    first = min(member.start_line for member in members)
    last = max(member.end_line for member in members)
    return f"Same file, line {first}" if first == last else f"Same file, lines {first} to {last}"


class SimilarityStep:
    """Groups the findings and groups whose analyzer texts are alike, after the rule step."""

    def __init__(
        self,
        lookup: FunctionLookup | None = None,
        nearby_lines: int = NEARBY_LINES,
        group_at: float = GROUP_AT,
    ):
        self._lookup = lookup if lookup is not None else NoFunctionLookup()
        self._nearby = nearby_lines
        self._group_at = group_at

    def group(self, findings: Sequence[ScanFinding], groups: list[Group]) -> list[Group]:
        scorer = TextScorer(findings)
        result: list[Group] = []
        for items in items_by_file(findings, groups).values():
            functions = functions_of(self._lookup, items)
            while found := best_pair(
                items, scorer, functions, self._nearby, lambda score: score >= self._group_at
            ):
                score, i, j = found
                items = merge(items, i, j, self._group(items[i], items[j], score, functions))
            result += [item.group for item in items if item.group is not None]
        return result

    def _group(
        self,
        first: Item,
        second: Item,
        score: float,
        functions: dict[str, FunctionSpan | None],
    ) -> Group:
        members = joined(first, second)
        before = earlier(first, second)
        rule = next((group.rule for group in before if group.rule), None)
        calls = [call for group in before for call in group.llm_call_ids]
        what = "related CWEs and similar analyzer messages" if rule else "similar analyzer messages"
        return Group(
            members,
            "similarity",
            f"{where(members, functions)}, {what} (text similarity {score:.2f})",
            rule=rule,
            similarity=score,
            llm_call_ids=calls,
        )


def _order(finding: ScanFinding) -> tuple:
    return (
        finding.start_line,
        finding.end_line,
        finding.tool,
        finding.rule_id,
        finding.finding_id,
    )
