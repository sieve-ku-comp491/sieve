"""The pilot triage of T6.2 (docs/evaluation.md, "Pilot triage").

The pilot sends a sample of baseline findings through LLMClient with the draft prompt
false_positive_check, one call per finding, to measure the cost and time per finding and how
often each model's verdict is right. It has no tools and no second opinion.

The findings are read with the pipeline's adapters from the analyzers' SARIF files, so the
prompt gets the same rule, message and lines as in a scan. Only findings that flag a Benchmark
case count: a finding in a case's file with the case's CWE or a related one. The sample takes
one finding per case and spreads the cases evenly over the CWEs of each Benchmark.
"""

import csv
import json
import random
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, fields
from decimal import Decimal
from pathlib import Path

from app.adapters import AdapterRegistry, Finding
from app.checkout import CheckoutReader
from app.eval import expected as expected_csv
from app.eval.expected import Expected
from app.eval.metrics import related
from app.llm import BudgetExceeded, CodeBlock, LLMClient, ProviderError, StopReason
from app.llm.templates import PromptTemplate
from app.runner.runner import PluginRun

TEMPLATE = "false_positive_check"
MAX_TOKENS = 4000
VERDICTS = ("true_positive", "false_positive", "unsure")
DATASETS = ("benchmark-java", "benchmark-python")


@dataclass(frozen=True)
class SampledFinding:
    """One finding of the sample, with the Benchmark case it flags."""

    finding_id: str
    dataset: str
    case_id: str
    tool: str
    rule_id: str
    rule_description: str
    cwe: str
    message: str
    file: str
    start_line: int
    end_line: int

    def values(self) -> dict[str, object]:
        """What the data block gives the model. The case ID and the answer stay out."""
        return {
            "tool": self.tool,
            "rule_id": self.rule_id,
            "rule_description": self.rule_description,
            "cwe": self.cwe.split(";") if self.cwe else [],
            "message": self.message,
            "file": self.file,
            "start_line": self.start_line,
            "end_line": self.end_line,
        }


SAMPLE_COLUMNS = [f.name for f in fields(SampledFinding)]
RESULT_COLUMNS = [
    "finding_id",
    "dataset",
    "file",
    "cwe",
    "verdict",
    "valid_reply",
    "stop_reason",
    "cost_usd",
    "seconds",
    "input_tokens",
    "output_tokens",
    "model_version",
    "call_id",
]


def read_findings(tool: str, sarif_path: Path, checkout: Path) -> list[Finding]:
    """The findings of one SARIF file, mapped by the tool's adapter against the checkout."""
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    run = PluginRun("pilot", "pilot", tool, "", "", "")
    adapter = AdapterRegistry().get(tool)
    return adapter.to_findings(sarif, run, CheckoutReader(checkout)).findings


def choose(
    dataset: str,
    findings_by_tool: dict[str, list[Finding]],
    cases: list[Expected],
    count: int,
    rng: random.Random,
) -> list[SampledFinding]:
    """count findings of one Benchmark, one per flagged case, taken from each CWE in turn.

    The cases of each CWE are shuffled, and the CWEs are visited in order, one case each per
    round, until count is reached or no CWE has a case left. A CWE with few flagged cases gives
    all of them. Each case's finding is chosen at random among the findings that flag it.
    """
    by_file = {case.file: case for case in cases}
    flagging: dict[str, list[SampledFinding]] = {}
    for tool in sorted(findings_by_tool):
        for index, finding in enumerate(findings_by_tool[tool]):
            case = by_file.get(finding.location.file)
            if case is None or not any(related(case.cwe, cwe) for cwe in finding.cwe):
                continue
            short = dataset.removeprefix("benchmark-")
            flagging.setdefault(case.case_id, []).append(
                SampledFinding(
                    finding_id=f"{short}-{tool}-{index:05d}",
                    dataset=dataset,
                    case_id=case.case_id,
                    tool=tool,
                    rule_id=finding.rule_id,
                    rule_description=finding.rule_description or "",
                    cwe=";".join(finding.cwe),
                    message=finding.message,
                    file=finding.location.file,
                    start_line=finding.location.start_line,
                    end_line=finding.location.end_line,
                )
            )
    by_cwe: dict[str, list[str]] = {}
    for case in sorted(cases, key=lambda c: c.case_id):
        if case.case_id in flagging:
            by_cwe.setdefault(case.cwe, []).append(case.case_id)
    for case_ids in by_cwe.values():
        rng.shuffle(case_ids)
    order = sorted(by_cwe, key=lambda c: int(c.removeprefix("CWE-")))
    chosen: list[SampledFinding] = []
    while len(chosen) < count and any(by_cwe[cwe] for cwe in order):
        for cwe in order:
            if by_cwe[cwe] and len(chosen) < count:
                candidates = flagging[by_cwe[cwe].pop()]
                chosen.append(rng.choice(candidates))
    return chosen


def write_sample(rows: Iterable[SampledFinding], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, SAMPLE_COLUMNS)
        writer.writeheader()
        writer.writerows(asdict(row) for row in rows)


def read_sample(path: Path) -> list[SampledFinding]:
    with path.open(encoding="utf-8", newline="") as handle:
        return [
            SampledFinding(
                **{
                    **row,
                    "start_line": int(row["start_line"]),
                    "end_line": int(row["end_line"]),
                }
            )
            for row in csv.DictReader(handle)
        ]


def write_expected(sample: list[SampledFinding], cases: list[Expected], path: Path) -> int:
    """The answers of the sampled cases only, so the false-positive check scores the sample."""
    sampled = {row.case_id for row in sample}
    return expected_csv.write_csv((case for case in cases if case.case_id in sampled), path)


@dataclass(frozen=True)
class Verdict:
    verdict: str
    valid_reply: bool


def parse_reply(text: str, stop_reason: StopReason) -> Verdict:
    """The verdict of a reply. A reply that isn't one complete JSON object with a known verdict
    counts as unsure, as the review screen would still show the finding."""
    if stop_reason is not StopReason.COMPLETE:
        return Verdict("unsure", False)
    try:
        reply = json.loads(text)
    except ValueError:
        return Verdict("unsure", False)
    if not isinstance(reply, dict) or reply.get("verdict") not in VERDICTS:
        return Verdict("unsure", False)
    return Verdict(reply["verdict"], True)


def done_ids(path: Path) -> set[str]:
    if not path.exists():
        return set()
    with path.open(encoding="utf-8", newline="") as handle:
        return {row["finding_id"] for row in csv.DictReader(handle)}


def triage(
    sample: list[SampledFinding],
    checkouts: dict[str, Path],
    client: LLMClient,
    template: PromptTemplate,
    model: str,
    results: Path,
    limit: int,
    effort: str | None = None,
    say: Callable[[str], None] = print,
) -> int:
    """Asks the model about the first `limit` findings of the sample, one call each.

    A finding that is already in the results file is skipped, so a run can be continued with a
    higher limit without paying for the same finding twice. Each answer is appended as soon as
    it arrives. The run stops at BudgetExceeded or a ProviderError, and returns how many new
    findings it triaged.
    """
    done = done_ids(results)
    new = not results.exists()
    results.parent.mkdir(parents=True, exist_ok=True)
    triaged = 0
    with results.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, RESULT_COLUMNS)
        if new:
            writer.writeheader()
        for row in sample[:limit]:
            if row.finding_id in done:
                continue
            lines = CheckoutReader(checkouts[row.dataset]).read_lines(row.file)
            if lines is None:
                say(f"{row.finding_id}: can't read {row.file}, skipped")
                continue
            code = [CodeBlock(row.file, 1, len(lines), "\n".join(lines))]
            try:
                response = client.ask(
                    template, row.values(), code, model=model, max_tokens=MAX_TOKENS, effort=effort
                )
            except (BudgetExceeded, ProviderError) as error:
                say(f"stopped before {row.finding_id}: {error}")
                break
            verdict = parse_reply(response.text, response.stop_reason)
            usage = response.usage
            writer.writerow(
                {
                    "finding_id": row.finding_id,
                    "dataset": row.dataset,
                    "file": row.file,
                    "cwe": row.cwe,
                    "verdict": verdict.verdict,
                    "valid_reply": "true" if verdict.valid_reply else "false",
                    "stop_reason": response.stop_reason.value,
                    "cost_usd": str(response.cost_usd),
                    "seconds": f"{response.duration_ms / 1000:.3f}",
                    "input_tokens": usage.prompt_tokens,
                    "output_tokens": usage.output_tokens,
                    "model_version": response.model_version,
                    "call_id": response.call_id or "",
                }
            )
            handle.flush()
            triaged += 1
    return triaged


def worst_cases(
    sample: list[SampledFinding],
    checkouts: dict[str, Path],
    client: LLMClient,
    template: PromptTemplate,
    model: str,
    limit: int,
    effort: str | None = None,
) -> list[Decimal]:
    """The worst-case cost of each call the run would make, without sending anything."""
    info = client.catalog.get(model)
    costs = []
    for row in sample[:limit]:
        lines = CheckoutReader(checkouts[row.dataset]).read_lines(row.file) or []
        code = [CodeBlock(row.file, 1, len(lines), "\n".join(lines))]
        request = client.build_request(
            template, row.values(), code, model=model, max_tokens=MAX_TOKENS, effort=effort
        )
        costs.append(client.catalog.worst_case_cost(info, request))
    return costs


def split_by_dataset(results: Path) -> dict[str, Path]:
    """One results file per Benchmark next to the full one, for the false-positive check,
    because the two Benchmarks' case IDs overlap."""
    with results.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    paths = {}
    for dataset in sorted({row["dataset"] for row in rows}):
        path = results.with_name(f"{results.stem}-{dataset}.csv")
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, RESULT_COLUMNS)
            writer.writeheader()
            writer.writerows(row for row in rows if row["dataset"] == dataset)
        paths[dataset] = path
    return paths
