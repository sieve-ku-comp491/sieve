"""Command line of the evaluation harness. Run from backend/: python -m app.eval --help"""

import argparse
import json
import random
import sys
from pathlib import Path

from app.eval import expected, findings, metrics, neutral, nvd, pilot, sources

DATASETS = {
    "benchmark-java": lambda root, s: expected.benchmark_java(root, s.commit),
    "benchmark-python": lambda root, s: expected.benchmark_python(root, s.commit),
    "cwe-bench-java": lambda root, s: expected.cwe_bench_java(root),
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.eval", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    fetch = commands.add_parser("fetch", help="check out the pinned datasets and targets")
    fetch.add_argument("names", nargs="*", help="sources to fetch, default all")

    commands.add_parser("expected", help="convert each fetched dataset's answers to one CSV")

    copy = commands.add_parser("neutral", help="make a Benchmark copy with neutral names")
    copy.add_argument("dataset", choices=sorted(neutral.PROFILES))
    copy.add_argument("--seed", type=int, help="reuse the seed of an earlier copy")

    cves = commands.add_parser("cves", help="look up the NVD vector of each CWE-Bench-Java CVE")
    cves.add_argument("--out", type=Path, default=nvd.CVES_FILE)

    tools = commands.add_parser("findings", help="turn analyzer SARIF files into a findings CSV")
    tools.add_argument(
        "--sarif",
        action="append",
        required=True,
        metavar="TOOL=FILE",
        help="a tool name and its SARIF file, for example semgrep=results.sarif, repeatable",
    )
    tools.add_argument("--strip-prefix", default="", help="remove this leading folder from paths")
    tools.add_argument(
        "--root",
        action="append",
        default=[],
        metavar="TOOL=DIR",
        help="the scanned folder of a tool as an absolute path, for a tool that names files by "
        "a base folder, such as spotbugs, repeatable",
    )
    tools.add_argument("--out", type=Path, required=True)

    score = commands.add_parser("metrics", help="compute one metric and print it as JSON")
    kinds = score.add_subparsers(dest="metric", required=True)
    fp = kinds.add_parser("false-positives", help="false-positive check on a Benchmark")
    fp.add_argument("--expected", type=Path, required=True)
    fp.add_argument("--findings", type=Path, required=True)
    dedup = kinds.add_parser("dedup", help="precision and recall of duplicate merges")
    dedup.add_argument("--labeled", type=Path, required=True)
    dedup.add_argument("--predicted", type=Path, required=True)
    severity = kinds.add_parser("severity", help="CVSS metrics, score error and level agreement")
    severity.add_argument("--cases", type=Path, required=True)
    baseline = kinds.add_parser("severity-baseline", help="the analyzer's own severity as a level")
    baseline.add_argument("--cases", type=Path, required=True)
    cost = kinds.add_parser("cost", help="API cost and time per finding")
    cost.add_argument("--findings", type=Path, required=True)

    trial = commands.add_parser("pilot", help="the pilot triage of T6.2")
    steps = trial.add_subparsers(dest="step", required=True)
    sample = steps.add_parser("sample", help="choose the findings of the pilot")
    sample.add_argument(
        "--sarif",
        action="append",
        required=True,
        metavar="DATASET:TOOL=FILE",
        help="a Benchmark, a tool and its SARIF file, for example "
        "benchmark-python:bandit=bandit.sarif, repeatable",
    )
    sample.add_argument("--per-dataset", type=int, default=50)
    sample.add_argument("--seed", type=int, required=True)
    triage = steps.add_parser("run", help="triage the sample with one model")
    triage.add_argument("--model", required=True)
    triage.add_argument("--budget", required=True, help="the run's limit in US dollars")
    triage.add_argument("--limit", type=int, required=True, help="triage the first N findings")
    triage.add_argument("--effort")
    triage.add_argument(
        "--dry-run", action="store_true", help="print the worst-case costs and send nothing"
    )
    for step in (sample, triage):
        step.add_argument("--dir", type=Path, help="the pilot's folder, default eval-data/pilot")

    args = parser.parse_args(argv)
    return COMMANDS[args.command](args)


def run_fetch(args: argparse.Namespace) -> int:
    chosen = _sources(args.names)
    for source in chosen:
        path = sources.fetch(source)
        print(f"{source.name}: {source.version} at {source.commit[:12]} in {path}")
    return 0


def run_expected(args: argparse.Namespace) -> int:
    chosen = _sources(list(DATASETS))
    if _not_fetched(chosen):
        return 1
    for source in chosen:
        root = sources.checkout_path(source)
        out = sources.data_dir() / "expected" / f"{source.name}.csv"
        count = expected.write_csv(DATASETS[source.name](root, source), out)
        print(f"{source.name}: {count} rows in {out}")
    return 0


def run_neutral(args: argparse.Namespace) -> int:
    (source,) = _sources([args.dataset])
    if _not_fetched([source]):
        return 1
    root = sources.checkout_path(source)
    dest = sources.data_dir() / "neutral" / source.name
    answers = sources.data_dir() / "answers" / source.name
    leaks = neutral.make_copy(
        neutral.PROFILES[source.name], root, source.commit, dest, answers, args.seed
    )
    if leaks:
        print(f"{len(leaks)} places still name the Benchmark:", file=sys.stderr)
        for leak in leaks[:50]:
            print(f"  {leak}", file=sys.stderr)
        return 1
    commit = neutral.commit_copy(dest)
    (answers / "copy_commit.txt").write_text(f"{commit}\n", encoding="utf-8")
    print(f"{source.name}: neutral copy at {commit[:12]} in {dest}, answers in {answers}")
    return 0


def run_cves(args: argparse.Namespace) -> int:
    (source,) = _sources(["cwe-bench-java"])
    if _not_fetched([source]):
        return 1
    root = sources.checkout_path(source)
    case_ids = {row.case_id for row in expected.cwe_bench_java(root)}
    rows = nvd.cwe_bench_java_cves(root, case_ids)
    nvd.write_cves(rows, args.out)
    print(f"{len(rows)} CVEs, {sum(1 for r in rows if r.cvss_vector)} with a vector, in {args.out}")
    return 0


def run_findings(args: argparse.Namespace) -> int:
    roots = dict(_pair(item, "--root", "TOOL=DIR") for item in args.root)
    every, total = [], 0
    for item in args.sarif:
        tool, file = _pair(item, "--sarif", "TOOL=FILE")
        result = findings.read_sarif(tool, Path(file), args.strip_prefix, roots.get(tool, ""))
        every.extend(result.findings)
        total += result.without_location + result.outside_checkout
        print(
            f"{tool}: {len(result.findings)} findings, {result.without_location} without a "
            f"location, {result.outside_checkout} outside the scanned folder"
        )
    findings.write_findings(every, args.out)
    print(f"{len(every)} findings in {args.out}")
    if total:
        print(f"warning: {total} results could not be matched to a path", file=sys.stderr)
    return 0


def run_metrics(args: argparse.Namespace) -> int:
    if args.metric == "false-positives":
        result = metrics.false_positive_check(
            expected.read_csv(args.expected), metrics.read_findings(args.findings)
        )
    elif args.metric == "dedup":
        result = metrics.merge_precision_recall(
            metrics.read_groups(args.labeled), metrics.read_groups(args.predicted)
        )
    elif args.metric == "severity":
        result = metrics.severity_agreement(metrics.read_severity(args.cases))
    elif args.metric == "severity-baseline":
        result = metrics.severity_baseline(metrics.read_severity_baseline(args.cases))
    else:
        result = metrics.cost_and_time(metrics.read_costs(args.findings))
    print(json.dumps(result, indent=2))
    return 0


def run_pilot(args: argparse.Namespace) -> int:
    folder = args.dir or sources.data_dir() / "pilot"
    checkouts = {name: sources.data_dir() / "neutral" / name for name in pilot.DATASETS}
    if args.step == "sample":
        return _pilot_sample(args, folder, checkouts)
    return _pilot_run(args, folder, checkouts)


def _pilot_sample(args: argparse.Namespace, folder: Path, checkouts: dict[str, Path]) -> int:
    by_dataset: dict[str, dict[str, list]] = {}
    for item in args.sarif:
        left, file = _pair(item, "--sarif", "DATASET:TOOL=FILE")
        dataset, _, tool = left.partition(":")
        if dataset not in pilot.DATASETS or not tool:
            raise SystemExit(f"--sarif needs DATASET:TOOL=FILE with one of {pilot.DATASETS}")
        found = pilot.read_findings(tool, Path(file), checkouts[dataset])
        by_dataset.setdefault(dataset, {})[tool] = found
        print(f"{dataset} {tool}: {len(found)} findings")
    rng = random.Random(args.seed)
    chosen = []
    for dataset in sorted(by_dataset):
        cases = expected.read_csv(sources.data_dir() / "answers" / dataset / "expected.csv")
        flagging = pilot.count_flagging(by_dataset[dataset], cases)
        print(f"{dataset}: {flagging} findings flag a case")
        rows = pilot.choose(dataset, by_dataset[dataset], cases, args.per_dataset, rng)
        count = pilot.write_expected(rows, cases, folder / f"expected-{dataset}.csv")
        print(f"{dataset}: {len(rows)} findings from {count} cases")
        chosen.extend(rows)
    pilot.write_sample(chosen, folder / "sample.csv")
    print(f"{len(chosen)} findings in {folder / 'sample.csv'}")
    return 0


def _pilot_run(args: argparse.Namespace, folder: Path, checkouts: dict[str, Path]) -> int:
    from app.llm import Budget, LLMClient, load_catalog, load_template, providers_from_env
    from app.llm.cache import InMemoryResponseCache
    from app.llm.call_log import InMemoryCallLog

    sample = pilot.read_sample(folder / "sample.csv")
    template = load_template(pilot.TEMPLATE)
    catalog = load_catalog()
    budget = Budget(args.budget)
    if args.dry_run:
        client = LLMClient({}, catalog, budget, InMemoryCallLog(), InMemoryResponseCache())
        costs = pilot.worst_cases(
            sample, checkouts, client, template, args.model, args.limit, args.effort
        )
        print(
            f"{len(costs)} calls to {args.model}: worst case ${max(costs):.6f} for one call, "
            f"${sum(costs):.6f} for all, against a ${budget.limit_usd} budget"
        )
        return 0

    from app.llm.postgres import PostgresCallStore

    store = PostgresCallStore()
    client = LLMClient(providers_from_env(catalog), catalog, budget, store, store)
    results = folder / args.model / "results.csv"
    count = pilot.triage(
        sample, checkouts, client, template, args.model, results, args.limit, args.effort
    )
    pilot.split_by_dataset(results)
    print(f"{count} findings triaged, ${budget.spent_usd} spent, results in {results}")
    return 0


def _pair(item: str, option: str, form: str) -> tuple[str, str]:
    left, _, right = item.partition("=")
    if not left or not right:
        raise SystemExit(f"{option} needs {form}, got {item!r}")
    return left, right


def _not_fetched(chosen: list[sources.Source]) -> bool:
    """Say which sources aren't checked out at their pinned commit, for example after a pin
    changed. Their files would not match the commit that the output records."""
    missing = [source for source in chosen if not sources.is_fetched(source)]
    for source in missing:
        print(
            f"{source.name}: not checked out at {source.commit[:12]}, "
            f"run: python -m app.eval fetch {source.name}",
            file=sys.stderr,
        )
    return bool(missing)


def _sources(names: list[str]) -> list[sources.Source]:
    every = {source.name: source for source in sources.load_sources()}
    unknown = [name for name in names if name not in every]
    if unknown:
        raise SystemExit(f"unknown sources {unknown}, known: {sorted(every)}")
    return [every[name] for name in names] if names else list(every.values())


COMMANDS = {
    "fetch": run_fetch,
    "expected": run_expected,
    "neutral": run_neutral,
    "findings": run_findings,
    "cves": run_cves,
    "metrics": run_metrics,
    "pilot": run_pilot,
}

if __name__ == "__main__":
    sys.exit(main())
