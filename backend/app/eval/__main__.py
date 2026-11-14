"""Command line of the evaluation harness. Run from backend/: python -m app.eval --help"""

import argparse
import json
import sys
from pathlib import Path

from app.eval import expected, metrics, neutral, nvd, sources

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
    cost = kinds.add_parser("cost", help="API cost and time per finding")
    cost.add_argument("--findings", type=Path, required=True)

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
    else:
        result = metrics.cost_and_time(metrics.read_costs(args.findings))
    print(json.dumps(result, indent=2))
    return 0


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
    "cves": run_cves,
    "metrics": run_metrics,
}

if __name__ == "__main__":
    sys.exit(main())
