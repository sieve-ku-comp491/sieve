"""python -m app.dedup group <scan ID>, or python -m app.dedup csv <scan ID> (see --help).

Both connect to DATABASE_URL. group runs the rule step and the text-similarity step, both with
the tree-sitter function lookup on the scan's checkout, which the worker keeps in
SIEVE_DATA_DIR/scans/<scan ID>/src (/data by default). When the checkout is gone, both group by
the same file and nearby lines instead. The LLM step needs a triage run's budget, so it runs only
in triage.
"""

import argparse
import os
import sys
from pathlib import Path

from app.checkout import CheckoutReader
from app.context.functions import TreeSitterFunctionLookup
from app.dedup.functions import FunctionLookup
from app.dedup.groups import GroupingError
from app.dedup.similarity import SimilarityStep
from app.dedup.store import group_scan, write_groups_csv


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.dedup")
    commands = parser.add_subparsers(dest="command", required=True)
    group = commands.add_parser(
        "group", help="group a scan's duplicate findings by the rules and by text similarity"
    )
    group.add_argument("scan_id")
    out = commands.add_parser(
        "csv", help="write a scan's groups as the CSV of python -m app.eval metrics dedup"
    )
    out.add_argument("scan_id")
    out.add_argument("--out", type=Path, help="the file to write, default standard output")
    args = parser.parse_args(argv)

    conninfo = os.environ.get("DATABASE_URL")
    if not conninfo:
        print("DATABASE_URL is not set", file=sys.stderr)
        return 2
    if args.command == "group":
        try:
            lookup = checkout_lookup(args.scan_id)
            groups = group_scan(
                conninfo, args.scan_id, lookup, later_steps=[SimilarityStep(lookup)]
            )
        except GroupingError as error:
            print(error, file=sys.stderr)
            return 1
        members = sum(len(g.members) for g in groups)
        print(f"groups: {len(groups)}, with {members} findings")
        for g in groups:
            print(f"  {g.group_id} {g.rule}, {len(g.members)} findings: {g.reason}")
        return 0
    if args.out is None:
        write_groups_csv(conninfo, args.scan_id, sys.stdout)
    else:
        with args.out.open("w", encoding="utf-8", newline="") as handle:
            count = write_groups_csv(conninfo, args.scan_id, handle)
        print(f"{count} findings written to {args.out}")
    return 0


def checkout_lookup(scan_id: str) -> FunctionLookup | None:
    """The function lookup on the scan's checkout, or None, with a note on standard error, when
    the checkout is gone."""
    checkout = Path(os.environ.get("SIEVE_DATA_DIR", "/data")) / "scans" / scan_id / "src"
    if not checkout.is_dir():
        print(
            f"no checkout at {checkout}, grouping by the same file and nearby lines",
            file=sys.stderr,
        )
        return None
    return TreeSitterFunctionLookup(CheckoutReader(checkout))


if __name__ == "__main__":
    sys.exit(main())
