"""python -m app.dedup group <scan ID>, or python -m app.dedup csv <scan ID> (see --help).

Both connect to DATABASE_URL. group runs the rule step without a function lookup, so findings
are grouped by the same file and nearby lines until the tree-sitter lookup of T3.3 is there.
"""

import argparse
import os
import sys
from pathlib import Path

from app.dedup.groups import GroupingError
from app.dedup.store import group_scan, write_groups_csv


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.dedup")
    commands = parser.add_subparsers(dest="command", required=True)
    group = commands.add_parser("group", help="group a scan's duplicate findings by the rules")
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
            groups = group_scan(conninfo, args.scan_id)
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


if __name__ == "__main__":
    sys.exit(main())
