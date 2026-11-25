"""python -m app.store migrate, or python -m app.store load-sarif ... (see --help).

Both connect to DATABASE_URL. load-sarif copies the checkout and the SARIF file into
SIEVE_DATA_DIR, /data by default. It checks --repo-url against the scope file in
SIEVE_SCOPE_FILE, as POST /scans does, except for the eval: URL of an evaluation run.
"""

import argparse
import os
import sys
from pathlib import Path

from app.scan.scope import DEFAULT_SCOPE_FILE, OutOfScope, ScopeError, UrlError, url_to_load
from app.store.load import SavedRun, load_runs
from app.store.migrate import migrate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.store")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("migrate", help="create or update the tables")
    load = commands.add_parser(
        "load-sarif",
        help="store saved SARIF files of plug-in runs on one checkout as a completed scan",
    )
    load.add_argument(
        "--manifest",
        type=Path,
        action="append",
        required=True,
        help="the plug-in's plugin.toml. Give --manifest and --sarif once per run.",
    )
    load.add_argument(
        "--sarif",
        type=Path,
        action="append",
        required=True,
        help="the SARIF file the plug-in wrote, in the order of --manifest",
    )
    load.add_argument("--checkout", type=Path, required=True, help="the files that were scanned")
    load.add_argument(
        "--repo-url",
        required=True,
        help="a repository in the scope file, or eval:benchmark-java/<run> or "
        "eval:benchmark-python/<run> for an evaluation run",
    )
    load.add_argument("--commit", required=True, help="the full 40-character commit hash")
    load.add_argument(
        "--image-digest",
        action="append",
        help="the digest of the plug-in image that ran, once per run if given",
    )
    args = parser.parse_args(argv)
    if args.command == "load-sarif":
        digests = args.image_digest or [None] * len(args.manifest)
        if not len(args.manifest) == len(args.sarif) == len(digests):
            parser.error("give --sarif, and --image-digest if any, once per --manifest")
        scope_file = Path(os.environ.get("SIEVE_SCOPE_FILE", DEFAULT_SCOPE_FILE))
        try:
            repo_url = url_to_load(args.repo_url, scope_file)
        except (UrlError, ScopeError, OutOfScope) as error:
            print(error, file=sys.stderr)
            return 1

    conninfo = os.environ.get("DATABASE_URL")
    if not conninfo:
        print("DATABASE_URL is not set", file=sys.stderr)
        return 2
    if args.command == "migrate":
        applied = migrate(conninfo)
        print("applied " + ", ".join(applied) if applied else "the database is up to date")
        return 0

    data_dir = Path(os.environ.get("SIEVE_DATA_DIR", "/data"))
    runs = [SavedRun(*run) for run in zip(args.manifest, args.sarif, digests, strict=True)]
    for loaded in load_runs(conninfo, data_dir, runs, args.checkout, repo_url, args.commit):
        print(f"scan {loaded.scan_id}, run {loaded.run_id}: {loaded.findings} findings stored")
        for reason, count in sorted(loaded.dropped.items()):
            print(f"  {count} results dropped: {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
