"""python -m app.store migrate, or python -m app.store load-sarif ... (see --help).

Both connect to DATABASE_URL. load-sarif copies the checkout and the SARIF file into
SIEVE_DATA_DIR, /data by default.
"""

import argparse
import os
import sys
from pathlib import Path

from app.store.load import load_sarif
from app.store.migrate import migrate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.store")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("migrate", help="create or update the tables")
    load = commands.add_parser(
        "load-sarif", help="store a saved SARIF file of one plug-in run as a completed scan"
    )
    load.add_argument("--manifest", type=Path, required=True, help="the plug-in's plugin.toml")
    load.add_argument("--sarif", type=Path, required=True, help="the SARIF file the plug-in wrote")
    load.add_argument("--checkout", type=Path, required=True, help="the files that were scanned")
    load.add_argument("--repo-url", required=True)
    load.add_argument("--commit", required=True, help="the full 40-character commit hash")
    load.add_argument("--image-digest", help="the digest of the plug-in image that ran")
    args = parser.parse_args(argv)

    conninfo = os.environ.get("DATABASE_URL")
    if not conninfo:
        print("DATABASE_URL is not set", file=sys.stderr)
        return 2
    if args.command == "migrate":
        applied = migrate(conninfo)
        print("applied " + ", ".join(applied) if applied else "the database is up to date")
        return 0

    data_dir = Path(os.environ.get("SIEVE_DATA_DIR", "/data"))
    loaded = load_sarif(
        conninfo,
        data_dir,
        args.manifest,
        args.sarif,
        args.checkout,
        args.repo_url,
        args.commit,
        args.image_digest,
    )
    print(f"scan {loaded.scan_id}, run {loaded.run_id}: {loaded.findings} findings stored")
    for reason, count in sorted(loaded.dropped.items()):
        print(f"  {count} results dropped: {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
