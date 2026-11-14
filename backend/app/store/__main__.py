"""python -m app.store migrate (see --help). Connects to DATABASE_URL."""

import argparse
import os
import sys

from app.store.migrate import migrate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.store")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("migrate", help="create or update the tables")
    parser.parse_args(argv)

    conninfo = os.environ.get("DATABASE_URL")
    if not conninfo:
        print("DATABASE_URL is not set", file=sys.stderr)
        return 2
    applied = migrate(conninfo)
    print("applied " + ", ".join(applied) if applied else "the database is up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
