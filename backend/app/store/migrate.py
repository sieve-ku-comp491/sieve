"""Creates and updates the tables of the findings store (docs/database.md).

Migrations are numbered SQL files in migrations/, applied in order. schema_migrations records
which ones a database has. All pending migrations run in one transaction under an advisory lock,
so the API and the worker can both start at the same time, and a failed migration leaves the
database as it was.
"""

import re
from dataclasses import dataclass
from pathlib import Path

import psycopg

MIGRATIONS_DIR = Path(__file__).with_name("migrations")
FILE_NAME = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")
# Any fixed number works, as long as nothing else in Sieve takes the same advisory lock.
LOCK_KEY = 491_0054

CREATE_HISTORY = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version integer PRIMARY KEY,
    name text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
)
"""


class MigrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    path: Path

    def sql(self) -> str:
        return self.path.read_text(encoding="utf-8")


def migrations(folder: Path = MIGRATIONS_DIR) -> list[Migration]:
    """The migrations in folder, numbered 1, 2, 3 and so on without gaps."""
    found = []
    for path in folder.glob("*.sql"):
        match = FILE_NAME.match(path.name)
        if not match:
            raise MigrationError(f"{path.name} is not named like 0001_name.sql")
        found.append(Migration(int(match.group(1)), match.group(2), path))
    found.sort(key=lambda m: m.version)
    if [m.version for m in found] != list(range(1, len(found) + 1)):
        raise MigrationError("migration numbers must run 1, 2, 3 and so on without gaps")
    return found


def migrate(conninfo: str, folder: Path = MIGRATIONS_DIR) -> list[str]:
    """Applies the migrations the database doesn't have yet, and returns their file names."""
    pending = migrations(folder)
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (LOCK_KEY,))
        conn.execute(CREATE_HISTORY)
        applied = {row[0] for row in conn.execute("SELECT version FROM schema_migrations")}
        if applied - {m.version for m in pending}:
            raise MigrationError("the database has migrations that this code doesn't know")
        done = []
        for migration in pending:
            if migration.version in applied:
                continue
            conn.execute(migration.sql())
            conn.execute(
                "INSERT INTO schema_migrations (version, name) VALUES (%s, %s)",
                (migration.version, migration.name),
            )
            done.append(migration.path.name)
    return done
