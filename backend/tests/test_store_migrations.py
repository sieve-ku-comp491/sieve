"""The migrations against PostgreSQL: every table and column of docs/database.md, and the keys
the document describes."""

import re
import uuid
from pathlib import Path

import psycopg
import pytest

from app.store import MigrationError, migrate
from app.store.migrate import migrations

DATABASE_DOC = Path(__file__).resolve().parents[2] / "docs" / "database.md"

# The type names of the ER diagram, as information_schema.columns.data_type gives them.
TYPES = {
    "uuid": "uuid",
    "text": "text",
    "text_array": "ARRAY",
    "int": "integer",
    "bigint": "bigint",
    "bool": "boolean",
    "numeric": "numeric",
    "jsonb": "jsonb",
    "timestamptz": "timestamp with time zone",
}


def documented_tables() -> dict[str, dict[str, str]]:
    """{table: {column: type}} from the ER diagram in docs/database.md."""
    text = DATABASE_DOC.read_text(encoding="utf-8")
    diagram = text.split("erDiagram", 1)[1].split("```", 1)[0]
    tables = {}
    for name, body in re.findall(r"^  (\w+) \{\n(.*?)^  \}", diagram, re.M | re.S):
        columns = {}
        for line in body.splitlines():
            kind, column = line.split()[:2]
            columns[column] = TYPES[kind]
        tables[name] = columns
    return tables


def test_the_er_diagram_is_read():
    tables = documented_tables()
    assert len(tables) == 16
    assert tables["locations"]["id"] == "bigint"
    assert tables["scans"]["languages"] == "ARRAY"


def test_every_table_and_column_in_docs_database_md_exists(database):
    with psycopg.connect(database) as conn:
        rows = conn.execute(
            "SELECT table_name, column_name, data_type FROM information_schema.columns"
            " WHERE table_schema = current_schema()"
        ).fetchall()
    actual: dict[str, dict[str, str]] = {}
    for table, column, data_type in rows:
        actual.setdefault(table, {})[column] = data_type
    actual.pop("schema_migrations")
    actual.pop("finding_states")
    assert actual == documented_tables()


def test_migrating_again_changes_nothing(database):
    assert migrate(database) == []


def test_migration_files_are_numbered_without_gaps(tmp_path):
    names = [m.path.name for m in migrations()]
    assert names[:4] == [
        "0001_scan_side.sql",
        "0002_llm_calls.sql",
        "0003_review_side.sql",
        "0004_finding_states.sql",
    ]
    (tmp_path / "0001_a.sql").write_text("", encoding="utf-8")
    (tmp_path / "0003_c.sql").write_text("", encoding="utf-8")
    with pytest.raises(MigrationError):
        migrations(tmp_path)


def insert_scan(conn) -> uuid.UUID:
    return conn.execute(
        "INSERT INTO scans (repo_url, commit_sha) VALUES ('https://example.org/r', %s)"
        " RETURNING id",
        ("a" * 40,),
    ).fetchone()[0]


def insert_finding(conn, scan_id, fingerprint: str, group_id=None) -> uuid.UUID:
    run_id = conn.execute(
        "INSERT INTO analyzer_runs (scan_id, plugin, image, tool_version, rules_version)"
        " VALUES (%s, %s, 'img:1', '1', 'r') ON CONFLICT (scan_id, plugin) DO UPDATE"
        " SET image = excluded.image RETURNING id",
        (scan_id, "semgrep"),
    ).fetchone()[0]
    return conn.execute(
        "INSERT INTO findings (scan_id, run_id, group_id, tool, tool_version, rule_id, message,"
        " tool_severity, file, start_line, end_line, fingerprint, context_hash, raw)"
        " VALUES (%s, %s, %s, 'semgrep', '1', 'r', 'm', 'warning', 'a.py', 1, 1, %s, 'c1:x',"
        " '{}') RETURNING id",
        (scan_id, run_id, group_id, fingerprint),
    ).fetchone()[0]


def test_llm_calls_job_id_references_jobs(database):
    with psycopg.connect(database) as conn, pytest.raises(psycopg.errors.ForeignKeyViolation):
        conn.execute(
            "INSERT INTO llm_calls (job_id, provider, model, messages, cache_key, max_tokens)"
            " VALUES (%s, 'anthropic', 'm', '[]', 'test:fk', 10)",
            (uuid.uuid4(),),
        )


def test_a_fingerprint_is_unique_within_a_scan(database):
    with psycopg.connect(database) as conn, pytest.raises(psycopg.errors.UniqueViolation):
        scan_id = insert_scan(conn)
        insert_finding(conn, scan_id, "v1:same")
        insert_finding(conn, scan_id, "v1:same")


def test_a_finding_can_only_join_a_group_of_its_own_scan(database):
    with psycopg.connect(database) as conn, pytest.raises(psycopg.errors.ForeignKeyViolation):
        group_id = conn.execute(
            "INSERT INTO duplicate_groups (scan_id, method, rule, reason)"
            " VALUES (%s, 'rule', 'same_line', 'same line') RETURNING id",
            (insert_scan(conn),),
        ).fetchone()[0]
        insert_finding(conn, insert_scan(conn), "v1:other", group_id)


def test_a_group_representative_must_be_a_member_at_commit(database):
    with psycopg.connect(database) as conn:
        scan_id = insert_scan(conn)
        outsider = insert_finding(conn, scan_id, "v1:outsider")
        conn.execute(
            "INSERT INTO duplicate_groups (scan_id, representative_finding_id, method, rule,"
            " reason) VALUES (%s, %s, 'rule', 'same_line', 'same line')",
            (scan_id, outsider),
        )
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            conn.commit()


def test_a_hidden_finding_needs_a_carried_review(database):
    with psycopg.connect(database) as conn, pytest.raises(psycopg.errors.CheckViolation):
        finding_id = insert_finding(conn, insert_scan(conn), "v1:hidden")
        conn.execute("UPDATE findings SET hidden = true WHERE id = %s", (finding_id,))
