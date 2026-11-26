import os
import uuid
from pathlib import Path

import psycopg
import pytest
from psycopg.conninfo import make_conninfo

from app.adapters import SemgrepAdapter
from app.checkout import CheckoutReader
from app.dedup import ScanFinding
from app.runner import SarifValidator
from app.runner.runner import PluginRun
from app.store import migrate

SERVER_URL = os.environ.get("SIEVE_TEST_DATABASE_URL")
SCHEMA = f"test_{uuid.uuid4().hex[:12]}"
DATABASE_URL = SERVER_URL and make_conninfo(SERVER_URL, options=f"-c search_path={SCHEMA}")
if DATABASE_URL:
    # Test modules that read the variable themselves, such as test_llm_postgres.py, then use
    # this run's schema too, and leave nothing in the database's public schema.
    os.environ["SIEVE_TEST_DATABASE_URL"] = DATABASE_URL


@pytest.fixture(scope="session", autouse=True)
def test_schema():
    """A schema of its own for this test run in the test database, made before the first test
    and dropped after the last. Nothing happens without SIEVE_TEST_DATABASE_URL."""
    if not SERVER_URL:
        yield
        return
    with psycopg.connect(SERVER_URL, autocommit=True) as conn:
        conn.execute(f'CREATE SCHEMA "{SCHEMA}"')
    yield
    with psycopg.connect(SERVER_URL, autocommit=True) as conn:
        conn.execute(f'DROP SCHEMA "{SCHEMA}" CASCADE')


ADAPTER_FIXTURE = Path(__file__).parent / "adapter_fixture"


@pytest.fixture(scope="session")
def pygoat_findings() -> list[ScanFinding]:
    """The nine Semgrep results on PyGoat in tests/adapter_fixture, read with the Semgrep
    adapter, as the grouping steps see them, with IDs f0 to f8."""
    run = PluginRun(
        "run-0021",
        "scan-0007",
        "semgrep",
        "sieve-plugin-semgrep:1.183.0-16b9e6d",
        "1.183.0",
        "semgrep-rules@16b9e6d",
    )
    sarif = SarifValidator().validate(ADAPTER_FIXTURE / "semgrep-pygoat.sarif")
    reader = CheckoutReader(ADAPTER_FIXTURE / "pygoat")
    return [
        ScanFinding(
            finding_id=f"f{i}",
            tool=f.tool,
            rule_id=f.rule_id,
            cwe=tuple(f.cwe),
            message=f.message,
            tool_severity=f.tool_severity,
            file=f.location.file,
            start_line=f.location.start_line,
            end_line=f.location.end_line,
            rule_description=f.rule_description,
            snippet=f.location.snippet,
        )
        for i, f in enumerate(SemgrepAdapter().to_findings(sarif, run, reader).findings)
    ]


@pytest.fixture(scope="session")
def database(test_schema):
    """Connection info for the test run's schema, with every migration applied. Tests that use
    it skip without SIEVE_TEST_DATABASE_URL."""
    if not DATABASE_URL:
        pytest.skip("set SIEVE_TEST_DATABASE_URL to a throwaway PostgreSQL database")
    migrate(DATABASE_URL)
    return DATABASE_URL
