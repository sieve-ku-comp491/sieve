import os
import uuid

import psycopg
import pytest
from psycopg.conninfo import make_conninfo

from app.store import migrate

DATABASE_URL = os.environ.get("SIEVE_TEST_DATABASE_URL")


@pytest.fixture(scope="session")
def database():
    """Connection info for a schema of its own in the test database, with every migration
    applied. The schema is dropped after the tests. Tests that use it skip without
    SIEVE_TEST_DATABASE_URL."""
    if not DATABASE_URL:
        pytest.skip("set SIEVE_TEST_DATABASE_URL to a throwaway PostgreSQL database")
    schema = f"test_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(DATABASE_URL, autocommit=True) as conn:
        conn.execute(f'CREATE SCHEMA "{schema}"')
    conninfo = make_conninfo(DATABASE_URL, options=f"-c search_path={schema}")
    migrate(conninfo)
    yield conninfo
    with psycopg.connect(DATABASE_URL, autocommit=True) as conn:
        conn.execute(f'DROP SCHEMA "{schema}" CASCADE')
