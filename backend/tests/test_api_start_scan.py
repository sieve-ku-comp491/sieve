"""POST /scans: the scope check in the API (requirement F2, acceptance tests 1 to 3), and the
scan and job it queues.

The tests without a database point DATABASE_URL at a port where nothing listens. A request that
reached the database would fail with a server error, so a refusal with 403 or 422 shows that the
check ran before anything was stored."""

from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient

from app.api.deps import Settings
from app.main import create_app

TOKEN = "test-token"
PYGOAT = "https://github.com/adeyosemanputra/pygoat"
NO_DATABASE = "postgresql://nobody@127.0.0.1:9/nothing?connect_timeout=1"


def scope(tmp_path: Path, text: str | None = None) -> Path:
    path = tmp_path / "scope.toml"
    path.write_text(
        text or f'[[repository]]\nurl = "{PYGOAT}"\nreason = "OWASP PyGoat"\n', encoding="utf-8"
    )
    return path


def client(scope_file: Path, database_url: str | None = NO_DATABASE) -> TestClient:
    settings = Settings(
        token=TOKEN, database_url=database_url, data_dir=Path("/data"), scope_file=scope_file
    )
    return TestClient(
        create_app(settings),
        base_url="http://localhost",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )


def test_f2_1_a_repository_not_in_the_scope_file_is_refused_naming_it_and_the_file(tmp_path):
    path = scope(tmp_path)
    response = client(path).post(
        "/scans", json={"repo_url": "https://github.com/OWASP/NodeGoat", "commit": "master"}
    )
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert detail == (
        f"https://github.com/OWASP/NodeGoat is not in the scope file {path}. Sieve scans only "
        "the repositories listed there."
    )


@pytest.mark.parametrize(
    ("url", "problem"),
    [
        ("https://user:token@github.com/adeyosemanputra/pygoat", "user name or password"),
        ("http://github.com/adeyosemanputra/pygoat", "must start with https://"),
    ],
)
def test_f2_2_urls_that_break_the_rules_are_refused(tmp_path, url, problem):
    response = client(scope(tmp_path)).post("/scans", json={"repo_url": url})
    assert response.status_code == 422
    assert problem in response.json()["detail"]
    assert "token" not in response.text


def test_f2_2_another_repository_of_the_same_owner_is_refused(tmp_path):
    response = client(scope(tmp_path)).post(
        "/scans", json={"repo_url": "https://github.com/adeyosemanputra/other"}
    )
    assert response.status_code == 403


def test_f2_3_a_scope_file_that_fails_to_load_refuses_every_scan_naming_the_entry(tmp_path):
    path = scope(tmp_path, f'[[repository]]\nurl = "{PYGOAT}"\n')
    response = client(path).post("/scans", json={"repo_url": PYGOAT})
    assert response.status_code == 500
    assert response.json()["detail"] == (
        f"the scope file {path}, entry 1 ({PYGOAT}): no reason, say why we may scan this repository"
    )


def test_a_commit_that_could_be_an_option_is_refused(tmp_path):
    response = client(scope(tmp_path)).post(
        "/scans", json={"repo_url": PYGOAT, "commit": "--upload-pack=touch x"}
    )
    assert response.status_code == 422
    assert "is not a commit hash, branch or tag name" in response.json()["detail"]


def test_a_repository_in_scope_needs_the_database(tmp_path):
    response = client(scope(tmp_path), database_url=None).post("/scans", json={"repo_url": PYGOAT})
    assert response.status_code == 503


def test_the_token_is_needed(tmp_path):
    test_client = client(scope(tmp_path))
    response = test_client.post("/scans", json={"repo_url": PYGOAT}, headers={"Authorization": ""})
    assert response.status_code == 401


def count(database, sql: str, *params) -> int:
    with psycopg.connect(database) as conn:
        return conn.execute(sql, params).fetchone()[0]


def test_a_repository_in_scope_is_queued_with_its_job(database, tmp_path):
    response = client(scope(tmp_path), database).post(
        "/scans", json={"repo_url": "https://GitHub.com/adeyosemanputra/pygoat.git/"}
    )
    assert response.status_code == 202, response.text
    started = response.json()
    assert (started["repo_url"], started["status"]) == (PYGOAT, "queued")
    with psycopg.connect(database) as conn:
        scan = conn.execute(
            "SELECT repo_url, commit_sha, requested_ref, status FROM scans WHERE id = %s",
            (started["scan_id"],),
        ).fetchone()
        job = conn.execute(
            "SELECT kind, status, payload FROM jobs WHERE id = %s", (started["job_id"],)
        ).fetchone()
    assert scan == (PYGOAT, None, "HEAD", "queued")
    assert job == ("scan", "queued", {"scan_id": started["scan_id"]})


def test_a_full_hash_is_stored_as_the_commit_and_anything_else_as_the_ref(database, tmp_path):
    test_client = client(scope(tmp_path), database)
    full = test_client.post(
        "/scans", json={"repo_url": PYGOAT, "commit": "2AA4CC14F251E4A780E94E200AED6B36A5B15C21"}
    ).json()
    short = test_client.post("/scans", json={"repo_url": PYGOAT, "commit": "2aa4cc1"}).json()
    sql = "SELECT commit_sha, requested_ref FROM scans WHERE id = %s"
    with psycopg.connect(database) as conn:
        assert conn.execute(sql, (full["scan_id"],)).fetchone() == (
            "2aa4cc14f251e4a780e94e200aed6b36a5b15c21",
            None,
        )
        assert conn.execute(sql, (short["scan_id"],)).fetchone() == (None, "2aa4cc1")


def test_f2_1_a_refused_scan_leaves_no_scan_and_no_job(database, tmp_path):
    scans_before = count(database, "SELECT count(*) FROM scans")
    jobs_before = count(database, "SELECT count(*) FROM jobs")
    response = client(scope(tmp_path), database).post(
        "/scans", json={"repo_url": "https://github.com/OWASP/NodeGoat"}
    )
    assert response.status_code == 403
    assert count(database, "SELECT count(*) FROM scans") == scans_before
    assert count(database, "SELECT count(*) FROM jobs") == jobs_before
