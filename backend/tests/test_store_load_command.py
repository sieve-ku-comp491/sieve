"""python -m app.store load-sarif: the scope check on --repo-url, with the eval: URL of an
evaluation run as the one exception (docs/evaluation.md)."""

from pathlib import Path

import psycopg
import pytest

from app.scan import OutOfScope, ScopeError, UrlError, url_to_load
from app.store.__main__ import main

FIXTURE = Path(__file__).parent / "adapter_fixture"
MANIFEST = Path(__file__).resolve().parents[2] / "plugins" / "semgrep" / "plugin.toml"
PYGOAT = "https://github.com/adeyosemanputra/pygoat"
COMMIT = "2aa4cc14f251e4a780e94e200aed6b36a5b15c21"
NO_DATABASE = "postgresql://nobody@127.0.0.1:9/nothing?connect_timeout=1"


@pytest.fixture
def scope_file(tmp_path) -> Path:
    path = tmp_path / "scope.toml"
    path.write_text(
        f'[[repository]]\nurl = "{PYGOAT}"\nreason = "OWASP PyGoat"\n', encoding="utf-8"
    )
    return path


@pytest.mark.parametrize(
    "url", ["eval:benchmark-java/t6.4", "eval:benchmark-python/pilot-2", "eval:benchmark-java/0"]
)
def test_an_evaluation_url_is_stored_as_it_is_without_the_scope_file(tmp_path, url):
    assert url_to_load(url, tmp_path / "missing.toml") == url


@pytest.mark.parametrize(
    "url",
    [
        "eval:benchmark-python",
        "eval:benchmark-python/",
        "eval:benchmark-go/t6.4",
        "eval:benchmark-java/T6.4",
        "eval:benchmark-java/t6.4/x",
        "eval:benchmark-java/-t6.4",
        "eval:benchmark-java/t6.4\n",
        "eval:benchmark-java/" + "a" * 65,
        "eval:https://github.com/adeyosemanputra/pygoat",
    ],
)
def test_other_evaluation_urls_are_refused(scope_file, url):
    with pytest.raises(UrlError, match="eval:benchmark-java/<run> or eval:benchmark-python/<run>"):
        url_to_load(url, scope_file)


def test_a_repository_in_the_scope_file_is_stored_normalized(scope_file):
    assert url_to_load("https://GitHub.com/adeyosemanputra/pygoat.git/", scope_file) == PYGOAT


def test_a_repository_outside_the_scope_file_is_refused_naming_it_and_the_file(scope_file):
    with pytest.raises(OutOfScope) as refused:
        url_to_load("https://github.com/OWASP/NodeGoat", scope_file)
    assert str(refused.value) == (
        f"https://github.com/OWASP/NodeGoat is not in the scope file {scope_file}. Sieve scans "
        "only the repositories listed there."
    )


def test_a_repository_url_needs_a_scope_file_that_loads(tmp_path):
    with pytest.raises(ScopeError, match="can't read the scope file"):
        url_to_load(PYGOAT, tmp_path / "missing.toml")


def load_args(repo_url: str) -> list[str]:
    return [
        "load-sarif",
        "--manifest", str(MANIFEST),
        "--sarif", str(FIXTURE / "semgrep-pygoat.sarif"),
        "--checkout", str(FIXTURE / "pygoat"),
        "--repo-url", repo_url,
        "--commit", COMMIT,
    ]  # fmt: skip


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("https://github.com/OWASP/NodeGoat", "is not in the scope file"),
        ("http://github.com/adeyosemanputra/pygoat", "must start with https://"),
        ("eval:benchmark-ruby/t6.4", "eval:benchmark-java/<run>"),
    ],
)
def test_the_command_refuses_before_it_touches_the_database(
    scope_file, tmp_path, monkeypatch, capsys, url, message
):
    # Nothing listens on the database's port, so a refusal shows that the check ran first.
    monkeypatch.setenv("DATABASE_URL", NO_DATABASE)
    monkeypatch.setenv("SIEVE_SCOPE_FILE", str(scope_file))
    monkeypatch.setenv("SIEVE_DATA_DIR", str(tmp_path / "data"))
    assert main(load_args(url)) == 1
    assert message in capsys.readouterr().err
    assert not (tmp_path / "data").exists()


@pytest.mark.parametrize(
    ("url", "stored"),
    [
        ("https://GitHub.com/adeyosemanputra/pygoat.git", PYGOAT),
        ("eval:benchmark-python/t6.4", "eval:benchmark-python/t6.4"),
    ],
)
def test_the_command_stores_the_scan_under_the_checked_url(
    database, scope_file, tmp_path, monkeypatch, capsys, url, stored
):
    monkeypatch.setenv("DATABASE_URL", database)
    monkeypatch.setenv("SIEVE_SCOPE_FILE", str(scope_file))
    monkeypatch.setenv("SIEVE_DATA_DIR", str(tmp_path / "data"))
    assert main(load_args(url)) == 0
    scan_id = capsys.readouterr().out.split(",")[0].removeprefix("scan ")
    with psycopg.connect(database) as conn:
        row = conn.execute(
            "SELECT repo_url, status FROM scans WHERE id = %s", (scan_id,)
        ).fetchone()
    assert row == (stored, "completed")


def test_several_runs_on_one_checkout_are_stored_as_one_scan(
    database, scope_file, tmp_path, monkeypatch, capsys
):
    # The Semgrep and Bandit fixtures are runs on the same PyGoat files, with 9 results each
    # (tests/adapter_fixture/README.md).
    monkeypatch.setenv("DATABASE_URL", database)
    monkeypatch.setenv("SIEVE_SCOPE_FILE", str(scope_file))
    monkeypatch.setenv("SIEVE_DATA_DIR", str(tmp_path / "data"))
    bandit = ["--manifest", str(MANIFEST.parents[1] / "bandit" / "plugin.toml")]
    bandit += ["--sarif", str(FIXTURE / "bandit-pygoat.sarif")]
    assert main(load_args("eval:benchmark-python/two-runs") + bandit) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 2 and all(line.endswith(": 9 findings stored") for line in lines)
    with psycopg.connect(database) as conn:
        rows = conn.execute(
            "SELECT s.status, s.languages, r.plugin, r.status, count(f.id) FROM scans s"
            " JOIN analyzer_runs r ON r.scan_id = s.id JOIN findings f ON f.run_id = r.id"
            " WHERE s.repo_url = 'eval:benchmark-python/two-runs'"
            " GROUP BY s.id, r.id ORDER BY r.plugin"
        ).fetchall()
    assert rows == [
        ("completed", ["python"], "bandit", "succeeded", 9),
        ("completed", ["python"], "semgrep", "succeeded", 9),
    ]


def test_each_manifest_needs_its_sarif_file(monkeypatch, capsys):
    monkeypatch.setenv("DATABASE_URL", NO_DATABASE)
    with pytest.raises(SystemExit):
        main(load_args("eval:benchmark-python/t6.4") + ["--manifest", str(MANIFEST)])
    assert "once per --manifest" in capsys.readouterr().err
