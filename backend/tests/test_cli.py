"""The command-line interface, against the API served by uvicorn on a free local port, so the
CLI's real HTTP requests go through the token and Host checks (requirement F2, test 1 through
the CLI). The progress display is checked with a scripted API."""

import io
import socket
import threading
import time
from pathlib import Path

import psycopg
import pytest
import uvicorn

from app import cli
from app.api.deps import Settings
from app.main import create_app
from app.store import load_sarif

TOKEN = "cli-test-token"
PYGOAT = "https://github.com/adeyosemanputra/pygoat"
FIXTURE = Path(__file__).parent / "adapter_fixture"
MANIFEST = Path(__file__).resolve().parents[2] / "plugins" / "semgrep" / "plugin.toml"
NO_DATABASE = "postgresql://nobody@127.0.0.1:9/nothing?connect_timeout=1"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def serve(tmp_path):
    """Starts the API for a database and returns its URL and the scope file's path."""
    servers = []

    def start(database_url: str) -> tuple[str, Path]:
        scope_file = tmp_path / "scope.toml"
        scope_file.write_text(
            f'[[repository]]\nurl = "{PYGOAT}"\nreason = "OWASP PyGoat"\n', encoding="utf-8"
        )
        settings = Settings(
            token=TOKEN, database_url=database_url, data_dir=tmp_path, scope_file=scope_file
        )
        port = free_port()
        config = uvicorn.Config(
            create_app(settings), host="127.0.0.1", port=port, log_level="warning"
        )
        server = uvicorn.Server(config)
        threading.Thread(target=server.run, daemon=True).start()
        servers.append(server)
        deadline = time.monotonic() + 10
        while not server.started:
            assert time.monotonic() < deadline, "the API did not start"
            time.sleep(0.05)
        return f"http://127.0.0.1:{port}", scope_file

    yield start
    for server in servers:
        server.should_exit = True


def run_cli(*argv: str, token: str = TOKEN) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(list(argv), environ={"SIEVE_API_TOKEN": token}, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def test_f2_1_the_cli_shows_the_refusal_naming_the_repository_and_scope_file(serve):
    api, scope_file = serve(NO_DATABASE)
    code, out, err = run_cli("--api", api, "scan", "https://github.com/OWASP/NodeGoat")
    assert code == 1 and out == ""
    assert err == (
        f"error: https://github.com/OWASP/NodeGoat is not in the scope file {scope_file}. "
        "Sieve scans only the repositories listed there.\n"
    )


def test_f2_1_a_scan_refused_through_the_cli_creates_nothing(database, serve):
    api, _ = serve(database)
    with psycopg.connect(database) as conn:
        before = conn.execute("SELECT (SELECT count(*) FROM scans), (SELECT count(*) FROM jobs)")
        before = before.fetchone()
    code, _, err = run_cli("--api", api, "scan", "https://github.com/adeyosemanputra/other")
    assert code == 1 and "is not in the scope file" in err
    with psycopg.connect(database) as conn:
        after = conn.execute("SELECT (SELECT count(*) FROM scans), (SELECT count(*) FROM jobs)")
        assert after.fetchone() == before


def test_a_url_with_credentials_is_refused_without_echoing_them(serve):
    api, _ = serve(NO_DATABASE)
    code, _, err = run_cli("--api", api, "scan", "https://me:hunter2@github.com/a/b")
    assert code == 1
    assert err == "error: the repository URL must not have a user name or password\n"


def test_the_cli_queues_a_scan_in_scope(database, serve):
    api, _ = serve(database)
    code, out, _ = run_cli("--api", api, "scan", PYGOAT, "--commit", "2aa4cc1", "--no-wait")
    assert code == 0
    scan_id = out.split()[1]
    assert out == f"scan {scan_id} queued: {PYGOAT} at 2aa4cc1\n"
    with psycopg.connect(database) as conn:
        row = conn.execute("SELECT status, requested_ref FROM scans WHERE id = %s", (scan_id,))
        assert row.fetchone() == ("queued", "2aa4cc1")


def test_a_wrong_token_is_reported(serve):
    api, _ = serve(NO_DATABASE)
    code, _, err = run_cli("--api", api, "scan", PYGOAT, token="wrong")
    assert code == 1 and err == "error: missing or wrong API token\n"


def test_an_unreachable_api_is_reported():
    code, _, err = run_cli("--api", f"http://127.0.0.1:{free_port()}", "findings", "x")
    assert code == 1 and err.startswith("error: can't reach the API at http://127.0.0.1:")


def test_findings_lists_every_finding_of_the_scan(database, serve, tmp_path):
    api, _ = serve(database)
    scan_id = load_sarif(
        database,
        tmp_path,
        MANIFEST,
        FIXTURE / "semgrep-pygoat.sarif",
        FIXTURE / "pygoat",
        PYGOAT,
        "2aa4cc14f251e4a780e94e200aed6b36a5b15c21",
    ).scan_id
    code, out, _ = run_cli("--api", api, "findings", scan_id)
    assert code == 0
    lines = out.splitlines()
    assert lines[0] == f"9 findings in scan {scan_id}"
    assert len(lines) == 10
    assert all(" semgrep " in line for line in lines[1:])
    assert all(line.endswith(tuple(f"app.py:{n}" for n in range(1, 400))) for line in lines[1:])

    code, out, _ = run_cli("--api", api, "findings", scan_id, "--tool", "bandit")
    assert (code, out) == (0, f"0 findings in scan {scan_id}\n")


def test_no_token_is_a_usage_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    out, err = io.StringIO(), io.StringIO()
    assert cli.main(["findings", "x"], environ={}, out=out, err=err) == 2
    assert "SIEVE_API_TOKEN" in err.getvalue()


def test_the_token_is_read_from_the_nearest_env_file(tmp_path):
    (tmp_path / ".env").write_text("POSTGRES_DB=sieve\nSIEVE_API_TOKEN='abc123'\n")
    (tmp_path / "backend").mkdir()
    assert cli.find_token({}, tmp_path / "backend") == "abc123"
    assert cli.find_token({"SIEVE_API_TOKEN": "env"}, tmp_path / "backend") == "env"


class ScriptedApi:
    """Answers GET /scans/<id> with the next scan state from a list."""

    def __init__(self, states: list[dict]):
        self.states = states

    def get(self, path: str, params=None) -> dict:
        state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
        base = {"commit_sha": None, "languages": [], "runs": [], "error": None}
        return base | {"finding_count": 0} | state


def run(plugin: str, status: str, reason=None, results=None, files=None) -> dict:
    return {
        "plugin": plugin,
        "status": status,
        "reason": reason,
        "result_count": results,
        "files_scanned": files,
    }


def test_scan_progress_shows_each_change_once():
    sha = "2aa4cc14f251e4a780e94e200aed6b36a5b15c21"
    running = {"status": "running", "commit_sha": sha, "languages": ["python"]}
    api = ScriptedApi(
        [
            {"status": "queued"},
            {"status": "running"},
            running | {"runs": [run("bandit", "pending"), run("semgrep", "running")]},
            running | {"runs": [run("bandit", "pending"), run("semgrep", "running")]},
            running
            | {"runs": [run("bandit", "running"), run("semgrep", "succeeded", None, 153, 446)]},
            running
            | {
                "status": "partial",
                "finding_count": 153,
                "runs": [
                    run("bandit", "failed", "runner_error"),
                    run("semgrep", "succeeded", None, 153, 446),
                ],
            },
        ]
    )
    out = io.StringIO()
    assert cli.follow(api, "s1", out, poll=0) == 1
    assert out.getvalue().splitlines() == [
        "scan running",
        f"commit {sha}, languages: python",
        "  bandit: pending",
        "  semgrep: running",
        "  bandit: running",
        "  semgrep: succeeded, 153 results from 446 files",
        "  bandit: failed (runner_error)",
        "scan partial: 153 findings",
        "list them with: python -m app.cli findings s1",
    ]


def test_a_failed_scan_shows_its_error_without_a_commit_line():
    sha = "0dc3c4f403bea36b83a03c7c07a7d676b939eab3"
    error = f"commit {sha} is not on a branch or tag of https://github.com/a/b"
    api = ScriptedApi(
        [
            {"status": "running", "commit_sha": sha},
            {"status": "failed", "commit_sha": sha, "error": error},
        ]
    )
    out = io.StringIO()
    assert cli.follow(api, "s1", out, poll=0) == 1
    assert out.getvalue().splitlines() == ["scan running", f"scan failed: 0 findings. {error}"]


def test_a_completed_scan_exits_with_0():
    api = ScriptedApi([{"status": "completed", "finding_count": 2}])
    out = io.StringIO()
    assert cli.follow(api, "s1", out, poll=0) == 0
    assert out.getvalue().splitlines()[0] == "scan completed: 2 findings"
