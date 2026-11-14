"""The command line of the evaluation harness."""

import json
import subprocess

import pytest

from app.eval.__main__ import main


def test_metrics_command_prints_json(tmp_path, capsys):
    path = tmp_path / "costs.csv"
    path.write_text("finding_id,cost_usd,seconds\nf1,0.5,10\n")
    assert main(["metrics", "cost", "--findings", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["total_cost_usd"] == "0.5"


@pytest.mark.parametrize(
    "command",
    [["expected"], ["neutral", "benchmark-python"], ["neutral", "benchmark-java"], ["cves"]],
)
def test_commands_need_fetch_first(command, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SIEVE_EVAL_DIR", str(tmp_path))
    assert main(command) == 1
    assert "run: python -m app.eval fetch" in capsys.readouterr().err
    assert not (tmp_path / "expected").exists() and not (tmp_path / "answers").exists()


def test_a_checkout_at_another_commit_counts_as_not_fetched(tmp_path, monkeypatch, capsys):
    # The folder exists, as after a pin change, but HEAD is some other commit.
    monkeypatch.setenv("SIEVE_EVAL_DIR", str(tmp_path))
    old = tmp_path / "sources/benchmark-python"
    old.mkdir(parents=True)
    git = ["git", "-C", str(old), "-c", "user.name=t", "-c", "user.email=t@localhost"]
    subprocess.run([*git, "init", "--quiet"], check=True)
    subprocess.run([*git, "commit", "--quiet", "--allow-empty", "-m", "old"], check=True)
    assert main(["neutral", "benchmark-python"]) == 1
    assert "benchmark-python: not checked out at f1291485808b" in capsys.readouterr().err
