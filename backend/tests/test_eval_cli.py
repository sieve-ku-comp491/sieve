"""The command line of the evaluation harness."""

import json

from app.eval.__main__ import main


def test_metrics_command_prints_json(tmp_path, capsys):
    path = tmp_path / "costs.csv"
    path.write_text("finding_id,cost_usd,seconds\nf1,0.5,10\n")
    assert main(["metrics", "cost", "--findings", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["total_cost_usd"] == "0.5"


def test_expected_needs_fetch_first(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SIEVE_EVAL_DIR", str(tmp_path))
    assert main(["expected"]) == 1
    assert "not fetched" in capsys.readouterr().err
