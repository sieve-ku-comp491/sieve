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


def test_findings_command_writes_one_csv_for_several_tools(tmp_path, capsys):
    rule = {"id": "B602", "properties": {"tags": ["external/cwe/cwe-78"]}}
    hit = {
        "ruleId": "B602",
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}}}],
    }
    for tool in ("semgrep", "bandit"):
        run = {"tool": {"driver": {"name": tool, "rules": [rule]}}, "results": [hit]}
        (tmp_path / f"{tool}.sarif").write_text(json.dumps({"runs": [run]}))
    out = tmp_path / "findings.csv"
    code = main(
        [
            "findings",
            "--sarif",
            f"semgrep={tmp_path}/semgrep.sarif",
            "--sarif",
            f"bandit={tmp_path}/bandit.sarif",
            "--out",
            str(out),
        ]
    )
    assert code == 0
    assert [line.split(",")[0] for line in out.read_text().splitlines()[1:]] == [
        "semgrep-0",
        "bandit-0",
    ]
    assert "semgrep: 1 findings" in capsys.readouterr().out


def test_findings_command_needs_tool_and_file(tmp_path):
    with pytest.raises(SystemExit, match="TOOL=FILE"):
        main(["findings", "--sarif", "no-equals-sign", "--out", str(tmp_path / "x.csv")])


def test_a_root_belongs_to_one_tool(tmp_path):
    rule = {"id": "R", "properties": {"tags": ["external/cwe/cwe-22"]}}

    def sarif(uri, base=None, base_ids=None):
        artifact = {"uri": uri, **({"uriBaseId": base} if base else {})}
        hit = {"ruleId": "R", "locations": [{"physicalLocation": {"artifactLocation": artifact}}]}
        run = {"tool": {"driver": {"name": "t", "rules": [rule]}}, "results": [hit]}
        if base_ids:
            run["originalUriBaseIds"] = base_ids
        return json.dumps({"runs": [run]})

    (tmp_path / "semgrep.sarif").write_text(sarif("/src/a.py"))
    (tmp_path / "spotbugs.sarif").write_text(
        sarif("org/B.java", "1", {"1": {"uri": "file:/build/src/main/java/"}})
    )
    out = tmp_path / "findings.csv"
    code = main(
        [
            "findings",
            "--sarif",
            f"semgrep={tmp_path}/semgrep.sarif",
            "--sarif",
            f"spotbugs={tmp_path}/spotbugs.sarif",
            "--root",
            "spotbugs=/build",
            "--out",
            str(out),
        ]
    )
    assert code == 0
    assert [line.split(",")[1] for line in out.read_text().splitlines()[1:]] == [
        "a.py",
        "src/main/java/org/B.java",
    ]
    with pytest.raises(SystemExit, match="--root needs TOOL=DIR"):
        main(
            ["findings", "--sarif", f"a={tmp_path}/semgrep.sarif", "--root", "x", "--out", str(out)]
        )
