"""The pinned datasets and target applications, and checking them out."""

import subprocess
from pathlib import Path

import pytest

from app.eval.sources import Source, SourceError, checkout_path, fetch, load_sources

REQUIREMENTS = Path(__file__).resolve().parents[2] / "docs/requirements.md"
GIT = ["git", "-c", "user.name=test", "-c", "user.email=test@localhost"]


# The row of each source in the tables of docs/requirements.md.
ROWS = {
    "benchmark-java": "OWASP Benchmark for Java",
    "benchmark-python": "OWASP Benchmark for Python",
    "cwe-bench-java": "CWE-Bench-Java",
    "pygoat": "OWASP PyGoat",
    "webgoat": "OWASP WebGoat",
    "juice-shop": "OWASP Juice Shop",
}


def test_every_source_matches_its_row_in_docs_requirements():
    sources = load_sources()
    assert [s.name for s in sources] == list(ROWS)
    lines = REQUIREMENTS.read_text(encoding="utf-8").splitlines()
    for source in sources:
        (row,) = [line for line in lines if line.startswith(f"| {ROWS[source.name]} |")]
        assert source.version in row, source.name
        # A row pinned by commit must name the same commit. WebGoat and Juice Shop are pinned by
        # tag, and sources.toml keeps the commit the tag pointed to.
        if "commit `" in row:
            assert f"commit `{source.commit[:7]}`" in row, source.name


def test_short_commit_is_refused(tmp_path):
    path = tmp_path / "sources.toml"
    path.write_text('[[source]]\nname="x"\nkind="dataset"\nurl="u"\nversion="1"\ncommit="abc123"\n')
    with pytest.raises(SourceError, match="full 40-character"):
        load_sources(path)


def make_repo(path: Path) -> str:
    path.mkdir()
    subprocess.run([*GIT, "-C", str(path), "init", "--quiet"], check=True)
    (path / "answers.csv").write_text("case,real\n")
    subprocess.run([*GIT, "-C", str(path), "add", "--all"], check=True)
    subprocess.run([*GIT, "-C", str(path), "commit", "--quiet", "-m", "one"], check=True)
    (path / "answers.csv").write_text("changed later\n")
    subprocess.run([*GIT, "-C", str(path), "commit", "--quiet", "-am", "two"], check=True)
    log = subprocess.run(
        ["git", "-C", str(path), "log", "--format=%H"], capture_output=True, text=True, check=True
    ).stdout.split()
    return log[1]


def test_fetch_checks_out_the_pinned_commit_not_the_latest(tmp_path):
    first = make_repo(tmp_path / "upstream")
    source = Source("sample", "dataset", (tmp_path / "upstream").as_uri(), "1", first)
    path = fetch(source, tmp_path / "data")
    assert path == checkout_path(source, tmp_path / "data")
    assert (path / "answers.csv").read_text() == "case,real\n"
    # A second fetch finds the commit already checked out.
    assert fetch(source, tmp_path / "data") == path


def test_fetch_fails_on_an_unknown_commit(tmp_path):
    make_repo(tmp_path / "upstream")
    source = Source("sample", "dataset", (tmp_path / "upstream").as_uri(), "1", "0" * 40)
    with pytest.raises(SourceError):
        fetch(source, tmp_path / "data")
