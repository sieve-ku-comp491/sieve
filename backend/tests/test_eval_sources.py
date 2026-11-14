"""The pinned datasets and target applications, and checking them out."""

import subprocess
from pathlib import Path

import pytest

from app.eval.sources import Source, SourceError, checkout_path, fetch, is_fetched, load_sources

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


def test_a_pin_change_leaves_exactly_the_new_commit(tmp_path):
    upstream = tmp_path / "upstream"
    upstream.mkdir()
    subprocess.run([*GIT, "-C", str(upstream), "init", "--quiet"], check=True)
    (upstream / "kept.txt").write_text("v1\n")
    (upstream / "only_old.txt").write_text("gone in v2\n")
    (upstream / ".gitignore").write_text("*.log\n")
    subprocess.run([*GIT, "-C", str(upstream), "add", "--all"], check=True)
    subprocess.run([*GIT, "-C", str(upstream), "commit", "--quiet", "-m", "v1"], check=True)
    old = _commit_of(upstream)
    (upstream / "only_old.txt").unlink()
    (upstream / "kept.txt").write_text("v2\n")
    subprocess.run([*GIT, "-C", str(upstream), "commit", "--quiet", "-am", "v2"], check=True)
    new = _commit_of(upstream)

    path = fetch(Source("s", "dataset", upstream.as_uri(), "1", old), tmp_path / "data")
    (path / "kept.txt").write_text("changed by hand\n")
    (path / "added_by_hand.txt").write_text("x\n")
    (path / "run.log").write_text("ignored\n")
    pinned = Source("s", "dataset", upstream.as_uri(), "2", new)
    assert not is_fetched(pinned, tmp_path / "data")

    fetch(pinned, tmp_path / "data")
    assert sorted(p.name for p in path.iterdir() if p.name != ".git") == [".gitignore", "kept.txt"]
    assert (path / "kept.txt").read_text() == "v2\n"
    assert is_fetched(pinned, tmp_path / "data")


def _commit_of(path: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
