"""The export of a scanned commit, on a local repository served over file://, so these tests
need no network. The repository has a symbolic link, the tools' ignore files, export-ignore and
export-subst attributes, a branch, a tag, and a commit that no branch or tag reaches, which
stands in for a commit that exists only in a fork."""

import os
import subprocess
from pathlib import Path

import pytest

from app.scan import CheckoutExporter, ExportError, RefError, ScopeEntry, split_ref
from app.scan.exporter import GIT_OPTIONS


def git(repo: Path, *args: str, stdin: str | None = None) -> str:
    env = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        input=stdin,
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, **env},
    )
    return result.stdout.strip()


def commit_all(repo: Path, message: str) -> str:
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", message)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture(scope="module")
def origin(tmp_path_factory) -> dict:
    repo = tmp_path_factory.mktemp("origin")
    git(repo, "init", "-q", "-b", "main")
    (repo / "app.py").write_text("import os\nos.system(input())\n", encoding="utf-8")
    (repo / "web").mkdir()
    (repo / "web" / "index.js").write_text("eval(location.hash)\n", encoding="utf-8")
    (repo / "hidden.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "subst.py").write_text("# $Format:%H$\n", encoding="utf-8")
    (repo / ".gitattributes").write_text(
        "hidden.py export-ignore\nsubst.py export-subst\n", encoding="utf-8"
    )
    for name in (".semgrepignore", ".gitleaks.toml", ".gitleaksignore", ".bandit"):
        (repo / name).write_text("app.py\n", encoding="utf-8")
    (repo / "web" / ".semgrepignore").write_text("index.js\n", encoding="utf-8")
    git(repo, "add", "-A")
    # A link to the worker's environment, made with plumbing so it is a link on every system.
    blob = git(repo, "hash-object", "-w", "--stdin", stdin="/proc/self/environ")
    git(repo, "update-index", "--add", "--cacheinfo", f"120000,{blob},environ")
    first = commit_all(repo, "first")
    git(repo, "tag", "v1.0")
    (repo / "app.py").write_text("print('second')\n", encoding="utf-8")
    second = commit_all(repo, "second")

    git(repo, "checkout", "-q", "-b", "fork")
    (repo / "app.py").write_text("print('fork')\n", encoding="utf-8")
    fork_only = commit_all(repo, "fork only")
    git(repo, "checkout", "-q", "main")
    git(repo, "branch", "-q", "-D", "fork")
    # Serve the unreachable commit when asked for it by hash, as GitHub does for fork commits.
    git(repo, "config", "uploadpack.allowAnySHA1InWant", "true")
    git(repo, "config", "uploadpack.allowFilter", "true")
    return {
        "entry": ScopeEntry(url=repo.as_uri(), reason="test"),
        "first": first,
        "second": second,
        "fork_only": fork_only,
    }


def export(origin: dict, ref: str | None, dest: Path) -> str:
    return CheckoutExporter(protocols=("file",)).export(origin["entry"], ref, dest)


def files(dest: Path) -> list[str]:
    return sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file())


def test_the_export_has_regular_files_only_without_links_ignore_files_or_git(origin, tmp_path):
    dest = tmp_path / "src"
    assert export(origin, origin["first"], dest) == origin["first"]
    assert files(dest) == [".gitattributes", "app.py", "hidden.py", "subst.py", "web/index.js"]
    assert not (dest / "environ").exists() and not (dest / "environ").is_symlink()
    assert not (dest / ".git").exists()


def test_the_repository_attributes_cannot_hide_or_change_files(origin, tmp_path):
    dest = tmp_path / "src"
    export(origin, origin["first"], dest)
    assert (dest / "hidden.py").read_text(encoding="utf-8") == "x = 1\n"
    assert (dest / "subst.py").read_text(encoding="utf-8") == "# $Format:%H$\n"


@pytest.mark.parametrize(
    ("ref", "expected"),
    [(None, "second"), ("main", "second"), ("v1.0", "first"), ("HEAD", "second")],
)
def test_branches_tags_and_the_default_branch_resolve_to_full_hashes(
    origin, tmp_path, ref, expected
):
    assert export(origin, ref, tmp_path / "src") == origin[expected]


def test_a_short_hash_resolves(origin, tmp_path):
    assert export(origin, origin["first"][:9], tmp_path / "src") == origin["first"]
    assert (tmp_path / "src" / "app.py").read_text(encoding="utf-8") == (
        "import os\nos.system(input())\n"
    )


def test_a_commit_on_no_branch_or_tag_is_refused_even_though_the_server_serves_it(origin, tmp_path):
    with pytest.raises(ExportError, match="is not on a branch or tag of"):
        export(origin, origin["fork_only"], tmp_path / "src")
    assert not (tmp_path / "src").exists()
    assert not (tmp_path / "src.git-work").exists()


def test_an_unknown_ref_is_refused(origin, tmp_path):
    with pytest.raises(ExportError, match="no-such-branch is not a branch, tag or commit"):
        export(origin, "no-such-branch", tmp_path / "src")


def test_only_the_allowed_protocols_are_used(origin, tmp_path):
    with pytest.raises(ExportError, match="cloning .* failed"):
        CheckoutExporter().export(origin["entry"], None, tmp_path / "src")


def test_git_runs_without_credential_helpers_redirects_or_submodules():
    options = dict(zip(GIT_OPTIONS[1::2], GIT_OPTIONS[0::2], strict=True))
    assert set(options) == {
        "credential.helper=",
        "credential.interactive=false",
        "core.askPass=",
        "http.followRedirects=false",
        "submodule.recurse=false",
        "fetch.recurseSubmodules=false",
    }


@pytest.mark.parametrize(
    ("ref", "split"),
    [
        (None, (None, "HEAD")),
        ("", (None, "HEAD")),
        (
            "2AA4CC14F251E4A780E94E200AED6B36A5B15C21",
            ("2aa4cc14f251e4a780e94e200aed6b36a5b15c21", None),
        ),
        ("2aa4cc1", (None, "2aa4cc1")),
        ("release/v3.0.0", (None, "release/v3.0.0")),
    ],
)
def test_split_ref(ref, split):
    assert split_ref(ref) == split


@pytest.mark.parametrize(
    "ref",
    ["--upload-pack=touch /tmp/x", "-x", "a..b", "a b", "main.lock", "a//b", "x/.hidden", "@{1}"],
)
def test_refs_that_could_be_options_or_odd_names_are_refused(ref):
    with pytest.raises(RefError):
        split_ref(ref)
