"""Clones a repository from the scope file and exports the files of one commit (requirement F2,
docs/interfaces.md).

Git runs with no system or user configuration, no credential helper, no prompts, no redirects
and HTTPS as the only protocol, so only a public repository can be cloned, and only from the URL
in the scope entry. Two clones are made:

1. A clone with commits only (--filter=tree:0) resolves the requested ref and checks that the
   commit is reachable from a branch or tag. GitHub serves a commit pushed to any fork through
   the original repository's URL, so a commit outside the branches and tags is refused.
   GIT_NO_LAZY_FETCH keeps Git from downloading a missing commit while checking.
2. A shallow fetch of that one commit, whose files git archive writes as a tar stream.

The export keeps regular files and folders only. Symbolic links and the tools' own ignore and
configuration files are left out, and the repository's export-ignore and export-subst attributes
are turned off, so the scanned code can't decide what is scanned.
"""

import os
import re
import shutil
import stat
import subprocess
import tarfile
from pathlib import Path, PurePosixPath

from app.scan.scope import ScopeEntry

IGNORED_FILES = frozenset({".semgrepignore", ".gitleaks.toml", ".gitleaksignore", ".bandit"})
FULL_HASH = re.compile(r"^[0-9a-f]{40}$")
REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/+-]{0,199}$")
DEFAULT_REF = "HEAD"

GIT_OPTIONS = (
    "-c", "credential.helper=",
    "-c", "credential.interactive=false",
    "-c", "core.askPass=",
    "-c", "http.followRedirects=false",
    "-c", "submodule.recurse=false",
    "-c", "fetch.recurseSubmodules=false",
)  # fmt: skip
# Variables a Git process on Windows needs to start and reach the network.
PASSED_VARIABLES = ("PATH", "SYSTEMROOT", "TEMP", "TMP")


class ExportError(RuntimeError):
    """The clone or the export failed. The message says why, for the scan's error."""


class RefError(ValueError):
    """A requested commit that is not a commit hash, branch or tag name."""


def split_ref(ref: str | None) -> tuple[str | None, str | None]:
    """(commit_sha, requested_ref) for the scans table: a full hash goes in commit_sha, and a
    branch, tag or short hash in requested_ref. No ref means the default branch."""
    if ref is None or ref == "":
        return None, DEFAULT_REF
    if FULL_HASH.match(ref.lower()):
        return ref.lower(), None
    if (
        not REF.match(ref)
        or ".." in ref
        or "//" in ref
        or ref.endswith(("/", ".", ".lock"))
        or "/." in ref
    ):
        raise RefError(f"{ref!r} is not a commit hash, branch or tag name")
    return None, ref


class CheckoutExporter:
    def __init__(self, timeout_seconds: int = 600, protocols: tuple[str, ...] = ("https",)):
        self.timeout_seconds = timeout_seconds
        self.protocols = protocols

    def export(self, entry: ScopeEntry, ref: str, dest: Path) -> str:
        """Writes the files of the commit that ref names to dest, which must not exist yet, and
        returns the full commit hash. Raises ExportError when the clone fails or the commit is
        not reachable from a branch or tag of the repository."""
        commit_sha, requested = split_ref(ref)
        ref = commit_sha or requested or DEFAULT_REF
        work = dest.parent / (dest.name + ".git-work")
        _remove(work)
        work.mkdir(parents=True)
        try:
            refs = work / "refs.git"
            self._git(
                work,
                "clone", "--quiet", "--bare", "--filter=tree:0", "--no-recurse-submodules",
                "--", entry.url, str(refs),
                failure=f"cloning {entry.url} failed",
            )  # fmt: skip
            sha = self._resolve(work, refs, ref, entry.url)

            content = work / "content.git"
            self._git(work, "init", "--quiet", "--bare", str(content), failure="git init failed")
            (content / "info").mkdir(exist_ok=True)
            (content / "info" / "attributes").write_text(
                "* -export-ignore -export-subst\n", encoding="utf-8"
            )
            self._git(
                work,
                "-C", str(content), "fetch", "--quiet", "--depth=1", "--no-tags",
                "--no-recurse-submodules", "--", entry.url, sha,
                failure=f"fetching commit {sha} from {entry.url} failed",
            )  # fmt: skip
            archive = work / "commit.tar"
            with archive.open("wb") as out:
                self._git(
                    work,
                    "-C", str(content), "archive", "--format=tar", sha,
                    failure=f"git archive of {sha} failed",
                    stdout=out,
                )  # fmt: skip
            extract(archive, dest)
        finally:
            _remove(work)
        return sha

    def _resolve(self, work: Path, refs: Path, ref: str, url: str) -> str:
        """The full hash of ref, if it is reachable from a branch or tag of the clone."""
        not_found = (
            f"commit {ref} is not on a branch or tag of {url}"
            if FULL_HASH.match(ref)
            else f"{ref} is not a branch, tag or commit on a branch or tag of {url}"
        )
        resolved = self._git(
            work,
            "-C", str(refs), "rev-parse", "--verify", "--quiet", "--end-of-options",
            f"{ref}^{{commit}}",
            failure=not_found,
        )  # fmt: skip
        sha = resolved.strip()
        containing = self._git(
            work,
            "-C", str(refs), "for-each-ref", "--count=1", "--format=%(refname)",
            f"--contains={sha}", "refs/heads", "refs/tags",
            failure=not_found,
        )  # fmt: skip
        if not containing.strip():
            raise ExportError(not_found)
        return sha

    def _git(self, work: Path, *args: str, failure: str, stdout=None) -> str:
        home = work / "home"
        home.mkdir(exist_ok=True)
        env = {name: os.environ[name] for name in PASSED_VARIABLES if name in os.environ}
        env |= {
            "HOME": str(home),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": ":".join(self.protocols),
            "GIT_NO_LAZY_FETCH": "1",
            "LC_ALL": "C",
        }
        try:
            completed = subprocess.run(
                ["git", *GIT_OPTIONS, *args],
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=stdout if stdout is not None else subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise ExportError(f"{failure}: no answer within {self.timeout_seconds} s") from None
        except OSError as error:
            raise ExportError(f"{failure}: can't run git: {error}") from None
        if completed.returncode != 0:
            detail = _last_line(completed.stderr)
            raise ExportError(f"{failure}: {detail}" if detail else failure)
        if stdout is not None:
            return ""
        return completed.stdout.decode("utf-8", errors="replace")


def extract(archive: Path, dest: Path) -> tuple[int, dict[str, int]]:
    """Extracts the regular files and folders of a git archive tar file into dest. Returns the
    number of files and what was left out: links and other special files, and ignore files."""
    left_out = {"links and special files": 0, "ignore and configuration files": 0}
    files = 0
    dest.mkdir(parents=True)
    with tarfile.open(archive) as tar:
        keep: list[tarfile.TarInfo] = []
        for member in tar:
            parts = PurePosixPath(member.name).parts
            if not parts or parts[0] == "/" or ".." in parts:
                raise ExportError(f"the archive has a path outside the export: {member.name!r}")
            if member.isdir():
                keep.append(member)
            elif not member.isreg():
                left_out["links and special files"] += 1
            elif parts[-1] in IGNORED_FILES:
                left_out["ignore and configuration files"] += 1
            else:
                keep.append(member)
                files += 1
        try:
            tar.extractall(dest, members=keep, filter="data")
        except (OSError, tarfile.TarError) as error:
            raise ExportError(f"extracting the files failed: {error}") from None
    return files, left_out


def _last_line(stderr: bytes) -> str:
    lines = [line.strip() for line in stderr.decode("utf-8", "replace").splitlines()]
    lines = [line for line in lines if line]
    return lines[-1][:500] if lines else ""


def _remove(path: Path) -> None:
    """Removes a folder. Git makes its pack files read-only, which stops rmtree on Windows."""

    def make_writable(function, name, _error):
        os.chmod(name, stat.S_IWRITE)
        function(name)

    if path.exists():
        shutil.rmtree(path, onexc=make_writable)
