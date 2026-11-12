"""Download the pinned datasets and target applications (docs/evaluation.md)."""

import os
import re
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path

SOURCES_FILE = Path(__file__).with_name("sources.toml")
REPO_ROOT = Path(__file__).resolve().parents[3]
COMMIT = re.compile(r"^[0-9a-f]{40}$")
KINDS = {"dataset", "target"}


class SourceError(RuntimeError):
    """A source that can't be loaded or checked out at its pinned commit."""


@dataclass(frozen=True)
class Source:
    name: str
    kind: str
    url: str
    version: str
    commit: str


def data_dir() -> Path:
    """Where downloads, generated CSV files and neutral copies go. Never committed."""
    return Path(os.environ.get("SIEVE_EVAL_DIR", REPO_ROOT / "eval-data"))


def load_sources(path: Path = SOURCES_FILE) -> list[Source]:
    entries = tomllib.loads(path.read_text(encoding="utf-8")).get("source", [])
    sources = []
    for entry in entries:
        source = Source(**entry)
        if source.kind not in KINDS:
            raise SourceError(f"{source.name}: kind must be one of {sorted(KINDS)}")
        if not COMMIT.match(source.commit):
            raise SourceError(f"{source.name}: commit must be a full 40-character hash")
        sources.append(source)
    names = [source.name for source in sources]
    if len(names) != len(set(names)):
        raise SourceError("source names must be unique")
    return sources


def checkout_path(source: Source, root: Path | None = None) -> Path:
    return (root or data_dir()) / "sources" / source.name


def fetch(source: Source, root: Path | None = None) -> Path:
    """Check out the source at its pinned commit, without history. Does nothing if it already is."""
    dest = checkout_path(source, root)
    if dest.exists() and _head(dest) == source.commit:
        return dest
    dest.mkdir(parents=True, exist_ok=True)
    _git(dest, "init", "--quiet")
    _git(dest, "fetch", "--quiet", "--depth", "1", source.url, source.commit)
    _git(dest, "-c", "advice.detachedHead=false", "checkout", "--quiet", "--force", "FETCH_HEAD")
    head = _head(dest)
    if head != source.commit:
        raise SourceError(f"{source.name}: checked out {head}, expected {source.commit}")
    return dest


def _head(path: Path) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _git(path: Path, *args: str) -> None:
    result = subprocess.run(["git", "-C", str(path), *args], capture_output=True, text=True)
    if result.returncode != 0:
        raise SourceError(f"git {args[0]} in {path} failed: {result.stderr.strip()}")
