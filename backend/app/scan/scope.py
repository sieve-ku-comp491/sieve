"""The scope file: the repositories Sieve may scan (requirement F2).

Each [[repository]] entry has a url and the reason we may scan it. The API checks every scan
request against this file before it creates anything, and the worker checks again and clones the
URL written in the entry, never the one in the request. The file lists public repositories only
(requirement N4).
"""

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

# Where the API and the worker find the scope file, unless SIEVE_SCOPE_FILE says otherwise.
DEFAULT_SCOPE_FILE = "/etc/sieve/scope.toml"
ENTRY_KEYS = {"url", "reason"}
HOST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")


class ScopeError(ValueError):
    """A scope file that can't be loaded. The message names the file and the entry."""


class UrlError(ValueError):
    """A repository URL that breaks the rules of F2."""


class OutOfScope(LookupError):
    """A repository that the scope file doesn't list."""

    def __init__(self, repo_url: str, scope_path: Path):
        super().__init__(
            f"{repo_url} is not in the scope file {scope_path}. Sieve scans only the "
            "repositories listed there."
        )
        self.repo_url = repo_url
        self.scope_path = scope_path


def normalize_url(url: str) -> str:
    """The URL as the scope check compares it: the host in lowercase, without a trailing / or
    .git. Raises UrlError when the URL breaks the rules: it must start with https:// and have no
    user name or password, port, query or fragment."""
    if not isinstance(url, str) or not url:
        raise UrlError("the repository URL is empty")
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 or c == "\\" for c in url):
        raise UrlError("the repository URL has a space, a control character or a backslash")
    if not url.startswith("https://"):
        raise UrlError("the repository URL must start with https://")
    if "?" in url:
        raise UrlError("the repository URL must not have a query")
    if "#" in url:
        raise UrlError("the repository URL must not have a fragment")
    parts = urlsplit(url)
    if "@" in parts.netloc:
        raise UrlError("the repository URL must not have a user name or password")
    if ":" in parts.netloc:
        raise UrlError("the repository URL must not have a port")
    if not HOST.match(parts.netloc):
        raise UrlError("the repository URL has no valid host name")
    segments = parts.path.split("/")[1:]
    while segments and segments[-1] == "":
        segments.pop()
    if segments:
        segments[-1] = segments[-1].removesuffix(".git")
    if not segments or any(s in ("", ".", "..") for s in segments):
        raise UrlError("the repository URL needs a path such as /owner/repository")
    return f"https://{parts.netloc.lower()}/{'/'.join(segments)}"


def without_credentials(url: str) -> str:
    """The URL with any user name and password removed, so an error message never shows them."""
    parts = urlsplit(url) if isinstance(url, str) else None
    if parts is None or "@" not in parts.netloc:
        return str(url)
    return parts._replace(netloc=parts.netloc.rsplit("@", 1)[1]).geturl()


@dataclass(frozen=True)
class ScopeEntry:
    url: str
    reason: str

    @property
    def normalized_url(self) -> str:
        return normalize_url(self.url)


class ScopeFile:
    def __init__(self, path: Path, entries: list[ScopeEntry]):
        self.path = path
        self.entries = entries
        self._by_url = {entry.normalized_url: entry for entry in entries}

    @classmethod
    def load(cls, path: Path) -> "ScopeFile":
        """Reads and checks the whole file. An entry without a reason, with a URL that breaks
        the rules, or listed twice makes the file fail to load, with an error naming it."""
        path = Path(path)
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except OSError as error:
            raise ScopeError(f"can't read the scope file {path}: {error.strerror}") from None
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
            raise ScopeError(f"the scope file {path} is not valid TOML: {error}") from None
        unknown = set(data) - {"repository"}
        if unknown:
            raise ScopeError(f"the scope file {path} has unknown keys {sorted(unknown)}")
        items = data.get("repository", [])
        if not isinstance(items, list):
            raise ScopeError(f"the scope file {path}: use [[repository]] for each entry")

        entries: list[ScopeEntry] = []
        seen: dict[str, int] = {}
        for number, item in enumerate(items, 1):
            url = item.get("url") if isinstance(item, dict) else None
            name = f"entry {number}"
            if isinstance(url, str):
                name += f" ({without_credentials(url)})"
            problem = _entry_problem(item)
            if problem:
                raise ScopeError(f"the scope file {path}, {name}: {problem}")
            entry = ScopeEntry(url=item["url"], reason=item["reason"].strip())
            normalized = entry.normalized_url
            if normalized in seen:
                raise ScopeError(
                    f"the scope file {path}, {name}: the same repository as entry "
                    f"{seen[normalized]}"
                )
            seen[normalized] = number
            entries.append(entry)
        return cls(path, entries)

    def allows(self, repo_url: str) -> ScopeEntry:
        """The entry that lists this repository. Raises UrlError for a URL that breaks the
        rules, and OutOfScope for one that no entry lists."""
        normalized = normalize_url(repo_url)
        entry = self._by_url.get(normalized)
        if entry is None:
            raise OutOfScope(normalized, self.path)
        return entry


def _entry_problem(item: object) -> str | None:
    if not isinstance(item, dict):
        return "each entry must be a [[repository]] table"
    unknown = set(item) - ENTRY_KEYS
    if unknown:
        return f"unknown keys {sorted(unknown)}"
    if not isinstance(item.get("url"), str) or not item["url"]:
        return "no url"
    reason = item.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        return "no reason, say why we may scan this repository"
    try:
        normalize_url(item["url"])
    except UrlError as error:
        return str(error)
    return None
