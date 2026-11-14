"""Counts the files in a checkout that a plug-in's languages cover.

The runner uses the count to tell a plug-in that had nothing to scan from one that scanned
nothing by mistake, such as a scan of the wrong folder (docs/interfaces.md, Run statuses).
"""

import os
from collections.abc import Iterable
from pathlib import Path

EXTENSIONS = {
    "python": {".py", ".pyi"},
    "java": {".java"},
    "javascript": {".js", ".jsx", ".mjs", ".cjs"},
    "typescript": {".ts", ".tsx", ".mts", ".cts"},
}


def count_files(checkout: Path, languages: Iterable[str]) -> int:
    """Regular files in the checkout in these languages, or all regular files for ["*"]."""
    languages = set(languages)
    every_file = "*" in languages
    suffixes = set().union(*(EXTENSIONS.get(language, set()) for language in languages))
    count = 0
    for folder, _, names in os.walk(checkout):
        for name in names:
            path = Path(folder, name)
            if path.is_symlink() or not path.is_file():
                continue
            if every_file or path.suffix.lower() in suffixes:
                count += 1
    return count


def detect_languages(checkout: Path) -> list[str]:
    """The languages with at least one regular file in the checkout, sorted. They decide which
    plug-ins a scan runs."""
    found = set()
    for folder, _, names in os.walk(checkout):
        for name in names:
            path = Path(folder, name)
            if path.is_symlink() or not path.is_file():
                continue
            suffix = path.suffix.lower()
            found.update(lang for lang, suffixes in EXTENSIONS.items() if suffix in suffixes)
    return sorted(found)
