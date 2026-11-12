"""Reads files from a scan's checkout without ever leaving it (docs/class-diagrams.md).

The checkout is code from a repository we don't control. Every path is resolved first, and a
path that ends up outside the checkout, through "..", an absolute path or a symbolic link, is
refused, so no read can reach the worker's own files.
"""

import re
from pathlib import Path, PurePosixPath

LINE_BREAK = re.compile(r"\r\n|\r|\n")


class CheckoutError(ValueError):
    """A path that is not a file inside the checkout."""


class CheckoutReader:
    def __init__(self, root: Path):
        self.root = Path(root).resolve()

    def resolve(self, relative: str) -> Path:
        """The checkout file at a relative path with / separators, or CheckoutError."""
        pure = PurePosixPath(relative)
        if not relative or "\\" in relative or pure.is_absolute() or ".." in pure.parts:
            raise CheckoutError(f"not a relative path inside the checkout: {relative!r}")
        path = (self.root / pure).resolve()
        if not path.is_relative_to(self.root):
            raise CheckoutError(f"{relative!r} leads outside the checkout")
        return path

    def is_file(self, relative: str) -> bool:
        try:
            return self.resolve(relative).is_file()
        except CheckoutError, OSError:
            return False

    def read_lines(self, relative: str) -> list[str] | None:
        """The file's lines without line breaks, or None if it can't be read.

        Bytes that aren't valid UTF-8 are replaced, so a file in another encoding still gives
        lines. Lines end at \\n, \\r\\n or \\r, as SARIF line numbers count them.
        """
        try:
            path = self.resolve(relative)
            if not path.is_file():
                return None
            text = path.read_bytes().decode("utf-8", errors="replace")
        except CheckoutError, OSError:
            return None
        lines = LINE_BREAK.split(text)
        if lines and lines[-1] == "":
            lines.pop()
        return lines
