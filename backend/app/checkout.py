"""Reads files from a scan's checkout without ever leaving it (docs/class-diagrams.md).

The checkout is code from a repository we don't control. Every path is resolved first, and a
path that ends up outside the checkout, through "..", an absolute path or a symbolic link, is
refused, so no read can reach the worker's own files. A bad path, such as one with a NUL byte,
counts as not readable and never raises past the reader.
"""

import os
import re
import stat
from pathlib import Path, PurePosixPath

# SARIF counts lines at \r\n and \n only, unless a tool sets run.newlineSequences (SARIF 2.1.0,
# 3.14.26), and Semgrep counts them the same way.
LINE_BREAK = re.compile(r"\r?\n")
MAX_FILE_BYTES = 5 * 1024 * 1024
OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)


class CheckoutError(ValueError):
    """A path that is not a file inside the checkout."""


class CheckoutReader:
    def __init__(self, root: Path, max_bytes: int = MAX_FILE_BYTES):
        self.root = Path(root).resolve()
        self.max_bytes = max_bytes

    def resolve(self, relative: str) -> Path:
        """The checkout file at a relative path with / separators, or CheckoutError."""
        if not relative or "\\" in relative or "\x00" in relative:
            raise CheckoutError(f"not a relative path inside the checkout: {relative!r}")
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts:
            raise CheckoutError(f"not a relative path inside the checkout: {relative!r}")
        try:
            path = (self.root / pure).resolve()
        except (OSError, ValueError) as error:
            raise CheckoutError(f"{relative!r} can't be resolved: {error}") from None
        if not path.is_relative_to(self.root):
            raise CheckoutError(f"{relative!r} leads outside the checkout")
        return path

    def is_file(self, relative: str) -> bool:
        try:
            return self.resolve(relative).is_file()
        except CheckoutError, OSError, ValueError:
            return False

    def read_lines(self, relative: str) -> list[str] | None:
        """The file's lines without line breaks, or None if it can't be read.

        Only a regular file up to max_bytes is read, opened without following a link and
        without blocking on a FIFO. Bytes that aren't valid UTF-8 are replaced, so a file in
        another encoding still gives lines.
        """
        try:
            path = self.resolve(relative)
            descriptor = os.open(path, OPEN_FLAGS)
        except CheckoutError, OSError, ValueError:
            return None
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > self.max_bytes:
                return None
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = None
                data = handle.read(self.max_bytes + 1)
        except OSError:
            return None
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if len(data) > self.max_bytes:
            return None
        lines = LINE_BREAK.split(data.decode("utf-8", errors="replace"))
        if lines and lines[-1] == "":
            lines.pop()
        return lines
