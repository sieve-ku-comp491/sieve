"""The enclosing-function lookup that the grouping rules ask (T3.3 writes the tree-sitter one)."""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class FunctionSpan:
    """One function or method in a scanned file. Two findings are in the same function when
    their lookups return equal spans."""

    name: str
    start_line: int
    end_line: int


class FunctionLookup(Protocol):
    def enclosing_function(self, file: str, line: int) -> FunctionSpan | None:
        """The innermost function or method of the scanned checkout that contains line of file,
        with its decorators or annotations counted as part of it. None when no function contains
        the line, or when the file can't be read or its language isn't supported."""
        ...


class NoFunctionLookup:
    """Knows no functions, so the rules fall back to the same file and nearby lines."""

    def enclosing_function(self, file: str, line: int) -> FunctionSpan | None:
        return None
