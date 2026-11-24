"""The function around a line of scanned code, found with tree-sitter.

Deduplication asks it whether two findings are in the same function (app.dedup.rules), and the
triage agent will get that function as the code around a finding (docs/interfaces.md, Triage
item).

A function here is a function, method or constructor, named or not, or a lambda or arrow
function whose body is a block, in Python, Java, JavaScript or TypeScript. A lambda or arrow
function whose body is a single expression, such as `lambda x: x + 1` or `x => x.id`, doesn't
count: a finding on its line would otherwise be in a different function from the rest of the
code around it. Decorators and annotations are part of the function they decorate, so a finding
on a line such as `@csrf_exempt` is in that function.
"""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import PurePosixPath

import tree_sitter_java
import tree_sitter_javascript
import tree_sitter_python
import tree_sitter_typescript
from tree_sitter import Language, Node, Parser, Query, QueryCursor

from app.checkout import CheckoutReader
from app.dedup.functions import FunctionSpan

# The same extensions as the runner's languages (app.runner.languages), with TSX parsed by its
# own grammar.
SUFFIXES = {
    ".py": "python",
    ".pyi": "python",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".tsx": "tsx",
}

JAVASCRIPT_FUNCTIONS = """
[(function_declaration) (generator_function_declaration) (function_expression)
 (generator_function) (method_definition) (arrow_function body: (statement_block))] @function
"""

QUERIES = {
    "python": "(function_definition) @function",
    "java": """
[(method_declaration) (constructor_declaration) (compact_constructor_declaration)
 (lambda_expression body: (block))] @function
""",
    "javascript": JAVASCRIPT_FUNCTIONS,
    "typescript": JAVASCRIPT_FUNCTIONS,
    "tsx": JAVASCRIPT_FUNCTIONS,
}

GRAMMARS: dict[str, Callable[[], object]] = {
    "python": tree_sitter_python.language,
    "java": tree_sitter_java.language,
    "javascript": tree_sitter_javascript.language,
    "typescript": tree_sitter_typescript.language_typescript,
    "tsx": tree_sitter_typescript.language_tsx,
}

# Where a function is a member, the node that holds it and the kinds of class that can own it.
MEMBER_CONTAINERS = {"block", "class_body", "interface_body", "enum_body_declarations"}
CLASSES = {
    "class_definition",
    "class_declaration",
    "abstract_class_declaration",
    "class",
    "interface_declaration",
    "enum_declaration",
    "record_declaration",
}
# Class fields whose value is an arrow function or a function expression.
FIELDS = {"public_field_definition", "field_definition"}


def language_of(file: str) -> str | None:
    """The grammar for a file, by its extension, or None for a language we don't parse."""
    return SUFFIXES.get(PurePosixPath(file).suffix.lower())


@dataclass(frozen=True)
class _Grammar:
    language: Language
    query: Query


_grammars: dict[str, _Grammar] = {}


def _grammar(name: str) -> _Grammar:
    if name not in _grammars:
        language = Language(GRAMMARS[name]())
        _grammars[name] = _Grammar(language, Query(language, QUERIES[name]))
    return _grammars[name]


class TreeSitterFunctionLookup:
    """The FunctionLookup of deduplication (app.dedup.functions) for one scan's checkout.

    Each file is read through the CheckoutReader, so no path can leave the checkout, and parsed
    once, the first time a line of it is asked for.
    """

    def __init__(self, reader: CheckoutReader):
        self._reader = reader
        self._functions: dict[str, list[FunctionSpan]] = {}

    def enclosing_function(self, file: str, line: int) -> FunctionSpan | None:
        if file not in self._functions:
            self._functions[file] = self.functions(file)
        inside = [f for f in self._functions[file] if f.start_line <= line <= f.end_line]
        # Functions nest, so the innermost one is the last to start, and of two that start on
        # the same line, the first to end.
        return max(inside, key=lambda f: (f.start_line, -f.end_line), default=None)

    def functions(self, file: str) -> list[FunctionSpan]:
        """Every function of the file, in order of their first line. Empty when the file can't
        be read or its language isn't one we parse."""
        language = language_of(file)
        if language is None:
            return []
        lines = self._reader.read_lines(file)
        if lines is None:
            return []
        grammar = _grammar(language)
        # The reader splits lines at \r\n and \n, as SARIF counts them, so joining them with \n
        # keeps tree-sitter's rows on the analyzers' line numbers.
        tree = Parser(grammar.language).parse("\n".join(lines).encode("utf-8"))
        nodes = QueryCursor(grammar.query).captures(tree.root_node).get("function", [])
        return sorted(
            {_span(node) for node in nodes}, key=lambda f: (f.start_line, -f.end_line, f.name)
        )


def _span(node: Node) -> FunctionSpan:
    first = node
    # Python wraps a decorated function in a decorated_definition that starts at the first
    # decorator. Java's annotations and JavaScript's method decorators are inside the node.
    if node.parent is not None and node.parent.type == "decorated_definition":
        first = node.parent
    # TypeScript puts the decorators of a class member before it in the class body, and
    # comments can sit between them.
    member = node.parent if node.parent is not None and node.parent.type in FIELDS else node
    sibling = member.prev_named_sibling
    while sibling is not None and sibling.type in ("decorator", "comment"):
        if sibling.type == "decorator" and sibling.start_byte < first.start_byte:
            first = sibling
        sibling = sibling.prev_named_sibling
    end_row, end_column = node.end_point[0], node.end_point[1]
    if end_column == 0 and end_row > node.start_point[0]:
        end_row -= 1
    return FunctionSpan(_name(node), first.start_point[0] + 1, end_row + 1)


def _name(node: Node) -> str:
    name = node.child_by_field_name("name") or _assigned_to(node)
    if name is not None:
        text = " ".join(_text(name).split())
    elif node.type == "lambda_expression":
        text = "lambda"
    else:
        text = "anonymous function"
    owner = _owner(node)
    return f"{owner}.{text}" if owner else text


def _assigned_to(node: Node) -> Node | None:
    """For an anonymous function, the variable, property or key it is assigned to."""
    parent = node.parent
    if parent is None:
        return None
    if parent.type == "variable_declarator":
        return parent.child_by_field_name("name")
    if parent.type in ("assignment_expression", "augmented_assignment_expression"):
        return parent.child_by_field_name("left")
    if parent.type == "pair":
        return parent.child_by_field_name("key")
    if parent.type in FIELDS:
        return parent.child_by_field_name("name") or parent.child_by_field_name("property")
    return None


def _owner(node: Node) -> str | None:
    """The name of the class the function is a member of, if it is one."""
    member = node
    if member.parent is not None and member.parent.type in ("decorated_definition", *FIELDS):
        member = member.parent
    container = member.parent
    if container is None or container.type not in MEMBER_CONTAINERS:
        return None
    owner = container.parent
    if owner is not None and owner.type == "enum_body":
        owner = owner.parent
    if owner is None or owner.type not in CLASSES:
        return None
    name = owner.child_by_field_name("name")
    return _text(name) if name is not None else None


def _text(node: Node) -> str:
    return (node.text or b"").decode("utf-8", errors="replace")
