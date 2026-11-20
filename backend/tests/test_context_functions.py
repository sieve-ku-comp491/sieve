"""The enclosing function of a line, found with tree-sitter (T3.3).

Each test writes a small file into a checkout and checks the function, with its name and lines,
that the lookup gives for its lines. The PyGoat tests use the real file in tests/adapter_fixture.
"""

from pathlib import Path

import pytest

from app.checkout import CheckoutReader
from app.context import TreeSitterFunctionLookup, language_of
from app.dedup import SAME_FUNCTION, FunctionSpan, RuleStep, ScanFinding, group_findings

FIXTURE = Path(__file__).parent / "adapter_fixture" / "pygoat"
LAB = "dockerized_labs/sql_injection_lab/app.py"


def lookup_for(tmp_path: Path, files: dict[str, str]) -> TreeSitterFunctionLookup:
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))
    return TreeSitterFunctionLookup(CheckoutReader(tmp_path))


def spans(lookup: TreeSitterFunctionLookup, file: str, lines: range) -> dict[int, object]:
    return {line: lookup.enclosing_function(file, line) for line in lines}


PYTHON = """\
@app.route('/ping')
@login_required
def ping(request):
    host = (lambda h: h.strip())(request.GET["host"])

    async def run():
        return await shell(host)

    return run()


class Views:
    @staticmethod
    def show(request):
        pass

    limit = 10
"""


def test_python_functions_with_their_decorators(tmp_path):
    lookup = lookup_for(tmp_path, {"views.py": PYTHON})
    ping = FunctionSpan("ping", 1, 9)
    run = FunctionSpan("run", 6, 7)
    show = FunctionSpan("Views.show", 13, 15)

    assert spans(lookup, "views.py", range(1, 18)) == {
        1: ping,  # the decorators belong to the function
        2: ping,
        3: ping,
        4: ping,  # a lambda with one expression is not a function of its own
        5: ping,
        6: run,  # the innermost function
        7: run,
        8: ping,
        9: ping,
        10: None,
        11: None,
        12: None,
        13: show,
        14: show,
        15: show,
        16: None,
        17: None,  # a class attribute is in no function
    }


JAVA = """\
class Lesson {
  @PostMapping("/attack")
  @ResponseBody
  public Result attack(@RequestParam String query) {
    Runnable task = () -> {
      run(query);
    };
    rows.forEach(row -> check(row));
    return result;
  }

  Lesson() {
    init();
  }

  private int count = 0;

  enum Kind {
    A;
    String label() { return "a"; }
  }
}
"""


def test_java_methods_annotations_constructors_and_lambdas(tmp_path):
    lookup = lookup_for(tmp_path, {"src/Lesson.java": JAVA})
    attack = FunctionSpan("Lesson.attack", 2, 10)
    task = FunctionSpan("task", 5, 7)
    constructor = FunctionSpan("Lesson.Lesson", 12, 14)

    assert spans(lookup, "src/Lesson.java", range(1, 23)) == {
        1: None,
        2: attack,  # the annotations belong to the method
        3: attack,
        4: attack,
        5: task,  # a lambda with a block is a function
        6: task,
        7: task,
        8: attack,  # a lambda with one expression is not
        9: attack,
        10: attack,
        11: None,
        12: constructor,
        13: constructor,
        14: constructor,
        15: None,
        16: None,  # a field is in no function
        17: None,
        18: None,
        19: None,
        20: FunctionSpan("Kind.label", 20, 20),
        21: None,
        22: None,
    }


JAVASCRIPT = """\
const express = require('express');

app.get('/search', (req, res) => {
  const ids = req.query.ids.map(id => id.trim());
  res.send(eval(req.query.q));
});

function render(user) {
  return <div>{user.name}</div>;
}

const handler = function () {
  return 1;
};

class Store {
  @memoize
  load(key) {
    return this.items[key];
  }
}

const api = { fetch(url) { return get(url); } };
"""


def test_javascript_functions_handlers_and_jsx(tmp_path):
    lookup = lookup_for(tmp_path, {"routes.js": JAVASCRIPT})
    search = FunctionSpan("anonymous function", 3, 6)
    load = FunctionSpan("Store.load", 17, 20)

    assert spans(lookup, "routes.js", range(1, 24)) == {
        1: None,
        2: None,
        3: search,  # a route handler is an arrow function with a block
        4: search,  # an arrow function with one expression is not a function of its own
        5: search,
        6: search,
        7: None,
        8: FunctionSpan("render", 8, 10),  # JSX in a .js file still parses
        9: FunctionSpan("render", 8, 10),
        10: FunctionSpan("render", 8, 10),
        11: None,
        12: FunctionSpan("handler", 12, 14),  # named after the variable it is assigned to
        13: FunctionSpan("handler", 12, 14),
        14: FunctionSpan("handler", 12, 14),
        15: None,
        16: None,
        17: load,  # the decorator belongs to the method
        18: load,
        19: load,
        20: load,
        21: None,
        22: None,
        23: FunctionSpan("fetch", 23, 23),
    }


TYPESCRIPT = """\
@Component({ selector: 'app-search' })
export class SearchComponent {
  @Input() term: string;

  @HostListener('keyup')
  search(): void {
    this.http.get(`/rest/products/search?q=${this.term}`);
  }

  reset = () => {
    this.term = '';
  };

  abstract load(): void;
}
"""


def test_typescript_decorators_before_a_member_belong_to_it(tmp_path):
    lookup = lookup_for(tmp_path, {"search.component.ts": TYPESCRIPT})
    search = FunctionSpan("SearchComponent.search", 5, 8)
    reset = FunctionSpan("SearchComponent.reset", 10, 12)

    assert spans(lookup, "search.component.ts", range(1, 16)) == {
        1: None,  # a class is not a function
        2: None,
        3: None,  # nor is a decorated field
        4: None,
        5: search,
        6: search,
        7: search,
        8: search,
        9: None,
        10: reset,  # an arrow function in a field is named after the field
        11: reset,
        12: reset,
        13: None,
        14: None,  # a method without a body is not a function
        15: None,
    }


def test_tsx_components(tmp_path):
    source = "export const Basket = (props: Props) => {\n  return <Item id={props.id} />;\n};\n"
    lookup = lookup_for(tmp_path, {"Basket.tsx": source})
    assert lookup.functions("Basket.tsx") == [FunctionSpan("Basket", 1, 3)]


def test_lines_follow_the_analyzers_numbering_with_crlf(tmp_path):
    lookup = lookup_for(tmp_path, {"a.py": "x = 1\r\n\r\ndef f():\r\n    return x\r\n"})
    assert lookup.enclosing_function("a.py", 4) == FunctionSpan("f", 3, 4)


@pytest.mark.parametrize(
    "file",
    ["templates/index.html", "missing.py", "../outside.py", "/etc/passwd.py", "README"],
)
def test_no_function_where_nothing_can_be_parsed(tmp_path, file):
    lookup = lookup_for(tmp_path, {"templates/index.html": "<form></form>\n"})
    (tmp_path.parent / "outside.py").write_text("def f():\n    pass\n")
    assert lookup.enclosing_function(file, 1) is None


def test_lines_outside_the_file_have_no_function(tmp_path):
    lookup = lookup_for(tmp_path, {"a.py": "def f():\n    pass\n"})
    assert [lookup.enclosing_function("a.py", line) for line in (0, 1, 2, 3, 99)] == [
        None,
        FunctionSpan("f", 1, 2),
        FunctionSpan("f", 1, 2),
        None,
        None,
    ]


def test_each_file_is_read_once(tmp_path):
    lookup = lookup_for(tmp_path, {"a.py": "def f():\n    pass\n"})
    reads = []
    read_lines = lookup._reader.read_lines
    lookup._reader.read_lines = lambda file: reads.append(file) or read_lines(file)
    for line in (1, 2, 1, 2):
        lookup.enclosing_function("a.py", line)
    lookup.enclosing_function("missing.py", 1)
    lookup.enclosing_function("missing.py", 2)
    assert reads == ["a.py", "missing.py"]


@pytest.mark.parametrize(
    ("file", "language"),
    [
        ("a.py", "python"),
        ("a.pyi", "python"),
        ("A.java", "java"),
        ("a.JS", "javascript"),
        ("a.jsx", "javascript"),
        ("a.mjs", "javascript"),
        ("a.cjs", "javascript"),
        ("a.ts", "typescript"),
        ("a.mts", "typescript"),
        ("a.cts", "typescript"),
        ("a.tsx", "tsx"),
        ("a.html", None),
        ("Makefile", None),
    ],
)
def test_languages_by_extension(file, language):
    assert language_of(file) == language


def test_the_lab_function_of_pygoat():
    """The function of the six SQL injection results in docs/finding-format.md, from its
    @app.route decorator on line 42 to its last line, 71, as tests/test_dedup_rules.py has it."""
    lookup = TreeSitterFunctionLookup(CheckoutReader(FIXTURE))
    lab = FunctionSpan("lab", 42, 71)
    assert [lookup.enclosing_function(LAB, line) for line in (42, 43, 46, 57, 71)] == [lab] * 5
    assert lookup.enclosing_function(LAB, 41) is None
    assert FunctionSpan("health_check", 38, 40) in lookup.functions(LAB)


def finding(fid, line, cwe, *, tool, rule):
    return ScanFinding(
        finding_id=fid,
        tool=tool,
        rule_id=rule,
        cwe=tuple(cwe),
        message="m",
        tool_severity="warning",
        file="ping.py",
        start_line=line,
        end_line=line,
    )


def test_the_rule_step_groups_by_the_functions_it_finds(tmp_path):
    """F3, test 1, with the real lookup: Semgrep and Bandit on one line of one function are one
    group, and one rule in two functions three lines apart is not."""
    source = (
        "import subprocess\n\n\n"
        "def run_ping(host):\n"
        '    subprocess.call("ping " + host, shell=True)\n\n\n'
        "def run_trace(host):\n"
        '    subprocess.call("traceroute " + host, shell=True)\n'
    )
    lookup = lookup_for(tmp_path, {"ping.py": source})
    semgrep = "python.lang.security.audit.subprocess-shell-true"
    findings = [
        finding("s", 5, ["CWE-78"], tool="semgrep", rule=semgrep),
        finding("b", 5, ["CWE-77"], tool="bandit", rule="B602"),
        finding("t", 9, ["CWE-78"], tool="semgrep", rule=semgrep),
    ]

    (group,) = group_findings(findings, [RuleStep(lookup, nearby_lines=5)])

    assert sorted(m.finding_id for m in group.members) == ["b", "s"]
    assert group.rule == SAME_FUNCTION
    assert group.reason == (
        "Same function run_ping (lines 4 to 5) and related CWEs (CWE-77 and CWE-78)"
    )
