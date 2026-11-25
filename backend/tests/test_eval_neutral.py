"""Neutral copies of the OWASP Benchmarks."""

import csv
import subprocess

import pytest

from app.eval.expected import read_csv
from app.eval.neutral import (
    PROFILES,
    Names,
    NeutralError,
    Rewriter,
    commit_copy,
    leaks,
    make_copy,
    strip_comments,
)

HEADER = """'''
OWASP Benchmark for Python v0.1

This file is part of the Open Web Application Security Project (OWASP) Benchmark Project.
  Author: Theo Cartsonis
'''
"""


def make_python_benchmark(root):
    (root / "testcode").mkdir(parents=True)
    (root / "templates/web/sqli-00").mkdir(parents=True)
    (root / "results").mkdir()
    (root / "expectedresults-0.1.csv").write_text(
        "# test name, category, real vulnerability, cwe, Benchmark version: 0.1\n"
        "BenchmarkTest00001,sqli,true,89\n"
        "BenchmarkTest00002,xss,false,79\n"
    )
    (root / "app.py").write_text(
        HEADER + "files = [f for f in names if f.startswith('Benchmark')]\n"
    )
    for name, category in (("BenchmarkTest00001", "sqli"), ("BenchmarkTest00002", "xss")):
        (root / f"testcode/{name}.py").write_text(
            HEADER + f"@app.route('/benchmark/{category}-00/{name}')\ndef {name}_get(): pass\n"
        )
    (root / "templates/web/sqli-00/BenchmarkTest00001.html").write_text(
        "<title>OWASP Benchmark</title>\n"
    )
    (root / "templates/web/sqli-Index.html").write_text("<h1>SQL Injection Test Case Index</h1>\n")
    (root / "README.md").write_text("OWASP Benchmark\n")
    (root / "results/Bandit.sarif").write_text("{}\n")


def test_python_copy_has_no_trace_of_the_benchmark(tmp_path):
    make_python_benchmark(tmp_path / "src")
    dest, answers = tmp_path / "neutral", tmp_path / "answers"
    leaks = make_copy(PROFILES["benchmark-python"], tmp_path / "src", "abc", dest, answers, seed=1)
    assert leaks == []
    files = sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file())
    # The answers, the tools' results, the README and the category index pages stay out.
    assert not any("Index" in f or f.startswith(("results", "README", "expected")) for f in files)
    assert all("Benchmark" not in f and "sqli" not in f for f in files)
    app = (dest / "app.py").read_text()
    assert app == "files = [f for f in names if f.startswith('Case')]\n"

    mapping = {
        (row["kind"], row["original"]): row["neutral"]
        for row in csv.DictReader((answers / "mapping.csv").open())
    }
    new_name = mapping[("case", "BenchmarkTest00001")]
    area = mapping[("category", "sqli")]
    test = (dest / f"testcode/{new_name}.py").read_text()
    assert test == f"@app.route('/case/{area}-00/{new_name}')\ndef {new_name}_get(): pass\n"
    assert (dest / f"templates/web/{area}-00/{new_name}.html").read_text() == (
        "<title>Sample App</title>\n"
    )

    rows = read_csv(answers / "expected.csv")
    assert {row.case_id for row in rows} == {new_name, mapping[("case", "BenchmarkTest00002")]}
    assert all((dest / row.file).is_file() for row in rows)
    assert (answers / "seed.txt").read_text() == "1\n"


def test_same_seed_same_names(tmp_path):
    make_python_benchmark(tmp_path / "src")
    for name in ("a", "b"):
        make_copy(
            PROFILES["benchmark-python"],
            tmp_path / "src",
            "abc",
            tmp_path / name,
            tmp_path / f"{name}-answers",
            seed=42,
        )
    assert (tmp_path / "a-answers/mapping.csv").read_text() == (
        tmp_path / "b-answers/mapping.csv"
    ).read_text()


def test_answers_must_stay_outside_the_copy(tmp_path):
    make_python_benchmark(tmp_path / "src")
    with pytest.raises(NeutralError):
        make_copy(
            PROFILES["benchmark-python"],
            tmp_path / "src",
            "abc",
            tmp_path / "copy",
            tmp_path / "copy/answers",
            seed=1,
        )


def test_leaks_are_reported(tmp_path):
    make_python_benchmark(tmp_path / "src")
    (tmp_path / "src/helpers").mkdir()
    (tmp_path / "src/helpers/utils.py").write_text('HELP = "https://owasp.org/x"\n')
    leaks = make_copy(
        PROFILES["benchmark-python"],
        tmp_path / "src",
        "abc",
        tmp_path / "neutral",
        tmp_path / "answers",
        seed=1,
    )
    assert leaks == ["helpers/utils.py:1: owasp"]


JAVA_TEST = """package org.owasp.benchmark.testcode;
/**
 * OWASP Benchmark v1.2
 *
 * @author Dave Wichers
 */
import org.owasp.esapi.ESAPI;

@WebServlet(value = "/xss-00/BenchmarkTest00001")
public class BenchmarkTest00001 extends HttpServlet {
    String safe = org.owasp
            .esapi.ESAPI.encoder().encodeForHTML(param);
}
"""
POM = """<project>
    <groupId>org.owasp</groupId>
    <artifactId>benchmark</artifactId>
    <name>OWASP Benchmark for Java</name>
    <description>OWASP Benchmark is a Java test suite.</description>
    <url>https://github.com/OWASP-Benchmark/BenchmarkJava</url>
    <developers>
        <developer><name>Dave Wichers</name></developer>
    </developers>
    <organization>
        <name>OWASP Foundation</name>
    </organization>
    <dependency><groupId>org.owasp.esapi</groupId></dependency>
</project>
"""


def test_java_copy_renames_the_package_and_keeps_esapi(tmp_path):
    src = tmp_path / "src"
    tests = src / "src/main/java/org/owasp/benchmark/testcode"
    tests.mkdir(parents=True)
    (tests / "BenchmarkTest00001.java").write_text(JAVA_TEST)
    (src / "pom.xml").write_text(POM)
    (src / "expectedresults-1.2.csv").write_text("# header\nBenchmarkTest00001,xss,true,79\n")
    (src / "src/main/resources").mkdir(parents=True)
    (src / "src/main/resources/benchmark.properties").write_text(
        "# used by test cases in the OWASP Benchmark\nhashAlg1=MD5\ntestCases.per.folder=80\n"
        "testsuite-version=1.2\n"
    )
    dest = tmp_path / "neutral"
    leaks = make_copy(PROFILES["benchmark-java"], src, "abc", dest, tmp_path / "answers", seed=3)
    assert leaks == []
    (copied,) = (dest / "src/main/java/org/example/app/testcode").iterdir()
    text = copied.read_text()
    assert text.startswith("package org.example.app.testcode;\nimport org.owasp.esapi.ESAPI;")
    assert f"public class {copied.stem} extends HttpServlet" in text
    assert "org.owasp\n            .esapi.ESAPI" in text
    assert (dest / "src/main/resources/case.properties").read_text() == "hashAlg1=MD5\n"
    assert (dest / "pom.xml").read_text() == (
        "<project>\n    <groupId>org.example</groupId>\n    <artifactId>case</artifactId>\n"
        "    <dependency><groupId>org.owasp.esapi</groupId></dependency>\n</project>\n"
    )


def test_commit_copy(tmp_path):
    (tmp_path / "a.txt").write_text("x\n")
    commit = commit_copy(tmp_path)
    log = subprocess.run(
        ["git", "-C", str(tmp_path), "log", "--format=%H"], capture_output=True, text=True
    ).stdout.split()
    assert log == [commit]


JAVA_WITH_COMMENTS = """package p;
// condition 'B', which is safe
public class A {
    String url = "http://example.org/x"; // a trailing comment
    char quote = '"';
    String star = "/* not a comment */";
    /* a block
       comment */
    int x = 1; /* inline */ int y = 2;
    String block = \"\"\"
        // inside a text block
        \"\"\";
}
"""


def test_strip_java_comments_keeps_strings():
    assert strip_comments(JAVA_WITH_COMMENTS, ".java") == (
        "package p;\n"
        "public class A {\n"
        '    String url = "http://example.org/x";\n'
        "    char quote = '\"';\n"
        '    String star = "/* not a comment */";\n'
        "    int x = 1;  int y = 2;\n"
        '    String block = """\n'
        "        // inside a text block\n"
        '        """;\n'
        "}\n"
    )


def test_strip_python_comments_keeps_strings_and_docstrings():
    source = '"""Docstring # stays."""\n# get the last \'safe\' value\nx = "#not" # trailing\n'
    assert strip_comments(source, ".py") == '"""Docstring # stays."""\nx = "#not"\n'


def test_strip_markup_and_properties_comments():
    assert strip_comments("<p>a</p>\n<!-- safe\n case -->\n<p>b</p>\n", ".html") == (
        "<p>a</p>\n<p>b</p>\n"
    )
    assert strip_comments("# about\nkey=value\n! more\n", ".properties") == "key=value\n"
    assert strip_comments("# stays\n", ".txt") == "# stays\n"


def test_hints_in_comments_and_class_names_are_gone(tmp_path):
    make_python_benchmark(tmp_path / "src")
    test = tmp_path / "src/testcode/BenchmarkTest00001.py"
    test.write_text(test.read_text() + "    # condition 'B', which is safe\n")
    page = tmp_path / "src/templates/web/sqli-00/BenchmarkTest00001.html"
    page.write_text('<input value="x" class="safe">\n')
    dest = tmp_path / "neutral"
    assert (
        make_copy(
            PROFILES["benchmark-python"],
            tmp_path / "src",
            "abc",
            dest,
            tmp_path / "answers",
            seed=1,
        )
        == []
    )
    copied = "\n".join(p.read_text() for p in dest.rglob("*") if p.is_file())
    assert "safe" not in copied
    assert 'class="input"' in copied


def test_a_comment_left_in_the_copy_is_a_leak(tmp_path):
    make_python_benchmark(tmp_path / "src")
    dest = tmp_path / "neutral"
    make_copy(
        PROFILES["benchmark-python"], tmp_path / "src", "abc", dest, tmp_path / "answers", seed=1
    )
    (dest / "app.py").write_text("x = 1  # which is safe\n")

    names = Names.make(["BenchmarkTest00001", "BenchmarkTest00002"], ["sqli", "xss"], 1)
    assert leaks(dest, PROFILES["benchmark-python"], names) == ["app.py: comment"]


def test_same_files_give_the_same_commit(tmp_path):
    commits = []
    for name in ("a", "b"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "a.txt").write_text("x\n")
        commits.append(commit_copy(tmp_path / name))
    assert commits[0] == commits[1]


PY_VALUES = """import markupsafe

def init(app):
    bar = 'safe!'
    lst.append('safe')
    lst.append('moresafe')
    other = "alsosafe"
    user = f'SafeToby{num}'
    bar = param + '_SafeStuff'
    data = yaml.safe_load(text)
"""
JAVA_VALUES = """public class A {
    String bar = "safe!";
    String user = "SafeInga";
    StringBuilder b = new StringBuilder(" SafeStuff");
    String more = "moresafe";
    DocumentBuilderFactory safeDocBuilderFactory = null;
}
"""


@pytest.mark.parametrize(
    "suffix, source, expected",
    [
        (
            ".py",
            PY_VALUES,
            "import markupsafe\n\ndef init(app):\n    bar = 'constant!'\n"
            "    lst.append('constant')\n    lst.append('moreconstant')\n"
            "    other = \"alsoconstant\"\n    user = f'Toby{num}'\n    bar = param + '_Stuff'\n"
            "    data = yaml.safe_load(text)\n",
        ),
        (
            ".java",
            JAVA_VALUES,
            'public class A {\n    String bar = "constant!";\n    String user = "Inga";\n'
            '    StringBuilder b = new StringBuilder(" Stuff");\n'
            '    String more = "moreconstant";\n'
            "    DocumentBuilderFactory safeDocBuilderFactory = null;\n}\n",
        ),
    ],
)
def test_safe_values_get_neutral_words_and_code_names_stay(suffix, source, expected):
    names = Names.make([], [], 1)
    rewriter_profile = PROFILES["benchmark-python" if suffix == ".py" else "benchmark-java"]
    assert Rewriter(rewriter_profile, names).text(source, suffix) == expected


def test_a_safe_value_left_in_test_code_is_a_leak(tmp_path):
    make_python_benchmark(tmp_path / "src")
    dest = tmp_path / "neutral"
    make_copy(
        PROFILES["benchmark-python"], tmp_path / "src", "abc", dest, tmp_path / "answers", seed=1
    )
    (dest / "app.py").write_text("user = f'SafeTheo{num}'\n")
    names = Names.make(["BenchmarkTest00001", "BenchmarkTest00002"], ["sqli", "xss"], 1)
    assert leaks(dest, PROFILES["benchmark-python"], names) == ["app.py: 'SafeTh"]


def test_commit_ignores_line_ending_and_signing_settings(tmp_path, monkeypatch):
    # A machine with autocrlf, as on Windows, and signing turned on, but no key.
    config = tmp_path / "gitconfig"
    config.write_text("[core]\n\tautocrlf = true\n[commit]\n\tgpgsign = true\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    copy = tmp_path / "copy"
    copy.mkdir()
    (copy / "a.txt").write_bytes(b"one\r\ntwo\r\n")
    commit = commit_copy(copy)
    stored = subprocess.run(
        ["git", "-C", str(copy), "cat-file", "-p", f"{commit}:a.txt"],
        capture_output=True,
        check=True,
    ).stdout
    assert stored == b"one\r\ntwo\r\n"
