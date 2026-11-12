"""Converting each dataset's answers to one CSV format."""

import pytest

from app.eval.expected import (
    Expected,
    ExpectedError,
    benchmark_java,
    cwe_bench_java,
    normalize_cwe,
    read_csv,
    write_csv,
)

TESTS = "src/main/java/org/owasp/benchmark/testcode"


def make_benchmark(root, rows):
    (root / TESTS).mkdir(parents=True)
    lines = ["# test name, category, real vulnerability, cwe, Benchmark version: 1.2, 2016-06-1"]
    for name, category, real, cwe in rows:
        lines.append(f"{name},{category},{real},{cwe}")
        (root / TESTS / f"{name}.java").write_text("class X {}\n")
    (root / "expectedresults-1.2.csv").write_text("\n".join(lines) + "\n")


def test_benchmark_java(tmp_path):
    make_benchmark(
        tmp_path,
        [
            ("BenchmarkTest00001", "pathtraver", "true", "22"),
            ("BenchmarkTest00002", "hash", "false", "328"),
        ],
    )
    first, second = benchmark_java(tmp_path, "abc")
    assert first == Expected(
        "benchmark-java",
        "BenchmarkTest00001",
        "CWE-22",
        f"{TESTS}/BenchmarkTest00001.java",
        None,
        None,
        "",
        "abc",
        True,
    )
    assert second.real is False and second.cwe == "CWE-328"


def test_benchmark_case_without_file(tmp_path):
    make_benchmark(tmp_path, [("BenchmarkTest00001", "pathtraver", "true", "22")])
    (tmp_path / TESTS / "BenchmarkTest00001.java").unlink()
    with pytest.raises(ExpectedError, match="has no file"):
        benchmark_java(tmp_path, "abc")


def test_benchmark_bad_real_value(tmp_path):
    make_benchmark(tmp_path, [("BenchmarkTest00001", "pathtraver", "yes", "22")])
    with pytest.raises(ExpectedError, match="real="):
        benchmark_java(tmp_path, "abc")


@pytest.mark.parametrize("value", ["22", "CWE-022", "cwe-22", " CWE-22 "])
def test_normalize_cwe(value):
    assert normalize_cwe(value) == "CWE-22"


def test_normalize_cwe_rejects_other_text():
    with pytest.raises(ExpectedError):
        normalize_cwe("path traversal")


PROJECTS = """id,project_slug,cve_id,cwe_id,cwe_name,github_username,github_repository_name,\
github_tag,github_url,advisory_id,buggy_commit_id,fix_commit_ids
1,acme__app_CVE-2020-1_1.0,CVE-2020-1,CWE-022,Path Traversal,acme,app,1.0,\
https://github.com/acme/app,GHSA-x,bad1,fix1
"""
FIXES = """project_slug,cve_id,github_username,github_repository_name,commit,file,class,\
class_start,class_end,method,method_start,method_end,signature
acme__app_CVE-2020-1_1.0_x,CVE-2020-1,acme,app,fix1,src/A.java,A,1,90,read,10,20,"void read()"
acme__app_CVE-2020-1_1.0,CVE-2020-1,acme,app,fix1,src/B.java,B,5,50,,,,
acme__other_CVE-2021-9_2.0,CVE-2021-9,acme,other,fix9,src/C.java,C,1,9,run,2,3,"void run()"
"""


def test_cwe_bench_java_joins_by_cve(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data/project_info.csv").write_text(PROJECTS)
    (tmp_path / "data/fix_info.csv").write_text(FIXES)
    rows = cwe_bench_java(tmp_path)
    # The first row's slug differs from project_info.csv but its CVE matches. The second has no
    # method lines, so it uses the class lines. CVE-2021-9 isn't a project, so it is skipped.
    assert [(r.case_id, r.file, r.start_line, r.end_line, r.method) for r in rows] == [
        ("CVE-2020-1", "src/A.java", 10, 20, "read"),
        ("CVE-2020-1", "src/B.java", 5, 50, ""),
    ]
    assert {r.cwe for r in rows} == {"CWE-22"} and {r.commit for r in rows} == {"fix1"}


def test_csv_round_trip(tmp_path):
    rows = [
        Expected(
            "cwe-bench-java", "CVE-2020-1", "CWE-22", "src/A.java", 10, 20, "read", "fix1", True
        ),
        Expected(
            "benchmark-python",
            "BenchmarkTest00002",
            "CWE-89",
            "testcode/x.py",
            None,
            None,
            "",
            "abc",
            False,
        ),
    ]
    path = tmp_path / "out/expected.csv"
    assert write_csv(rows, path) == 2
    assert path.read_text().splitlines()[0] == (
        "dataset,case_id,cwe,file,start_line,end_line,method,commit,real"
    )
    assert read_csv(path) == rows


def test_read_csv_checks_columns(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_text("case_id,cwe\nA,CWE-22\n")
    with pytest.raises(ExpectedError, match="columns"):
        read_csv(path)
