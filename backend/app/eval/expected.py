"""Convert each dataset's answers to one CSV format (docs/evaluation.md, "Expected results")."""

import csv
import re
from collections.abc import Iterable
from dataclasses import astuple, dataclass, fields
from pathlib import Path

BENCHMARK_JAVA_TESTS = "src/main/java/org/owasp/benchmark/testcode"
BENCHMARK_PYTHON_TESTS = "testcode"
CWE = re.compile(r"^(?:CWE-)?0*(\d+)$", re.IGNORECASE)


class ExpectedError(ValueError):
    """A dataset file that doesn't have the shape we expect."""


@dataclass(frozen=True)
class Expected:
    """One known answer: a location that is, or is not, a real vulnerability."""

    dataset: str
    case_id: str
    cwe: str
    file: str
    start_line: int | None
    end_line: int | None
    method: str
    commit: str
    real: bool


COLUMNS = [field.name for field in fields(Expected)]


def normalize_cwe(value: str) -> str:
    """'22', 'CWE-022' and 'cwe-22' all become 'CWE-22', the form findings use."""
    match = CWE.match(value.strip())
    if not match:
        raise ExpectedError(f"not a CWE: {value!r}")
    return f"CWE-{int(match.group(1))}"


def benchmark(dataset: str, root: Path, answers: str, tests_dir: str, suffix: str, commit: str):
    """The OWASP Benchmark's expectedresults CSV: one test case per file, judged as a whole."""
    rows = []
    with (root / answers).open(encoding="utf-8", newline="") as handle:
        for line in csv.reader(handle):
            if not line or line[0].startswith("#"):
                continue
            if len(line) < 4:
                raise ExpectedError(f"{answers}: short row {line}")
            name, _category, real, cwe = (cell.strip() for cell in line[:4])
            if real not in {"true", "false"}:
                raise ExpectedError(f"{answers}: {name} has real={real!r}")
            file = f"{tests_dir}/{name}{suffix}"
            if not (root / file).is_file():
                raise ExpectedError(f"{answers}: {name} has no file {file}")
            rows.append(
                Expected(
                    dataset, name, normalize_cwe(cwe), file, None, None, "", commit, real == "true"
                )
            )
    return rows


def benchmark_java(root: Path, commit: str) -> list[Expected]:
    return benchmark(
        "benchmark-java", root, "expectedresults-1.2.csv", BENCHMARK_JAVA_TESTS, ".java", commit
    )


def benchmark_python(root: Path, commit: str) -> list[Expected]:
    return benchmark(
        "benchmark-python", root, "expectedresults-0.1.csv", BENCHMARK_PYTHON_TESTS, ".py", commit
    )


def cwe_bench_java(root: Path) -> list[Expected]:
    """CWE-Bench-Java: the methods each CVE's fix changed, all real vulnerabilities.

    fix_info.csv gives line numbers in the fix commit, not the vulnerable one, so each row keeps
    that commit and the method name. Rows join project_info.csv by CVE ID, because a few project
    slugs differ between the two files, and CVEs that aren't among the projects are skipped.
    """
    with (root / "data/project_info.csv").open(encoding="utf-8", newline="") as handle:
        projects = {row["cve_id"]: row for row in csv.DictReader(handle)}
    rows = []
    with (root / "data/fix_info.csv").open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            project = projects.get(row["cve_id"])
            if project is None:
                continue
            start, end = row["method_start"], row["method_end"]
            if not start:
                start, end = row["class_start"], row["class_end"]
            rows.append(
                Expected(
                    dataset="cwe-bench-java",
                    case_id=row["cve_id"],
                    cwe=normalize_cwe(project["cwe_id"]),
                    file=row["file"],
                    start_line=int(start) if start else None,
                    end_line=int(end) if end else None,
                    method=row["method"],
                    commit=row["commit"],
                    real=True,
                )
            )
    return rows


def write_csv(rows: Iterable[Expected], path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(COLUMNS)
        for row in rows:
            values = list(astuple(row))
            values[-1] = "true" if row.real else "false"
            writer.writerow("" if value is None else value for value in values)
            count += 1
    return count


def read_csv(path: Path) -> list[Expected]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != COLUMNS:
            raise ExpectedError(f"{path}: columns must be {COLUMNS}")
        return [
            Expected(
                dataset=row["dataset"],
                case_id=row["case_id"],
                cwe=row["cwe"],
                file=row["file"],
                start_line=int(row["start_line"]) if row["start_line"] else None,
                end_line=int(row["end_line"]) if row["end_line"] else None,
                method=row["method"],
                commit=row["commit"],
                real=row["real"] == "true",
            )
            for row in reader
        ]
