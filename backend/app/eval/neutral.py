"""Copies of the OWASP Benchmarks with neutral names (docs/evaluation.md, "Neutral copies").

A model may have seen the Benchmarks during training, so it could recognize a test case by its
name, its category in the URL or the project's own headers, instead of judging the code. The
Benchmarks' comments also hint at the answer, such as "condition 'B', which is safe". The copy keeps
only the code that a scan needs, removes every comment, gives every test case and category a random
neutral name, and renames the project's package. The answers and the mapping back to the original
names go to a separate folder that is never part of a scan, because the triage agent's tools read
only the scanned checkout.
"""

import csv
import fnmatch
import io
import os
import random
import re
import secrets
import shutil
import subprocess
import tokenize
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

from app.eval import expected

COMMENT = re.compile(r"/\*.*?\*/\n?|'''.*?'''\n?|\"\"\".*?\"\"\"\n?|<!--.*?-->\n?", re.DOTALL)
TEST_NAME = re.compile(r"BenchmarkTest(\d{5})")
LEFTOVER_WORDS = (("BENCHMARK", "CASE"), ("Benchmark", "Case"), ("benchmark", "case"))
AUTHORS = ("Wichers", "Cartsonis")
MARKERS = ("OWASP Benchmark", "Benchmark Project", *AUTHORS)
PROJECT_NAME = ("OWASP Benchmark", "Sample App")
MARKUP_COMMENT = re.compile(r"<!--.*?-->|<%--.*?--%>", re.DOTALL)
MARKUP_SUFFIXES = {".html", ".htm", ".xml", ".jsp"}
# A fixed date makes the copy's commit depend only on its files, so the same seed gives the same
# commit.
COMMIT_DATE = "2000-01-01T00:00:00+0000"


class NeutralError(RuntimeError):
    """A neutral copy that couldn't be made or still names the Benchmark."""


@dataclass(frozen=True)
class Profile:
    """What to copy from one Benchmark, and how to make it neutral.

    keep: the paths a scan needs. Everything else, such as the answers, the tools' saved results,
    the scorecards and the README, stays out.
    drop: file name patterns left out even inside kept paths, such as the category index pages,
    whose headings name each vulnerability class.
    remove: regular expressions deleted from every text file, such as the project's own pom
    metadata.
    renames: exact text replaced in contents and paths, such as the project's package name.
    allowed: regular expressions for real uses of OWASP libraries, which the leak check accepts.
    allowed_files: library files kept as they are, such as ESAPI's own properties file, which
    names OWASP because ESAPI is an OWASP library.
    """

    dataset: str
    answers: str
    keep: tuple[str, ...]
    drop: tuple[str, ...]
    remove: tuple[str, ...]
    renames: tuple[tuple[str, str], ...]
    allowed: tuple[str, ...]
    allowed_files: tuple[str, ...]
    read_expected: Callable[[Path, str], list[expected.Expected]]


PROFILES = {
    "benchmark-java": Profile(
        dataset="benchmark-java",
        answers="expectedresults-1.2.csv",
        keep=("pom.xml", "src/main", "src/config"),
        drop=("*Index*.html",),
        remove=(
            r"[ \t]*<name>OWASP Benchmark[^<]*</name>\n",
            r"[ \t]*<description>[^<]*</description>\n",
            r"[ \t]*<url>https://github\.com/OWASP-Benchmark[^<]*</url>\n",
            r"[ \t]*<developers>.*?</developers>\n",
            r"[ \t]*<organization>.*?</organization>\n",
            r"(?m)^testCases\.per\.folder=[^\n]*\n",
            r"(?m)^testsuite-version=[^\n]*\n",
        ),
        renames=(
            ("<groupId>org.owasp</groupId>", "<groupId>org.example</groupId>"),
            ('class="safe"', 'class="input"'),
            ("OWASP_Benchmark", "Sample_App"),
            ("org.owasp.benchmark", "org.example.app"),
            ("org/owasp/benchmark", "org/example/app"),
        ),
        allowed=(
            r"org\.owasp\s*\.\s*(?:esapi|encoder)",
            r"owasp-java-encoder",
            r"OWASP Enterprise Security API",
            r"OWASP XXE cheat sheet",
        ),
        allowed_files=("src/main/resources/ESAPI.properties",),
        read_expected=expected.benchmark_java,
    ),
    "benchmark-python": Profile(
        dataset="benchmark-python",
        answers="expectedresults-0.1.csv",
        keep=("app.py", "helpers", "templates", "testcode", "testfiles", "requirements.txt"),
        drop=("*Index*.html",),
        remove=(),
        renames=(('class="safe"', 'class="input"'),),
        allowed=(),
        allowed_files=(),
        read_expected=expected.benchmark_python,
    ),
}


@dataclass
class Names:
    """The random neutral name of every test case and category."""

    cases: dict[str, str]
    categories: dict[str, str]

    @classmethod
    def make(cls, case_ids: list[str], categories: list[str], seed: int) -> "Names":
        rng = random.Random(seed)
        shuffled_cases = sorted(case_ids)
        rng.shuffle(shuffled_cases)
        shuffled_categories = sorted(categories)
        rng.shuffle(shuffled_categories)
        return cls(
            cases={name: f"Case{i:05d}" for i, name in enumerate(shuffled_cases, 1)},
            categories={name: f"area{i:02d}" for i, name in enumerate(shuffled_categories, 1)},
        )


class Rewriter:
    def __init__(self, profile: Profile, names: Names):
        self.profile = profile
        self.names = names
        words = "|".join(sorted(map(re.escape, names.categories), key=len, reverse=True))
        self.category = re.compile(rf"\b({words})(?=-(?:\d{{2}}|Index)\b)")

    def text(self, content: str, suffix: str) -> str:
        content = strip_comments(content, suffix)
        content = COMMENT.sub(
            lambda m: "" if any(word in m.group(0) for word in MARKERS) else m.group(0), content
        )
        for pattern in self.profile.remove:
            content = re.sub(pattern, "", content, flags=re.DOTALL)
        content = content.replace(*PROJECT_NAME)
        return self.names_in(content)

    def path(self, relative: str) -> str:
        return self.names_in(relative)

    def names_in(self, value: str) -> str:
        value = TEST_NAME.sub(lambda m: self.names.cases.get(m.group(0), m.group(0)), value)
        value = self.category.sub(lambda m: self.names.categories[m.group(1)], value)
        for old, new in self.profile.renames:
            value = value.replace(old, new)
        for old, new in LEFTOVER_WORDS:
            value = value.replace(old, new)
        return value


def strip_comments(text: str, suffix: str) -> str:
    """Remove every comment from a Java, Python, markup or properties file.

    A Benchmark case is scored per file, so no line number depends on the comments. A line that
    held only a comment is dropped, and the others keep their code.
    """
    if suffix == ".java":
        stripped = _strip_java(text)
    elif suffix == ".py":
        stripped = _strip_python(text)
    elif suffix in MARKUP_SUFFIXES:
        stripped = MARKUP_COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    elif suffix == ".properties":
        stripped = "\n".join(
            "" if line.lstrip().startswith(("#", "!")) else line for line in text.split("\n")
        )
    else:
        return text
    return _tidy(stripped, text)


def _strip_java(text: str) -> str:
    """Java comments, read past string and character literals and text blocks."""
    out, i, n = [], 0, len(text)
    while i < n:
        if text.startswith('"""', i):
            end = text.find('"""', i + 3)
            end = n if end < 0 else end + 3
            out.append(text[i:end])
            i = end
        elif text[i] in "\"'":
            quote, end = text[i], i + 1
            while end < n and text[end] not in (quote, "\n"):
                end += 2 if text[end] == "\\" else 1
            end = min(end + 1, n)
            out.append(text[i:end])
            i = end
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end < 0 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            out.append("\n" * text.count("\n", i, end))
            i = end
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def _strip_python(text: str) -> str:
    lines = text.split("\n")
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, SyntaxError) as error:
        raise NeutralError(f"can't read the Python file to remove its comments: {error}") from None
    for token in reversed(tokens):
        if token.type == tokenize.COMMENT:
            (row, start), (_, end) = token.start, token.end
            lines[row - 1] = lines[row - 1][:start] + lines[row - 1][end:]
    return "\n".join(lines)


def _tidy(stripped: str, original: str) -> str:
    """Drop the lines that held only a comment, and the spaces a comment leaves at a line's end."""
    new_lines, old_lines = stripped.split("\n"), original.split("\n")
    if len(new_lines) != len(old_lines):
        raise NeutralError("removing comments changed the number of lines")
    return "\n".join(
        new.rstrip()
        for new, old in zip(new_lines, old_lines, strict=True)
        if new.strip() or not old.strip()
    )


def categories(root: Path, answers: str) -> list[str]:
    with (root / answers).open(encoding="utf-8", newline="") as handle:
        rows = [row for row in csv.reader(handle) if row and not row[0].startswith("#")]
    return sorted({row[1].strip() for row in rows})


def make_copy(
    profile: Profile,
    root: Path,
    commit: str,
    dest: Path,
    answers_dir: Path,
    seed: int | None = None,
) -> list[str]:
    """Write the neutral copy to dest and the answers to answers_dir. Returns any leaks found."""
    if dest.resolve() == answers_dir.resolve() or answers_dir.resolve().is_relative_to(
        dest.resolve()
    ):
        raise NeutralError("the answers must not be inside the neutral copy")
    seed = secrets.randbits(63) if seed is None else seed
    rows = profile.read_expected(root, commit)
    names = Names.make([row.case_id for row in rows], categories(root, profile.answers), seed)
    rewriter = Rewriter(profile, names)

    if dest.exists():
        shutil.rmtree(dest)
    files = {}
    for kept in profile.keep:
        source = root / kept
        paths = (
            [source] if source.is_file() else sorted(p for p in source.rglob("*") if p.is_file())
        )
        for path in paths:
            if any(fnmatch.fnmatch(path.name, pattern) for pattern in profile.drop):
                continue
            relative = path.relative_to(root).as_posix()
            target = dest / rewriter.path(relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            data = path.read_bytes()
            try:
                text = rewriter.text(data.decode("utf-8"), path.suffix)
                # "\n" on every system, so a copy made on Windows has the same bytes.
                target.write_text(text, encoding="utf-8", newline="\n")
            except UnicodeDecodeError:
                target.write_bytes(data)
            files[relative] = target.relative_to(dest).as_posix()

    answers_dir.mkdir(parents=True, exist_ok=True)
    (answers_dir / "seed.txt").write_text(f"{seed}\n", encoding="utf-8")
    with (answers_dir / "mapping.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["kind", "original", "neutral"])
        writer.writerows(("case", old, new) for old, new in sorted(names.cases.items()))
        writer.writerows(("category", old, new) for old, new in sorted(names.categories.items()))
        writer.writerows(("file", old, new) for old, new in sorted(files.items()))
    neutral_rows = [
        replace(row, case_id=names.cases[row.case_id], file=files[row.file], commit="")
        for row in rows
    ]
    expected.write_csv(neutral_rows, answers_dir / "expected.csv")
    return leaks(dest, profile, names)


def leaks(dest: Path, profile: Profile, names: Names) -> list[str]:
    """Every place in the copy that still names the Benchmark, its categories or its authors, and
    every source file that still has a comment."""
    words = "|".join(map(re.escape, names.categories))
    patterns = [
        re.compile(r"benchmark|expectedresults", re.IGNORECASE),
        re.compile(r"owasp", re.IGNORECASE),
        re.compile(rf"\b(?:{words})-(?:\d{{2}}|Index)\b"),
        re.compile("|".join(AUTHORS)),
    ]
    allowed = re.compile("|".join(profile.allowed)) if profile.allowed else None
    found = []
    for path in sorted(p for p in dest.rglob("*") if p.is_file()):
        relative = path.relative_to(dest).as_posix()
        if relative in profile.allowed_files:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = ""
        if text and strip_comments(text, path.suffix) != text:
            found.append(f"{relative}: comment")
        if allowed:
            # Blank out allowed matches but keep their line breaks, so line numbers stay right.
            text = allowed.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)
        for number, line in enumerate([relative, *text.splitlines()]):
            for pattern in patterns:
                match = pattern.search(line)
                if match:
                    where = relative if number == 0 else f"{relative}:{number}"
                    found.append(f"{where}: {match.group(0)}")
    return found


def commit_copy(dest: Path) -> str:
    """Make the copy a git repository with one commit, so a scan can check out an exact commit."""
    # The settings that change a commit between machines are fixed here: line ending conversion,
    # signing, the author and the date.
    git = [
        "git",
        "-C",
        str(dest),
        "-c",
        "user.name=sieve-eval",
        "-c",
        "user.email=eval@localhost",
        "-c",
        "core.autocrlf=false",
        "-c",
        "commit.gpgsign=false",
    ]
    env = {**os.environ, "GIT_AUTHOR_DATE": COMMIT_DATE, "GIT_COMMITTER_DATE": COMMIT_DATE}
    for args in (
        ["init", "--quiet"],
        ["add", "--all"],
        ["commit", "--quiet", "-m", "neutral copy"],
    ):
        result = subprocess.run([*git, *args], capture_output=True, text=True, env=env)
        if result.returncode != 0:
            raise NeutralError(f"git {args[0]} failed: {result.stderr.strip()}")
    head = subprocess.run([*git, "rev-parse", "HEAD"], capture_output=True, text=True)
    return head.stdout.strip()
