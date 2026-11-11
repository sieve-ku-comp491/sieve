"""Check that every image and dependency is pinned (requirement N6, test 4).

Fails when a Dockerfile's FROM line or an image in a Compose file has no tag
or uses latest, when a Python requirements file has a package without an
exact version, or when a package.json has no committed package-lock.json.
Run from the repository root: python3 scripts/check_pins.py
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP = {".git", "node_modules", ".venv", "dist"}


def files(pattern: str) -> list[Path]:
    return sorted(p for p in ROOT.rglob(pattern) if not SKIP & set(p.relative_to(ROOT).parts))


def image_problem(image: str) -> str | None:
    if "@sha256:" in image:
        return None
    name = image.rsplit("/", 1)[-1]
    if ":" not in name:
        return "has no tag"
    if name.rsplit(":", 1)[1] == "latest":
        return "uses latest"
    return None


def check_dockerfiles(errors: list[str]) -> None:
    for path in files("Dockerfile*"):
        stages: set[str] = set()
        for number, line in enumerate(path.read_text().splitlines(), 1):
            match = re.match(r"\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", line, re.I)
            if not match:
                continue
            image, stage = match.group(1), match.group(2)
            if image.lower() not in stages and image != "scratch":
                problem = image_problem(image)
                if problem:
                    errors.append(f"{path.relative_to(ROOT)}:{number}: image {image} {problem}")
            if stage:
                stages.add(stage.lower())


def check_compose(errors: list[str]) -> None:
    for pattern in ("docker-compose*.yml", "docker-compose*.yaml", "compose*.yml", "compose*.yaml"):
        for path in files(pattern):
            for number, line in enumerate(path.read_text().splitlines(), 1):
                match = re.match(r"\s*image:\s*[\"']?([^\"'\s#]+)", line)
                if match:
                    problem = image_problem(match.group(1))
                    if problem:
                        errors.append(
                            f"{path.relative_to(ROOT)}:{number}: image {match.group(1)} {problem}"
                        )


def check_requirements(errors: list[str]) -> None:
    for path in files("requirements*.txt"):
        for number, line in enumerate(path.read_text().splitlines(), 1):
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("-r ") or line.startswith("--"):
                continue
            if not re.match(r"^[A-Za-z0-9._\[\],-]+==[^=<>~!*]+$", line):
                errors.append(f"{path.relative_to(ROOT)}:{number}: {line} is not pinned with ==")


def check_lock_files(errors: list[str]) -> None:
    for path in files("package.json"):
        lock = path.with_name("package-lock.json")
        if not lock.exists():
            errors.append(f"{path.relative_to(ROOT)}: no package-lock.json next to it")
            continue
        if json.loads(lock.read_text()).get("lockfileVersion", 0) < 2:
            errors.append(f"{lock.relative_to(ROOT)}: lockfileVersion is older than 2")


def main() -> int:
    errors: list[str] = []
    check_dockerfiles(errors)
    check_compose(errors)
    check_requirements(errors)
    check_lock_files(errors)
    for error in errors:
        print(error)
    if errors:
        print(f"{len(errors)} unpinned version(s)")
        return 1
    print("every image and dependency is pinned")
    return 0


if __name__ == "__main__":
    sys.exit(main())
