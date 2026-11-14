"""Reads the build step's java-build.json and writes SpotBugs' inputs to /tmp.

The build step ran code from the scanned project with write access to /build, so nothing in
/build is trusted: every folder must be a plain relative path to a real folder, not a link,
inside /build/work for classes and inside /src for sources.

Writes /tmp/analyze.txt (class folders), /tmp/aux.txt (library jars) and /tmp/sourcepath, and
scan-info.json with the number of class files. Exits with 3 when there is no class file.

With --add-roots, it adds every source folder to originalUriBaseIds in the SARIF file instead.
SpotBugs lists only the folders it found a flagged file in, and the adapter tries each listed
folder for a path SpotBugs wrote without one (docs/finding-format.md, File paths).
"""

import json
import os
import re
import sys
from pathlib import Path

BUILD = Path(os.environ.get("SIEVE_BUILD", "/build"))
SRC = Path(os.environ.get("SIEVE_SRC", "/src"))
OUT = Path(os.environ.get("SIEVE_OUT", "/out"))
WORK = BUILD / "work"
SAFE = re.compile(r"^[A-Za-z0-9._/-]+$")
MAX_JSON_BYTES = 1024 * 1024


def folder(root: Path, relative: object) -> Path | None:
    """root/relative if it is a real folder inside root, reached without a link."""
    if not isinstance(relative, str) or not SAFE.match(relative):
        return None
    parts = relative.split("/")
    if relative.startswith("/") or ".." in parts:
        return None
    path = root
    for part in parts:
        if part in ("", "."):
            continue
        path = path / part
        if path.is_symlink():
            return None
    return path if path.is_dir() and not path.is_symlink() else None


def class_files(path: Path) -> int:
    count = 0
    for _, _, files in os.walk(path):  # os.walk doesn't follow links to folders
        count += sum(1 for name in files if name.endswith(".class"))
    return count


def add_roots() -> int:
    sarif_path = OUT / "results.sarif"
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    roots = Path("/tmp/sourcepath").read_text(encoding="utf-8")
    for run in sarif.get("runs") or []:
        bases = run.setdefault("originalUriBaseIds", {})
        known = {base.get("uri") for base in bases.values() if isinstance(base, dict)}
        for number, root in enumerate(r for r in roots.split(":") if r):
            uri = f"file:{root}/"
            if uri not in known:
                bases[f"SOURCE_FOLDER_{number}"] = {"uri": uri}
    sarif_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return 0


def main() -> int:
    if sys.argv[1:] == ["--add-roots"]:
        return add_roots()
    listing = BUILD / "java-build.json"
    try:
        if listing.is_symlink() or listing.stat().st_size > MAX_JSON_BYTES:
            raise ValueError("not a plain file of at most 1 MB")
        data = json.loads(listing.read_text(encoding="utf-8"))
        class_dirs, source_dirs = data["class_dirs"], data["source_dirs"]
        if not isinstance(class_dirs, list) or not isinstance(source_dirs, list):
            raise ValueError("class_dirs and source_dirs must be lists")
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"can't read {listing}: {error}", file=sys.stderr)
        return 1

    classes = []
    for relative in class_dirs:
        path = folder(WORK, relative)
        if path is None:
            print(f"left out the class folder {relative!r}", file=sys.stderr)
        else:
            classes.append(path)
    sources = []
    for relative in source_dirs:
        path = folder(SRC, relative)
        if path is None:
            print(f"left out the source folder {relative!r}", file=sys.stderr)
        else:
            sources.append(path)
    deps = BUILD / "deps"
    jars = []
    if deps.is_dir() and not deps.is_symlink():
        jars = sorted(
            p
            for p in deps.iterdir()
            if p.suffix == ".jar" and SAFE.match(p.name) and p.is_file() and not p.is_symlink()
        )

    count = sum(class_files(path) for path in classes)
    (OUT / "scan-info.json").write_text(json.dumps({"files_scanned": count}), encoding="utf-8")
    print(f"{count} class files in {len(classes)} folders, {len(jars)} libraries")
    if count == 0:
        return 3
    Path("/tmp/analyze.txt").write_text("".join(f"{p}\n" for p in classes), encoding="utf-8")
    Path("/tmp/aux.txt").write_text("".join(f"{p}\n" for p in jars), encoding="utf-8")
    Path("/tmp/sourcepath").write_text(":".join(str(p) for p in sources), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
