"""Checks a plug-in's results.sarif before an adapter reads it (docs/interfaces.md, Results)."""

import json
import os
import stat
from functools import cache
from pathlib import Path
from typing import Any

import jsonschema

MAX_SARIF_BYTES = 100 * 1024 * 1024

# The OASIS schema for SARIF 2.1.0 with errata 01, from
# https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json
SCHEMA_FILE = Path(__file__).with_name("sarif-schema-2.1.0.json")


class InvalidSarif(Exception):
    """The run fails with `reason`, missing_sarif or invalid_sarif."""

    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason


@cache
def _validator() -> jsonschema.protocols.Validator:
    schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
    validator_class = jsonschema.validators.validator_for(schema)
    return validator_class(schema)


class SarifValidator:
    def __init__(self, max_bytes: int = MAX_SARIF_BYTES):
        self.max_bytes = max_bytes

    def validate(self, path: Path) -> dict[str, Any]:
        """The parsed SARIF file, or InvalidSarif if it is missing or not valid SARIF 2.1.0."""
        try:
            sarif = json.loads(read_plugin_file(path, self.max_bytes))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise InvalidSarif("invalid_sarif", f"{path.name} is not JSON: {error}") from None
        if not isinstance(sarif, dict) or sarif.get("version") != "2.1.0":
            raise InvalidSarif("invalid_sarif", f"{path.name} is not SARIF version 2.1.0")
        error = jsonschema.exceptions.best_match(_validator().iter_errors(sarif))
        if error is not None:
            where = "/".join(str(part) for part in error.absolute_path) or "the top level"
            raise InvalidSarif(
                "invalid_sarif",
                f"{path.name} fails the SARIF 2.1.0 schema at {where}: {error.message[:300]}",
            )
        # The schema allows any number of runs, the plug-in contract exactly one.
        runs = sarif.get("runs")
        if not isinstance(runs, list) or len(runs) != 1:
            count = len(runs) if isinstance(runs, list) else "no list of"
            raise InvalidSarif("invalid_sarif", f"{path.name} has {count} runs instead of one")
        return sarif


def read_plugin_file(path: Path, max_bytes: int) -> bytes:
    """A file a plug-in wrote to /out, refused unless it is a regular file within the limit.

    The plug-in controls /out, so a symbolic link there could point anywhere in the worker, such
    as /proc/self/environ. Links are refused, not followed.
    """
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise InvalidSarif("missing_sarif", f"{path.name} is missing") from None
    if not stat.S_ISREG(info.st_mode):
        raise InvalidSarif("invalid_sarif", f"{path.name} is not a regular file")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    except OSError as error:
        raise InvalidSarif("invalid_sarif", f"can't open {path.name}: {error}") from None
    with os.fdopen(fd, "rb") as file:
        size = os.fstat(file.fileno()).st_size
        if size > max_bytes:
            raise InvalidSarif("invalid_sarif", f"{path.name} is {size} bytes, over the limit")
        return file.read(max_bytes + 1)


def result_count(sarif: dict[str, Any]) -> int:
    return sum(len(run.get("results") or []) for run in sarif.get("runs", []))


def tool_versions(sarif: dict[str, Any]) -> list[str]:
    """What each run's driver says about itself. Logged, never trusted (docs/interfaces.md)."""
    versions = []
    for run in sarif.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        version = driver.get("semanticVersion") or driver.get("version") or "no version"
        versions.append(f"{driver.get('name', 'unnamed tool')} {version}")
    return versions
