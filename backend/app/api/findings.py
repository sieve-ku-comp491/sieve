"""The finding endpoint: one finding with everything the finding detail screen shows."""

from pathlib import Path
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from app.adapters import AdapterError, AdapterRegistry, BaseSarifAdapter, Location
from app.api.deps import Settings, get_reader, get_settings
from app.api.models import FindingDetail
from app.checkout import CheckoutReader
from app.store.queries import FindingsReader

router = APIRouter(prefix="/findings", tags=["findings"])

CONTEXT_LINES = 10
# The most lines the code window holds. A finding longer than that, such as a SpotBugs finding
# on a whole class, shows from CONTEXT_LINES before its first line.
MAX_CODE_LINES = 200
LOCATION_FIELDS = ("file", "start_line", "end_line", "start_column", "end_column", "snippet")


@router.get("/{finding_id}", response_model=FindingDetail)
def get_finding(
    finding_id: UUID,
    reader: Annotated[FindingsReader, Depends(get_reader)],
    settings: Annotated[Settings, Depends(get_settings)],
):
    """One finding with its locations, the code around it, its verdict, edits, reviews and
    duplicate group."""
    finding = reader.get_finding(str(finding_id))
    if finding is None:
        raise HTTPException(404, "no such finding")
    finding["location"] = {name: finding[name] for name in LOCATION_FIELDS}
    flagged = reader.flagged_lines(str(finding["scan_id"]), finding["file"])
    finding["code"] = read_code(settings.data_dir, finding, flagged)
    return finding


def read_code(data_dir: Path, finding: dict, flagged: list[dict]) -> dict | None:
    """The flagged lines with up to CONTEXT_LINES lines around them, at most MAX_CODE_LINES in
    all, from the scan's checkout in the data folder. flagged holds the tool and lines of every
    finding of the scan in the same file, and each is masked by its tool's adapter the same way
    as its stored snippets, so a secret Gitleaks found a few lines away doesn't show either.
    None when the file can't be read, or when one of those tools has no known adapter, since
    then nothing says which lines must be masked."""
    registry = AdapterRegistry()
    try:
        adapters = [(registry.get(row["tool"]), row) for row in flagged]
    except AdapterError:
        return None
    reader = CheckoutReader(data_dir / "scans" / str(finding["scan_id"]) / "src")
    lines = reader.read_lines(finding["file"])
    if lines is None:
        return None
    for adapter, row in adapters:
        if isinstance(adapter, BaseSarifAdapter) and adapter.masks:
            location = Location(finding["file"], row["start_line"], row["end_line"])
            lines = adapter.mask(lines, location)
    first = max(1, finding["start_line"] - CONTEXT_LINES)
    last = min(len(lines), finding["end_line"] + CONTEXT_LINES, first + MAX_CODE_LINES - 1)
    if first > last:
        return None
    return {
        "file": finding["file"],
        "start_line": first,
        "end_line": last,
        "lines": lines[first - 1 : last],
    }
