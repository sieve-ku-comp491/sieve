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
    finding["code"] = read_code(settings.data_dir, finding)
    return finding


def read_code(data_dir: Path, finding: dict) -> dict | None:
    """The flagged lines with up to CONTEXT_LINES lines around them, from the scan's checkout in
    the data folder, masked by the tool's adapter the same way as its stored snippets. None when
    the file can't be read, or when no adapter is known for the tool, since then nothing says
    which lines must be masked."""
    try:
        adapter = AdapterRegistry().get(finding["tool"])
    except AdapterError:
        return None
    reader = CheckoutReader(data_dir / "scans" / str(finding["scan_id"]) / "src")
    lines = reader.read_lines(finding["file"])
    if lines is None:
        return None
    if isinstance(adapter, BaseSarifAdapter):
        location = Location(finding["file"], finding["start_line"], finding["end_line"])
        lines = adapter.mask(lines, location)
    first = max(1, finding["start_line"] - CONTEXT_LINES)
    last = min(len(lines), finding["end_line"] + CONTEXT_LINES)
    if first > last:
        return None
    return {
        "file": finding["file"],
        "start_line": first,
        "end_line": last,
        "lines": lines[first - 1 : last],
    }
