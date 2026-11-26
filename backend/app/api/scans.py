"""The scan endpoints: the scans, the review queue of one scan and the code of its checkout."""

from pathlib import PurePosixPath
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.deps import Settings, get_reader, get_scan_service, get_settings
from app.api.findings import MAX_CODE_LINES, checkout_dir, masked_lines
from app.api.models import (
    Code,
    FindingPage,
    Level,
    Scan,
    ScanDetail,
    ScanStarted,
    StartScan,
    State,
    ToolSeverity,
    Verdict,
)
from app.api.security import json_from_the_ui
from app.checkout import CheckoutError, CheckoutReader
from app.scan import OutOfScope, RefError, ScanService, ScopeError, UrlError
from app.scan.service import NoQueue
from app.store.queries import FindingFilter, FindingsReader

router = APIRouter(prefix="/scans", tags=["scans"])

Reader = Annotated[FindingsReader, Depends(get_reader)]
Service = Annotated[ScanService, Depends(get_scan_service)]


@router.post(
    "",
    status_code=202,
    response_model=ScanStarted,
    dependencies=[Depends(json_from_the_ui)],
    responses={
        403: {
            "description": "the repository is not in the scope file, or the request comes from"
            " a web page other than the review web app"
        },
        415: {"description": "the body is not application/json"},
        422: {"description": "the URL or the commit breaks the rules of requirement F2"},
        500: {"description": "the scope file can't be loaded"},
    },
)
def start_scan(body: StartScan, service: Service):
    """Starts a scan of a repository in the scope file (requirement F2). Like every endpoint
    that changes data, it takes only a JSON body and refuses other web pages by their Origin
    (json_from_the_ui). The scope check runs next, and a refused repository gets an error with
    nothing created. Otherwise the scan is
    queued as a background job: read its progress with GET /scans/{scan_id}."""
    try:
        started = service.start_scan(body.repo_url, body.commit)
    except OutOfScope as error:
        raise HTTPException(403, str(error)) from None
    except (UrlError, RefError) as error:
        raise HTTPException(422, str(error)) from None
    except ScopeError as error:
        raise HTTPException(500, str(error)) from None
    except NoQueue as error:
        raise HTTPException(503, str(error)) from None
    return ScanStarted(
        scan_id=started.scan_id, job_id=started.job_id, repo_url=started.repo_url, status="queued"
    )


@router.get("", response_model=list[Scan])
def list_scans(
    reader: Reader,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
):
    """The scans, newest first."""
    return reader.list_scans(limit, offset)


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: UUID, reader: Reader):
    """One scan with its plug-in runs, its latest triage run and its findings per state."""
    scan = reader.get_scan(str(scan_id))
    if scan is None:
        raise HTTPException(404, "no such scan")
    return scan


@router.get("/{scan_id}/findings", response_model=FindingPage)
def list_findings(
    scan_id: UUID,
    reader: Reader,
    status: Annotated[list[State] | None, Query(description="the finding's state")] = None,
    tool: Annotated[list[str] | None, Query(description="the plug-in, such as semgrep")] = None,
    severity: Annotated[list[Level] | None, Query(description="the CVSS v4.0 level")] = None,
    verdict: Annotated[list[Verdict] | None, Query()] = None,
    tool_severity: Annotated[
        list[ToolSeverity] | None, Query(description="the analyzer's own severity")
    ] = None,
    q: Annotated[
        str | None, Query(max_length=500, description="part of the file path or rule ID")
    ] = None,
    include_hidden: Annotated[
        bool, Query(description="also list findings an earlier review decided")
    ] = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
):
    """The scan's findings, highest severity first. Each filter can be given more than once,
    such as status=triaged&status=edited, and keeps findings that match any of its values.
    Findings without a verdict match no verdict or severity filter."""
    filters = FindingFilter(
        states=list(status or []),
        tools=list(tool or []),
        severities=list(severity or []),
        verdicts=list(verdict or []),
        tool_severities=list(tool_severity or []),
        search=q,
        include_hidden=include_hidden,
    )
    if not reader.scan_exists(str(scan_id)):
        raise HTTPException(404, "no such scan")
    total, items = reader.list_findings(str(scan_id), filters, limit, offset)
    return {"total": total, "limit": limit, "offset": offset, "items": items}


@router.get(
    "/{scan_id}/code",
    response_model=Code,
    responses={
        404: {"description": "no such scan, or the file isn't one the scan's checkout can serve"},
        422: {"description": "the range is not one of the file's lines"},
    },
)
def get_code(
    scan_id: UUID,
    reader: Reader,
    settings: Annotated[Settings, Depends(get_settings)],
    file: Annotated[
        str, Query(min_length=1, max_length=4096, description="a path relative to the checkout")
    ],
    start: Annotated[int, Query(ge=1, le=10_000_000, description="the first line")],
    end: Annotated[int, Query(ge=1, le=10_000_000, description="the last line")],
):
    """Lines start to end of one file of the scan's checkout, for code the finding's code
    window doesn't hold, such as cited lines and injection lines elsewhere. At most 200 lines:
    a longer range stops after 200, and an end past the file stops at its last line, so
    end_line tells where the lines stop. Every finding of the scan in the file is masked as in
    the code window, so a secret Gitleaks found reads REDACTED. A path outside the checkout,
    a file that can't be read, and a file with a finding of a tool whose adapter is unknown
    are not found."""
    if end < start:
        raise HTTPException(422, "end is before start")
    if not reader.scan_exists(str(scan_id)):
        raise HTTPException(404, "no such scan")
    checkout = CheckoutReader(checkout_dir(settings.data_dir, str(scan_id)))
    try:
        target = checkout.resolve(file).relative_to(checkout.root).as_posix()
    except CheckoutError:
        raise HTTPException(404, "no such file in the scan's checkout") from None
    # Findings store paths in this form. A link in the checkout reads its target, so the
    # findings under the target's path are masked too.
    name = PurePosixPath(file).as_posix()
    flagged = reader.flagged_lines(str(scan_id), *{name, target})
    lines = masked_lines(settings.data_dir, str(scan_id), file, flagged)
    if lines is None:
        raise HTTPException(404, "no such file in the scan's checkout")
    if start > len(lines):
        raise HTTPException(422, f"the file has {len(lines)} lines")
    last = min(end, len(lines), start + MAX_CODE_LINES - 1)
    return {"file": name, "start_line": start, "end_line": last, "lines": lines[start - 1 : last]}
