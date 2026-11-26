"""The scan endpoints: the scans, and the review queue of one scan."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.deps import get_reader, get_scan_service
from app.api.models import (
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
    responses={
        403: {"description": "the repository is not in the scope file"},
        422: {"description": "the URL or the commit breaks the rules of requirement F2"},
        500: {"description": "the scope file can't be loaded"},
    },
)
def start_scan(body: StartScan, service: Service):
    """Starts a scan of a repository in the scope file (requirement F2). The scope check runs
    first, and a refused repository gets an error with nothing created. Otherwise the scan is
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
    offset: Annotated[int, Query(ge=0)] = 0,
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
    offset: Annotated[int, Query(ge=0)] = 0,
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
