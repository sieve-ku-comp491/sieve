"""The endpoints that save review decisions and edits: approve and reject into reviews, and
edits into finding_edits, with the state changes of docs/finding-states.md. app.main includes
this router, so its routes pass the token and Host checks of every other endpoint, and each of
them also needs a JSON body and refuses other web pages (json_from_the_ui)."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request

from app.api.deps import get_settings
from app.api.models import EditIn, EditSaved, ReviewIn, ReviewSaved
from app.api.security import json_from_the_ui
from app.cvss import VectorError
from app.store.reviews import Edit, FindingNotFound, ReviewConflict, ReviewStore

router = APIRouter(prefix="/findings", tags=["reviews"], dependencies=[Depends(json_from_the_ui)])

REFUSED = {
    404: {"description": "no such finding"},
    409: {"description": "the finding's state doesn't allow it, with the reason in detail"},
}


def get_store(request: Request) -> ReviewStore:
    settings = get_settings(request)
    if not settings.database_url:
        raise HTTPException(503, "DATABASE_URL is not set")
    return ReviewStore(settings.database_url)


Store = Annotated[ReviewStore, Depends(get_store)]


@router.post(
    "/{finding_id}/reviews", response_model=ReviewSaved, status_code=201, responses=REFUSED
)
def review(finding_id: UUID, body: ReviewIn, store: Store):
    """Approves or rejects the finding as it is now: the AI's verdict with the latest edit, if
    there is one. The latest review counts, so a finding can be approved after a rejection and
    the other way round. Refused before triage and after export."""
    try:
        return store.decide(
            str(finding_id),
            body.decision,
            body.reviewer,
            body.comment,
            None if body.finding_edit_id is None else str(body.finding_edit_id),
        )
    except FindingNotFound as error:
        raise HTTPException(404, "no such finding") from error
    except ReviewConflict as error:
        raise HTTPException(409, str(error)) from error


@router.post("/{finding_id}/edits", response_model=EditSaved, status_code=201, responses=REFUSED)
def edit(finding_id: UUID, body: EditIn, store: Store):
    """Saves the reviewer's changes next to the AI's verdict, which stays as it is. The finding
    becomes edited until the reviewer approves or rejects it again. Refused before triage and
    after export."""
    try:
        return store.edit(
            str(finding_id),
            Edit(body.editor, body.verdict, body.reasoning, body.cvss_v4_vector, body.note),
        )
    except VectorError as error:
        raise HTTPException(422, f"cvss_v4_vector: {error}") from error
    except FindingNotFound as error:
        raise HTTPException(404, "no such finding") from error
    except ReviewConflict as error:
        raise HTTPException(409, str(error)) from error
