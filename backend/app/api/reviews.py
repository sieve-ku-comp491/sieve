"""The endpoints that save review decisions and edits: approve and reject into reviews, and
edits into finding_edits, with the state changes of docs/finding-states.md. Written by Furkan
as his part of T2.3. app.main already includes this router."""

from fastapi import APIRouter

router = APIRouter(tags=["reviews"])
