"""Settings of the API, and what the endpoints get from them."""

import os
from dataclasses import dataclass
from pathlib import Path

from fastapi import HTTPException, Request

from app.scan.scope import DEFAULT_SCOPE_FILE
from app.scan.service import ScanService
from app.store.jobs import PostgresJobQueue
from app.store.queries import FindingsReader


@dataclass(frozen=True)
class Settings:
    token: str | None
    database_url: str | None
    data_dir: Path
    scope_file: Path = Path(DEFAULT_SCOPE_FILE)

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            token=os.environ.get("SIEVE_API_TOKEN"),
            database_url=os.environ.get("DATABASE_URL"),
            data_dir=Path(os.environ.get("SIEVE_DATA_DIR", "/data")),
            scope_file=Path(os.environ.get("SIEVE_SCOPE_FILE", DEFAULT_SCOPE_FILE)),
        )


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_reader(request: Request) -> FindingsReader:
    settings = get_settings(request)
    if not settings.database_url:
        raise HTTPException(503, "DATABASE_URL is not set")
    return FindingsReader(settings.database_url)


def get_scan_service(request: Request) -> ScanService:
    """The API side of the scan service: the scope check and the job queue. The queue connects
    only after the scope check has passed, so a refused request never reaches the database."""
    settings = get_settings(request)
    queue = PostgresJobQueue(settings.database_url) if settings.database_url else None
    return ScanService(settings.scope_file, queue=queue)
