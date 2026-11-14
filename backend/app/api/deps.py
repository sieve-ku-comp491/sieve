"""Settings of the API, and what the endpoints get from them."""

import os
from dataclasses import dataclass
from pathlib import Path

from fastapi import HTTPException, Request

from app.store.queries import FindingsReader


@dataclass(frozen=True)
class Settings:
    token: str | None
    database_url: str | None
    data_dir: Path

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            token=os.environ.get("SIEVE_API_TOKEN"),
            database_url=os.environ.get("DATABASE_URL"),
            data_dir=Path(os.environ.get("SIEVE_DATA_DIR", "/data")),
        )


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_reader(request: Request) -> FindingsReader:
    settings = get_settings(request)
    if not settings.database_url:
        raise HTTPException(503, "DATABASE_URL is not set")
    return FindingsReader(settings.database_url)
