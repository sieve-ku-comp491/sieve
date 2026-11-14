"""The FastAPI back end."""

from fastapi import FastAPI

from app.api import findings, reviews, scans
from app.api.deps import Settings
from app.api.models import Health

VERSION = "0.1.0"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    app = FastAPI(title="Sieve", version=VERSION)
    app.state.settings = settings

    @app.get("/health", response_model=Health, tags=["health"])
    def health():
        return {"status": "ok"}

    app.include_router(scans.router)
    app.include_router(findings.router)
    app.include_router(reviews.router)
    return app


app = create_app()
