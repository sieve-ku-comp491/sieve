"""The FastAPI back end. Every request passes the Host and token checks in app.api.security."""

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api import findings, reviews, scans
from app.api.deps import Settings
from app.api.models import Health
from app.api.security import ALLOWED_HOSTS, TokenMiddleware

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

    # The last middleware added runs first, so the Host check comes before the token check.
    app.add_middleware(TokenMiddleware, token=settings.token)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)

    def openapi() -> dict:
        if app.openapi_schema is None:
            schema = get_openapi(title=app.title, version=app.version, routes=app.routes)
            schema.setdefault("components", {})["securitySchemes"] = {
                "token": {"type": "http", "scheme": "bearer"}
            }
            schema["security"] = [{"token": []}]
            app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = openapi
    return app


app = create_app()
