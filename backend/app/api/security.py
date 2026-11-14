"""The two checks every request to the API passes first (docs/architecture.md, deployment view).

The Host header must be localhost or 127.0.0.1, so a web page the researcher visits can't reach
the API through DNS rebinding: its requests carry the page's own host name. And the request must
carry the API token from .env as "Authorization: Bearer <token>". Only nginx and the CLI have it.
"""

import hmac

from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

ALLOWED_HOSTS = ["localhost", "127.0.0.1"]


class TokenMiddleware:
    """Refuses every HTTP request without the token, including /docs and /openapi.json. With no
    token configured, the API refuses everything rather than run open."""

    def __init__(self, app: ASGIApp, token: str | None):
        self.app = app
        self.token = (token or "").encode("utf-8")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if not self.token:
            response = JSONResponse(
                {"detail": "the API token is not set: add SIEVE_API_TOKEN to .env"},
                status_code=503,
            )
            await response(scope, receive, send)
            return
        scheme, _, given = Headers(scope=scope).get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(
            given.strip().encode("utf-8"), self.token
        ):
            response = JSONResponse(
                {"detail": "missing or wrong API token"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)
