"""The token and Host checks of every request (docs/architecture.md, deployment view)."""

from pathlib import Path

import pytest
from fastapi import WebSocket, WebSocketDisconnect
from fastapi.testclient import TestClient

from app.api.deps import Settings
from app.main import create_app

TOKEN = "k3Jx9-test-token"


def client(base_url="http://localhost", token: str | None = TOKEN) -> TestClient:
    settings = Settings(token=token, database_url=None, data_dir=Path("/data"))
    return TestClient(create_app(settings), base_url=base_url)


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize("base_url", ["http://localhost", "http://127.0.0.1:8000"])
def test_a_request_with_the_token_to_localhost_is_answered(base_url):
    assert client(base_url).get("/health", headers=bearer(TOKEN)).status_code == 200


@pytest.mark.parametrize(
    "headers",
    [
        {},
        bearer("wrong"),
        bearer(""),
        {"Authorization": TOKEN},
        {"Authorization": f"Basic {TOKEN}"},
    ],
)
def test_a_request_without_the_right_token_is_refused(headers):
    response = client().get("/health", headers=headers)
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.parametrize("path", ["/docs", "/openapi.json", "/scans", "/no-such-path"])
def test_every_path_needs_the_token(path):
    assert client().get(path).status_code == 401


@pytest.mark.parametrize(
    "base_url",
    ["http://sieve.attacker.example", "http://192.168.1.20:8000", "http://localhost.evil"],
)
def test_another_host_is_refused_even_with_the_token(base_url):
    assert client(base_url).get("/health", headers=bearer(TOKEN)).status_code == 400


@pytest.mark.parametrize("token", [None, ""])
def test_without_a_configured_token_every_request_is_refused(token):
    response = client(token=token).get("/health", headers=bearer(""))
    assert response.status_code == 503


def echo_client(token: str | None = TOKEN) -> TestClient:
    """A client of an app with one WebSocket route, as a later endpoint could add."""
    app = create_app(Settings(token=token, database_url=None, data_dir=Path("/data")))

    @app.websocket("/echo")
    async def echo(websocket: WebSocket):
        await websocket.accept()
        await websocket.send_text("open")
        await websocket.close()

    return TestClient(app, base_url="http://localhost")


@pytest.mark.parametrize("headers", [{}, bearer("wrong"), bearer(TOKEN + "x")])
def test_a_websocket_without_the_right_token_is_closed(headers):
    with pytest.raises(WebSocketDisconnect) as closed:
        with echo_client().websocket_connect("ws://localhost/echo", headers=headers):
            pass
    assert closed.value.code == 1008


def test_a_websocket_with_the_token_is_answered():
    with echo_client().websocket_connect("ws://localhost/echo", headers=bearer(TOKEN)) as socket:
        assert socket.receive_text() == "open"


def test_without_a_configured_token_every_websocket_is_closed():
    with pytest.raises(WebSocketDisconnect) as closed:
        with echo_client(token=None).websocket_connect("ws://localhost/echo", headers=bearer("")):
            pass
    assert closed.value.code == 1008


@pytest.mark.parametrize("token", [TOKEN, None])
def test_the_server_starts_and_stops_without_the_token(token):
    with client(token=token) as started:
        assert started.get("/health", headers=bearer(TOKEN)).status_code == (200 if token else 503)
