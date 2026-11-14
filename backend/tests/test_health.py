from pathlib import Path

from fastapi.testclient import TestClient

from app.api.deps import Settings
from app.main import create_app

app = create_app(Settings(token="test-token", database_url=None, data_dir=Path("/data")))
client = TestClient(
    app, base_url="http://localhost", headers={"Authorization": "Bearer test-token"}
)


def test_health_returns_ok():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
