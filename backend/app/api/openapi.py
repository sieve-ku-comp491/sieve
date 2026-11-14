"""Writes the API's OpenAPI specification to docs/openapi.json.

Run from backend/ after changing an endpoint: python -m app.api.openapi
tests/test_openapi.py fails while the committed file differs from what the code generates.
"""

import json
from pathlib import Path

from app.api.deps import Settings
from app.main import create_app

SPEC_FILE = Path(__file__).resolve().parents[3] / "docs" / "openapi.json"


def spec() -> dict:
    return create_app(Settings(token=None, database_url=None, data_dir=Path("/data"))).openapi()


def render() -> str:
    return json.dumps(spec(), indent=2, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    SPEC_FILE.write_text(render(), encoding="utf-8", newline="\n")
    print(f"wrote {SPEC_FILE}")
