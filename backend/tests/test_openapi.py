import json

from app.api.openapi import SPEC_FILE, spec


def test_docs_openapi_json_matches_the_code():
    committed = json.loads(SPEC_FILE.read_text(encoding="utf-8"))
    assert committed == spec(), "run python -m app.api.openapi in backend/ and commit the result"


def test_the_spec_requires_the_token():
    generated = spec()
    assert generated["security"] == [{"token": []}]
    assert generated["components"]["securitySchemes"]["token"] == {
        "type": "http",
        "scheme": "bearer",
    }
