"""Answers a repeated request with the earlier response instead of calling the API again."""

import hashlib
import json
from typing import Protocol

from app.llm.types import LLMRequest, LLMResponse


def cache_key(request: LLMRequest) -> str:
    """The same model, messages and settings always give the same key."""
    data = {
        "model": request.model,
        "messages": [[message.role, message.content] for message in request.messages],
        "max_tokens": request.max_tokens,
        "effort": request.effort,
        "temperature": request.temperature,
        "server_fallbacks": request.server_fallbacks,
    }
    encoded = json.dumps(data, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return "k1:" + hashlib.sha256(encoded).hexdigest()


class ResponseCache(Protocol):
    def get(self, key: str) -> LLMResponse | None: ...

    def put(self, key: str, response: LLMResponse) -> None: ...


class InMemoryResponseCache:
    def __init__(self) -> None:
        self._responses: dict[str, LLMResponse] = {}

    def get(self, key: str) -> LLMResponse | None:
        return self._responses.get(key)

    def put(self, key: str, response: LLMResponse) -> None:
        self._responses[key] = response
