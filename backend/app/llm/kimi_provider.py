"""Kimi models through Moonshot's API."""

from typing import Any

from app.llm.chat_completions_provider import ChatCompletionsProvider

# The K3 models take low, high and max, so the other levels go to the nearest one.
EFFORTS = {"low": "low", "medium": "high", "high": "high", "xhigh": "max", "max": "max"}


class KimiProvider(ChatCompletionsProvider):
    """The K3 models always think. Without an effort the API uses max, the most expensive level.

    The API wants max_completion_tokens and counts cache reads and writes inside prompt_tokens.
    """

    name = "kimi"
    label = "Kimi"
    api_key_variable = "MOONSHOT_API_KEY"
    base_url = "https://api.moonshot.ai/v1"
    max_tokens_field = "max_completion_tokens"

    def effort_fields(self, effort: str) -> dict[str, Any]:
        return {"reasoning_effort": EFFORTS.get(effort, effort)}
