"""Qwen models through Alibaba Cloud Model Studio, international deployment (Singapore)."""

from typing import Any

from app.llm.chat_completions_provider import ChatCompletionsProvider
from app.llm.types import LLMRequest


class QwenProvider(ChatCompletionsProvider):
    """qwen3.8-max and qwen3.8-flash think by default. Effort "none" turns thinking off, and
    other levels keep it on, since the API has no levels.

    Qwen's max_tokens limits only the answer, and thinking_budget the thinking. While the model
    may think, the request's max_tokens is split between the two, so that thinking and answer
    together stay within it, as LLMClient's worst case expects. When the budget ends the
    thinking, Qwen adds a few tokens of its own, which the worst case's prompt estimate covers.

    Alibaba now recommends a workspace endpoint over the shared one. To use it, set
    DASHSCOPE_BASE_URL to https://<WorkspaceId>.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1
    with a key from that workspace. Only an https URL on an aliyuncs.com host is accepted.
    """

    name = "qwen"
    label = "Qwen"
    api_key_variable = "DASHSCOPE_API_KEY"
    base_url = "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
    base_url_variable = "DASHSCOPE_BASE_URL"
    base_url_host = ".aliyuncs.com"

    def body_fields(self, request: LLMRequest) -> dict[str, Any]:
        fields = super().body_fields(request)
        if request.effort != "none":
            thinking = max(request.max_tokens // 2, 1)
            fields |= {
                "thinking_budget": thinking,
                "max_tokens": max(request.max_tokens - thinking, 1),
            }
        return fields

    def effort_fields(self, effort: str) -> dict[str, Any]:
        return {"enable_thinking": effort != "none"}
