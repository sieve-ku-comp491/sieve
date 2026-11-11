"""Qwen models through Alibaba Cloud Model Studio, international deployment (Singapore)."""

from typing import Any

from app.llm.chat_completions_provider import ChatCompletionsProvider


class QwenProvider(ChatCompletionsProvider):
    """qwen3.8-max and qwen3.8-flash think by default. Effort "none" turns thinking off, and
    other levels keep it on, since the API has no levels.

    Alibaba now recommends a workspace endpoint over the shared one. To use it, set
    DASHSCOPE_BASE_URL to https://<WorkspaceId>.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1
    with a key from that workspace.
    """

    name = "qwen"
    label = "Qwen"
    api_key_variable = "DASHSCOPE_API_KEY"
    base_url = "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
    base_url_variable = "DASHSCOPE_BASE_URL"

    def effort_fields(self, effort: str) -> dict[str, Any]:
        return {"enable_thinking": effort != "none"}
