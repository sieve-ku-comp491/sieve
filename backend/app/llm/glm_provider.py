"""GLM models through Z.ai's API."""

from typing import Any

from app.llm.chat_completions_provider import STOP_REASONS, ChatCompletionsProvider
from app.llm.types import StopReason


class GLMProvider(ChatCompletionsProvider):
    """The models think by default. Effort "none" turns thinking off, and other levels keep it on,
    since the API has no levels.

    For a temperature of 0 the request sets do_sample to false, which is greedy decoding. The
    docs give the temperature range as [0.0, 1.0] but also call it a positive number. A finish
    reason of "sensitive" means the content was filtered.
    """

    name = "glm"
    label = "Z.ai"
    api_key_variable = "ZAI_API_KEY"
    base_url = "https://api.z.ai/api/paas/v4/"
    stop_reasons = STOP_REASONS | {"sensitive": StopReason.REFUSAL}

    def effort_fields(self, effort: str) -> dict[str, Any]:
        return {"thinking": {"type": "disabled" if effort == "none" else "enabled"}}

    def sampling_fields(self, temperature: float) -> dict[str, Any]:
        if temperature == 0:
            return {"do_sample": False}
        return {"temperature": temperature}
