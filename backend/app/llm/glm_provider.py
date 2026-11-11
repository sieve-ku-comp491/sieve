"""GLM models through Z.ai's API."""

from typing import Any

from app.llm.chat_completions_provider import NEAREST_LEVEL, STOP_REASONS, ChatCompletionsProvider
from app.llm.types import StopReason


class GLMProvider(ChatCompletionsProvider):
    """The GLM-5.3 models always think. reasoning_effort takes low, high and max, so the other
    levels go to the nearest one. Without an effort the API uses max, the most expensive level.
    Effort "none" asks for thinking to be turned off, which the GLM-5.3 models refuse.

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
        if effort == "none":
            return {"thinking": {"type": "disabled"}}
        return {
            "thinking": {"type": "enabled"},
            "reasoning_effort": NEAREST_LEVEL.get(effort, effort),
        }

    def sampling_fields(self, temperature: float) -> dict[str, Any]:
        if temperature == 0:
            return {"do_sample": False}
        return {"temperature": temperature}
