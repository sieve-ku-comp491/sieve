"""DeepSeek models through DeepSeek's own API."""

from app.llm.chat_completions_provider import ChatCompletionsProvider


class DeepSeekProvider(ChatCompletionsProvider):
    """The models think unless effort is "none".

    reasoning_effort takes none, low, high and max, and the API itself maps medium and xhigh to
    high. A temperature is accepted but has no effect while the model thinks. A call made
    outside DeepSeek's peak hours is charged half, see "off_peak" in models.json.
    """

    name = "deepseek"
    label = "DeepSeek"
    api_key_variable = "DEEPSEEK_API_KEY"
    base_url = "https://api.deepseek.com"
