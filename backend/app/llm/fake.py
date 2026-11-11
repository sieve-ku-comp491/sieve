"""A provider for tests. It answers from a list and never touches the network."""

from collections.abc import Iterable

from app.llm.provider import LLMProvider
from app.llm.types import Attempt, LLMRequest, LLMResponse, StopReason, Usage


class FakeProvider(LLMProvider):
    name = "fake"
    api_key_variable = "FAKE_API_KEY"

    def __init__(
        self,
        name: str = "fake",
        replies: Iterable[str] = (),
        usage: Usage | None = None,
        stop_reason: StopReason = StopReason.COMPLETE,
        error: Exception | None = None,
    ):
        self.name = name
        self.requests: list[LLMRequest] = []
        self.usage = usage or Usage(input_tokens=100, output_tokens=20)
        self.stop_reason = stop_reason
        self.error = error
        self._replies = list(replies)

    def complete(self, request: LLMRequest) -> LLMResponse:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return LLMResponse(
            text=self._replies.pop(0) if self._replies else "ok",
            model_version=f"{request.model}-fake",
            stop_reason=self.stop_reason,
            raw_stop_reason=self.stop_reason.value,
            attempts=(Attempt(request.model, self.usage),),
            request_id="req_fake",
        )
