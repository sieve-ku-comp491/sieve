"""The one way Sieve calls an LLM: template, cache, budget, provider, cost, call log."""

import importlib
import logging
import os
import time
from collections.abc import Mapping, Sequence
from dataclasses import replace
from decimal import Decimal

from app.llm.budget import Budget
from app.llm.cache import ResponseCache, cache_key
from app.llm.call_log import CallLog, CallRecord
from app.llm.catalog import Catalog
from app.llm.provider import LLMProvider, ProviderError
from app.llm.templates import PromptTemplate
from app.llm.types import CodeBlock, LLMRequest, LLMResponse, Message, StopReason

DEFAULT_MAX_TOKENS = 16000

log = logging.getLogger(__name__)


class LLMClient:
    """Sends prompts for one run, such as a triage run, within that run's budget.

    Every call, including a cache hit or a failed call, is written to the call log with its
    prompt, response, exact model version, tokens, cost and duration.
    """

    def __init__(
        self,
        providers: Mapping[str, LLMProvider],
        catalog: Catalog,
        budget: Budget,
        call_log: CallLog,
        cache: ResponseCache,
        job_id: str | None = None,
    ):
        self.providers = providers
        self.catalog = catalog
        self.budget = budget
        self.call_log = call_log
        self.cache = cache
        self.job_id = job_id

    def build_request(
        self,
        template: PromptTemplate,
        values: Mapping[str, object],
        code: Sequence[CodeBlock] = (),
        *,
        model: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        effort: str | None = None,
        history: Sequence[Message] = (),
    ) -> LLMRequest:
        """The request ask() would send, for example to check its worst-case cost first.

        `history` holds earlier turns of the same conversation. They go between the system
        message and the new data block.
        """
        info = self.catalog.get(model)
        system, data = template.render(values, code)
        return LLMRequest(
            model=model,
            messages=(system, *history, data),
            max_tokens=max_tokens,
            effort=effort,
            temperature=0.0 if info.temperature else None,
            server_fallbacks=info.server_fallbacks,
        )

    def ask(
        self,
        template: PromptTemplate,
        values: Mapping[str, object],
        code: Sequence[CodeBlock] = (),
        *,
        model: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        effort: str | None = None,
        history: Sequence[Message] = (),
    ) -> LLMResponse:
        """Renders the template and sends it to the model, or answers from the cache.

        Raises BudgetExceeded, before anything is sent, when the worst-case cost doesn't fit in
        the budget, and ProviderError when the call fails.
        """
        request = self.build_request(
            template,
            values,
            code,
            model=model,
            max_tokens=max_tokens,
            effort=effort,
            history=history,
        )
        info = self.catalog.get(model)
        provider = self._provider(info.provider)
        key = cache_key(request)

        cached = self.cache.get(key)
        if cached is not None:
            hit = replace(cached, cost_usd=Decimal(0), duration_ms=0, cached=True, call_id=None)
            return self._log(provider, request, key, template, hit)

        reservation = self.budget.reserve(self.catalog.worst_case_cost(info, request))
        started = time.monotonic()
        try:
            response = provider.complete(request)
        except Exception as error:
            reservation.release()
            self._log_failure(provider, request, key, template, error, _elapsed_ms(started))
            raise
        cost = self.catalog.cost(provider.name, response.attempts)
        reservation.charge(cost)

        response = replace(response, cost_usd=cost, duration_ms=_elapsed_ms(started), cached=False)
        response = self._log(provider, request, key, template, response)
        if response.stop_reason is StopReason.COMPLETE:
            self.cache.put(key, response)
        return response

    def _provider(self, name: str) -> LLMProvider:
        try:
            return self.providers[name]
        except KeyError:
            raise ProviderError(
                f"no {name} provider is set up, check its API key in .env", retryable=False
            ) from None

    def _log(
        self,
        provider: LLMProvider,
        request: LLMRequest,
        key: str,
        template: PromptTemplate,
        response: LLMResponse,
    ) -> LLMResponse:
        record = CallRecord(
            provider=provider.name,
            model=request.model,
            messages=request.messages,
            max_tokens=request.max_tokens,
            cache_key=key,
            cached=response.cached,
            cost_usd=response.cost_usd,
            duration_ms=response.duration_ms,
            model_version=response.model_version,
            response_text=response.text,
            stop_reason=response.stop_reason.value,
            raw_stop_reason=response.raw_stop_reason,
            # A cache hit used no tokens. The response keeps the usage of the original call.
            attempts=() if response.cached else response.attempts,
            effort=request.effort,
            temperature=request.temperature,
            template_name=template.name,
            template_version=template.version,
            job_id=self.job_id,
            request_id=response.request_id,
        )
        self._record(record)
        return replace(response, call_id=record.id)

    def _log_failure(
        self,
        provider: LLMProvider,
        request: LLMRequest,
        key: str,
        template: PromptTemplate,
        error: Exception,
        duration_ms: int,
    ) -> None:
        self._record(
            CallRecord(
                provider=provider.name,
                model=request.model,
                messages=request.messages,
                max_tokens=request.max_tokens,
                cache_key=key,
                cached=False,
                cost_usd=Decimal(0),
                duration_ms=duration_ms,
                effort=request.effort,
                temperature=request.temperature,
                template_name=template.name,
                template_version=template.version,
                job_id=self.job_id,
                error=f"{type(error).__name__}: {error}",
            )
        )

    def _record(self, record: CallRecord) -> None:
        """Writes the record to the call log, or to the error log if that write fails.

        A failed write doesn't raise, so a paid answer still reaches the caller and a failed
        call still raises its own ProviderError. The error log keeps the whole record.
        """
        try:
            self.call_log.record(record)
        except Exception:
            log.exception("could not write call %s to the call log: %r", record.id, record)


def providers_from_env(catalog: Catalog) -> dict[str, LLMProvider]:
    """The providers listed in models.json whose API key is set in the environment."""
    providers: dict[str, LLMProvider] = {}
    for name, target in catalog.providers.items():
        provider_class = load_provider_class(target)
        if provider_class.name != name:
            raise ValueError(
                f"models.json lists {target} as {name}, but its name is {provider_class.name}"
            )
        if os.environ.get(provider_class.api_key_variable, "").strip():
            providers[name] = provider_class()
    return providers


def load_provider_class(target: str) -> type[LLMProvider]:
    """Imports a provider class from its "module:Class" entry in models.json."""
    module_name, _, class_name = target.partition(":")
    return getattr(importlib.import_module(module_name), class_name)


def _elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
