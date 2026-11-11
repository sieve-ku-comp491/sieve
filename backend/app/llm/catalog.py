"""The providers and models we can call, what they cost, and which settings their APIs accept.

All of it is in models.json. When you add a model or a price changes, check the provider's
pricing page and update "checked_on".
"""

import json
import logging
import re
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

from app.llm.types import Attempt, LLMRequest, Usage

MODELS_FILE = Path(__file__).with_name("models.json")
MILLION = Decimal(1_000_000)
PRICE_KINDS = ("input", "output", "cache_read", "cache_write")

# APIs can answer with a dated snapshot of the model that was asked, such as
# gpt-5.4-mini-2026-03-17 or claude-haiku-4-5-20251001. A snapshot has its model's price.
SNAPSHOT_DATE = re.compile(r"-(\d{4}-\d{2}-\d{2}|\d{8})$")

# Every token covers at least one byte of text, so the UTF-8 length of the messages bounds the
# number of input tokens. These allowances cover the tokens the API adds around each message.
TOKENS_PER_MESSAGE = 16
TOKENS_PER_REQUEST = 64

log = logging.getLogger(__name__)


class UnknownModel(Exception):
    def __init__(self, model: str):
        super().__init__(f"{model} is not in app/llm/models.json, add it with its prices first")
        self.model = model


@dataclass(frozen=True)
class Price:
    """US dollars per million tokens of each kind."""

    input: Decimal
    output: Decimal
    cache_read: Decimal
    cache_write: Decimal

    def cost(self, usage: Usage) -> Decimal:
        total = (
            usage.input_tokens * self.input
            + usage.output_tokens * self.output
            + usage.cache_read_tokens * self.cache_read
            + usage.cache_write_tokens * self.cache_write
        )
        return total / MILLION

    def highest_input(self) -> Decimal:
        """The most one input token can cost: normal, cache read or cache write."""
        return max(self.input, self.cache_read, self.cache_write)


@dataclass(frozen=True)
class ModelInfo:
    name: str
    provider: str
    price: Price
    long_context_price: Price | None = None
    long_context_above: int | None = None
    temperature: bool = False
    server_fallbacks: bool = False

    def price_for(self, prompt_tokens: int) -> Price:
        """Some models charge more for the whole request once the prompt passes a threshold."""
        if self.long_context_price is None or self.long_context_above is None:
            return self.price
        if prompt_tokens > self.long_context_above:
            return self.long_context_price
        return self.price

    def cost(self, usage: Usage) -> Decimal:
        return self.price_for(usage.prompt_tokens).cost(usage)

    def prices(self) -> list[Price]:
        return [self.price] + ([self.long_context_price] if self.long_context_price else [])


def input_token_upper_bound(request: LLMRequest) -> int:
    message_bytes = sum(len(message.content.encode("utf-8")) for message in request.messages)
    return message_bytes + TOKENS_PER_MESSAGE * len(request.messages) + TOKENS_PER_REQUEST


class Catalog:
    def __init__(
        self,
        models: dict[str, ModelInfo],
        checked_on: str,
        providers: dict[str, str] | None = None,
    ):
        self._models = models
        self.checked_on = checked_on
        # Provider name to the "module:Class" of its LLMProvider.
        self.providers = providers or {}

    def __contains__(self, model: str) -> bool:
        return self.find(model) is not None

    def names(self) -> list[str]:
        return sorted(self._models)

    def find(self, model: str) -> ModelInfo | None:
        """The model's entry, also when the name is a dated snapshot of a model in the file."""
        if model in self._models:
            return self._models[model]
        return self._models.get(SNAPSHOT_DATE.sub("", model))

    def get(self, model: str) -> ModelInfo:
        info = self.find(model)
        if info is None:
            raise UnknownModel(model)
        return info

    def ceiling_price(self, provider: str) -> Price:
        """The highest price of each kind among a provider's models.

        Used for a model we have no price for, such as an unexpected refusal fallback, so the
        cost is never understated.
        """
        prices = [p for m in self._models.values() if m.provider == provider for p in m.prices()]
        if not prices:
            raise UnknownModel(f"any model of provider {provider}")
        return Price(
            input=max(p.input for p in prices),
            output=max(p.output for p in prices),
            cache_read=max(p.cache_read for p in prices),
            cache_write=max(p.cache_write for p in prices),
        )

    def cost(self, provider: str, attempts: tuple[Attempt, ...]) -> Decimal:
        """What a response cost, with each attempt charged at its own model's price."""
        total = Decimal(0)
        for attempt in attempts:
            info = self.find(attempt.model)
            if info is not None:
                total += info.cost(attempt.usage)
            else:
                log.warning(
                    "no price for %s, charging the highest %s price", attempt.model, provider
                )
                total += self.ceiling_price(provider).cost(attempt.usage)
        return total

    def worst_case_cost(self, info: ModelInfo, request: LLMRequest) -> Decimal:
        """The most a request can cost, reserved from the budget before it is sent.

        It assumes every input token at its highest price and an answer of max_tokens. With
        refusal fallbacks, a declined attempt can be billed and a substitute model then runs
        the same request, so a second attempt is added at the provider's highest prices. A model
        that declines partway through passes its partial answer on to the substitute, so the
        second attempt can read up to max_tokens more than the first.
        """
        prompt = input_token_upper_bound(request)

        def worst(price: Price, prompt_tokens: int) -> Decimal:
            input_cost = prompt_tokens * price.highest_input()
            return (input_cost + request.max_tokens * price.output) / MILLION

        cost = max(worst(price, prompt) for price in info.prices())
        if request.server_fallbacks:
            cost += worst(self.ceiling_price(info.provider), prompt + request.max_tokens)
        return cost


def load_catalog(path: Path = MODELS_FILE) -> Catalog:
    data = json.loads(path.read_text(encoding="utf-8"))
    providers = data["providers"]
    models = {}
    for name, entry in data["models"].items():
        if entry["provider"] not in providers:
            raise ValueError(
                f"{name} in {path.name} has provider {entry['provider']}, "
                'which is not listed under "providers"'
            )
        long_context = entry.get("long_context")
        models[name] = ModelInfo(
            name=name,
            provider=entry["provider"],
            price=_price(name, entry["price"]),
            long_context_price=_price(name, long_context["price"]) if long_context else None,
            long_context_above=long_context["above_prompt_tokens"] if long_context else None,
            temperature=entry.get("temperature", False),
            server_fallbacks=entry.get("server_fallbacks", False),
        )
    return Catalog(models, checked_on=data["checked_on"], providers=providers)


def _price(model: str, data: dict[str, str]) -> Price:
    """All four prices are required. Repeat the input price where a provider has no other."""
    missing = [kind for kind in PRICE_KINDS if kind not in data]
    if missing:
        raise ValueError(f"{model} in models.json has no {' or '.join(missing)} price")
    return Price(*(Decimal(data[kind]) for kind in PRICE_KINDS))
