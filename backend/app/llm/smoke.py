"""Sends one tiny request through LLMClient, to check a provider and its API key by hand.

    python -m app.llm.smoke claude-haiku-5-5

Run it once for each provider, with that provider's cheapest model in models.json. The run's
budget is US$0.01, so the check can never cost more than that. A model whose worst case doesn't
fit, such as claude-opus-5-5, is stopped by the budget before anything is sent.
"""

import argparse
import sys
from decimal import Decimal

from app.llm.budget import Budget, BudgetExceeded
from app.llm.cache import InMemoryResponseCache
from app.llm.call_log import InMemoryCallLog
from app.llm.catalog import UnknownModel, load_catalog
from app.llm.client import LLMClient, providers_from_env
from app.llm.provider import ProviderError
from app.llm.templates import load_template
from app.llm.types import StopReason

BUDGET_USD = Decimal("0.01")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check that a model answers through LLMClient.")
    parser.add_argument("model", help="a model from app/llm/models.json")
    parser.add_argument("--effort", default="low", help="effort for the request (default: low)")
    parser.add_argument("--max-tokens", type=int, default=512)
    args = parser.parse_args(argv)

    catalog = load_catalog()
    client = LLMClient(
        providers=providers_from_env(catalog),
        catalog=catalog,
        budget=Budget(BUDGET_USD),
        call_log=InMemoryCallLog(),
        cache=InMemoryResponseCache(),
    )
    try:
        response = client.ask(
            load_template("smoke_test"),
            {"reply": "OK"},
            model=args.model,
            max_tokens=args.max_tokens,
            effort=args.effort,
        )
    except (BudgetExceeded, ProviderError, UnknownModel) as error:
        print(f"check failed: {error}", file=sys.stderr)
        return 1

    usage = response.usage
    print(f"reply: {response.text!r}")
    print(f"model version: {response.model_version}")
    print(f"stop reason: {response.stop_reason} ({response.raw_stop_reason})")
    print(f"tokens: {usage.prompt_tokens} in, {usage.output_tokens} out")
    print(f"cost: ${response.cost_usd:.6f} of a ${BUDGET_USD} budget")
    return 0 if response.stop_reason is StopReason.COMPLETE else 1


if __name__ == "__main__":
    sys.exit(main())
