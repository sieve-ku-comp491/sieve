"""SARIF adapters: each plug-in's SARIF file turned into findings (docs/finding-format.md)."""

from app.adapters.base import BaseSarifAdapter, SarifAdapter
from app.adapters.finding import AdapterResult, Finding, FlowStep, Location
from app.adapters.fingerprint import Fingerprinter, context_hash, fingerprint, normalize
from app.adapters.semgrep import SemgrepAdapter


class AdapterError(LookupError):
    """A plug-in manifest names an adapter that doesn't exist."""


class AdapterRegistry:
    """The adapter for each name a plug-in manifest can give in its adapter field."""

    def __init__(self, adapters: list[SarifAdapter] | None = None):
        adapters = adapters if adapters is not None else [SemgrepAdapter()]
        self._adapters = {adapter.tool: adapter for adapter in adapters}

    def get(self, name: str) -> SarifAdapter:
        try:
            return self._adapters[name]
        except KeyError:
            raise AdapterError(f"no adapter named {name!r}") from None


__all__ = [
    "AdapterError",
    "AdapterRegistry",
    "AdapterResult",
    "BaseSarifAdapter",
    "Finding",
    "Fingerprinter",
    "FlowStep",
    "Location",
    "SarifAdapter",
    "SemgrepAdapter",
    "context_hash",
    "fingerprint",
    "normalize",
]
