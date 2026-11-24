"""SARIF adapters: each plug-in's SARIF file turned into findings (docs/finding-format.md)."""

import importlib
import re

from app.adapters.base import BaseSarifAdapter, SarifAdapter
from app.adapters.finding import AdapterResult, Finding, FlowStep, Location
from app.adapters.fingerprint import Fingerprinter, context_hash, fingerprint, normalize
from app.adapters.semgrep import SemgrepAdapter

ADAPTER_NAME = re.compile(r"[a-z][a-z0-9_]*")


class AdapterError(LookupError):
    """A plug-in manifest names an adapter that doesn't exist."""


class AdapterRegistry:
    """The adapter for each name a plug-in manifest can give in its adapter field.

    The adapter named x is the class in app/adapters/x.py whose tool is x, so adding an
    adapter adds only its own module (requirement N5). A registry made with a list of
    adapters gives only those."""

    def __init__(self, adapters: list[SarifAdapter] | None = None):
        self._only_given = adapters is not None
        self._adapters = {adapter.tool: adapter for adapter in adapters or []}

    def get(self, name: str) -> SarifAdapter:
        if name not in self._adapters and not self._only_given:
            self._adapters[name] = _load(name)
        try:
            return self._adapters[name]
        except KeyError:
            raise AdapterError(f"no adapter named {name!r}") from None


def _load(name: str) -> SarifAdapter:
    if not ADAPTER_NAME.fullmatch(name):
        raise AdapterError(f"no adapter named {name!r}")
    module_name = f"{__name__}.{name}"
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as error:
        if error.name != module_name:
            raise
        raise AdapterError(f"no adapter named {name!r}") from None
    classes = [
        value
        for value in vars(module).values()
        if isinstance(value, type)
        and issubclass(value, BaseSarifAdapter)
        and value.__module__ == module_name
        and value.tool == name
    ]
    if len(classes) != 1:
        raise AdapterError(f"{module_name} has {len(classes)} adapters for {name!r}, not one")
    return classes[0]()


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
