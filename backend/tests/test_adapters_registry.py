"""AdapterRegistry finds the adapter for a manifest's adapter name by its module."""

import importlib
import sys
import types

import pytest

from app.adapters import AdapterError, AdapterRegistry, BaseSarifAdapter, SemgrepAdapter


def fake_module(monkeypatch, name, **classes):
    module = types.ModuleType(f"app.adapters.{name}")
    for class_name, tool in classes.items():
        attrs = {"tool": tool, "__module__": module.__name__}
        setattr(module, class_name, type(class_name, (BaseSarifAdapter,), attrs))
    monkeypatch.setitem(sys.modules, module.__name__, module)
    return module


def test_an_adapter_is_found_by_its_module_and_tool(monkeypatch):
    module = fake_module(monkeypatch, "faketool", FakeToolAdapter="faketool")
    registry = AdapterRegistry()
    adapter = registry.get("faketool")
    assert type(adapter) is module.FakeToolAdapter
    assert registry.get("faketool") is adapter


def test_the_semgrep_adapter():
    assert isinstance(AdapterRegistry().get("semgrep"), SemgrepAdapter)


@pytest.mark.parametrize(
    "name", ["no-such-tool", "nosuchtool", "base", "fingerprint", "finding", "", "../semgrep"]
)
def test_names_without_an_adapter(name):
    with pytest.raises(AdapterError):
        AdapterRegistry().get(name)


def test_a_module_needs_exactly_one_adapter_for_its_name(monkeypatch):
    fake_module(monkeypatch, "othertool", OtherAdapter="semgrep")
    fake_module(monkeypatch, "twotools", OneAdapter="twotools", TwoAdapter="twotools")
    with pytest.raises(AdapterError):
        AdapterRegistry().get("othertool")
    with pytest.raises(AdapterError):
        AdapterRegistry().get("twotools")


def test_an_import_error_inside_the_adapter_is_not_hidden(monkeypatch):
    def import_module(name):
        raise ModuleNotFoundError("No module named 'yaml'", name="yaml")

    monkeypatch.setattr(importlib, "import_module", import_module)
    with pytest.raises(ModuleNotFoundError):
        AdapterRegistry().get("brokentool")


def test_a_registry_made_with_adapters_gives_only_those():
    registry = AdapterRegistry([SemgrepAdapter()])
    assert isinstance(registry.get("semgrep"), SemgrepAdapter)
    with pytest.raises(AdapterError):
        registry.get("faketool")
