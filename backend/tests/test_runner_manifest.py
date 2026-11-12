"""Plug-in manifests and the registry."""

import pytest

from app.runner import BuildStep, ManifestError, PluginManifest, PluginRegistry
from app.runner.languages import count_files

SEMGREP = {
    "name": "semgrep",
    "image": "sieve-plugin-semgrep:1.183.0-16b9e6d",
    "languages": ["python", "java", "javascript", "typescript"],
    "adapter": "semgrep",
    "timeout_seconds": 600,
    "versions": {"tool": "1.183.0", "rules": "semgrep-rules@16b9e6d"},
}


def test_defaults_and_build_step():
    data = SEMGREP | {"name": "spotbugs", "build": {"image": "sieve-plugin-spotbugs-build:jdk25"}}
    del data["timeout_seconds"]
    manifest = PluginManifest.from_dict(data)
    assert manifest.timeout_seconds == 600
    assert manifest.build == BuildStep(image="sieve-plugin-spotbugs-build:jdk25")


@pytest.mark.parametrize(
    "change",
    [
        {"name": "Semgrep"},
        {"name": ""},
        {"image": "sieve-plugin-semgrep"},
        {"image": "sieve-plugin-semgrep:latest"},
        {"languages": []},
        {"languages": "python"},
        {"languages": ["*", "python"]},
        {"languages": ["pyhton"]},
        {"timeout_seconds": 0},
        {"timeout_seconds": 3601},
        {"timeout_seconds": "600"},
        {"versions": {"tool": "1.183.0"}},
        {"versions": {"tool": "1.183.0", "rules": "x", "extra": "y"}},
        {"build": {"image": "builder"}},
        {"build": {"image": "builder:1", "network": "bridge"}},
        {"network": "bridge"},
        {"adapter": None},
    ],
)
def test_bad_manifests_are_refused(change):
    with pytest.raises(ManifestError):
        PluginManifest.from_dict(SEMGREP | change)


def test_a_digest_counts_as_a_pinned_image():
    digest = "sieve-plugin-semgrep@sha256:" + "a" * 64
    assert PluginManifest.from_dict(SEMGREP | {"image": digest}).image == digest


def test_bad_toml_names_the_file(tmp_path):
    path = tmp_path / "plugin.toml"
    path.write_text('name = "semgrep"\nimage = ', encoding="utf-8")
    with pytest.raises(ManifestError, match="plugin.toml"):
        PluginManifest.load(path)


def test_registry_picks_plugins_by_language():
    registry = PluginRegistry(
        [
            PluginManifest.from_dict(SEMGREP),
            PluginManifest.from_dict(SEMGREP | {"name": "bandit", "languages": ["python"]}),
            PluginManifest.from_dict(SEMGREP | {"name": "gitleaks", "languages": ["*"]}),
            PluginManifest.from_dict(SEMGREP | {"name": "eslint", "languages": ["javascript"]}),
        ]
    )
    names = [manifest.name for manifest in registry.for_languages({"python"})]
    assert names == ["semgrep", "bandit", "gitleaks"]
    assert [manifest.name for manifest in registry.for_languages(set())] == ["gitleaks"]
    assert registry.get("bandit").languages == ("python",)


def test_registry_refuses_two_plugins_with_one_name():
    with pytest.raises(ManifestError):
        PluginRegistry([PluginManifest.from_dict(SEMGREP), PluginManifest.from_dict(SEMGREP)])


def test_count_files_by_language(tmp_path):
    (tmp_path / "web").mkdir()
    for name in ("app.py", "web/main.ts", "web/view.TSX", "web/old.js", "Main.java", "notes.txt"):
        (tmp_path / name).write_text("x\n")
    assert count_files(tmp_path, ["python"]) == 1
    assert count_files(tmp_path, ["typescript"]) == 2
    assert count_files(tmp_path, ["javascript", "java"]) == 2
    assert count_files(tmp_path, ["*"]) == 6
    assert count_files(tmp_path, ["go"]) == 0
