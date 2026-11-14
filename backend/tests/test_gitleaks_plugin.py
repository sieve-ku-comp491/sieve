"""The Gitleaks plug-in image through the runner, on files with a fake key made for the test.

CI doesn't build plug-in images, so this test is skipped where the image is missing.
Build it with: docker build -t sieve-plugin-gitleaks:8.30.1 plugins/gitleaks
"""

import json
import secrets
import string
import uuid
from pathlib import Path

import docker
import docker.errors
import pytest

from app.adapters import GitleaksAdapter
from app.checkout import CheckoutReader
from app.runner import (
    DockerEngine,
    InMemoryRunStore,
    PluginManifest,
    PluginRunner,
    RunnerSettings,
    RunStatus,
    SarifValidator,
    ScanTarget,
)

MANIFEST = Path(__file__).resolve().parents[2] / "plugins" / "gitleaks" / "plugin.toml"


def test_the_gitleaks_plugin_in_the_repository_loads():
    manifest = PluginManifest.load(MANIFEST)
    assert manifest.name == "gitleaks" and manifest.adapter == "gitleaks"
    assert manifest.image == "sieve-plugin-gitleaks:8.30.1"
    assert manifest.languages == ("*",)
    assert manifest.tool_version == "8.30.1"
    assert manifest.timeout_seconds == 600
    assert manifest.build is None


@pytest.fixture(scope="module")
def client() -> docker.DockerClient:
    plugin = PluginManifest.load(MANIFEST)
    try:
        client = docker.from_env()
        client.images.get(plugin.image)
    except docker.errors.ImageNotFound:
        pytest.skip(f"the image {plugin.image} isn't built on this machine")
    except Exception:
        pytest.skip("Docker is not running")
    return client


def scan(client, tmp_path, files: dict[str, str]):
    plugin = PluginManifest.load(MANIFEST)
    target = ScanTarget(scan_id=str(uuid.uuid4()), repo_url="https://example.com/app")
    src = tmp_path / "scans" / target.scan_id / "src"
    src.mkdir(parents=True)
    for name, text in files.items():
        (src / name).write_text(text, newline="\n")
    store = InMemoryRunStore()
    runner = PluginRunner(DockerEngine(client), store, RunnerSettings(tmp_path, data_volume=None))
    run = runner.run(target, plugin, store.create_run(target.scan_id, plugin))
    return run, src


def test_gitleaks_plugin_finds_the_key_and_redacts_it(client, tmp_path):
    key = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
    settings = f'DEBUG = False\napi_key = "{key}"\n'
    run, src = scan(
        client,
        tmp_path,
        {
            "settings.py": settings,
            # The plug-in must not obey the scanned code's own allow comments.
            "hidden.py": settings.replace(f'"{key}"', f'"{key}"  # gitleaks:allow'),
            "README.md": "Nothing to see here.\n",
        },
    )

    log = (tmp_path / run.log_path).read_text(encoding="utf-8")
    assert run.status is RunStatus.SUCCEEDED, log
    assert run.files_scanned == 3
    assert run.result_count == 2
    assert (run.tool_version, run.rules_version) == ("8.30.1", "gitleaks 8.30.1 built-in rules")

    sarif_text = (tmp_path / run.sarif_path).read_text(encoding="utf-8")
    assert key not in sarif_text and key not in log
    sarif = SarifValidator().validate(tmp_path / run.sarif_path)
    out = GitleaksAdapter().to_findings(sarif, run, CheckoutReader(src))
    assert sorted((f.location.file, f.location.start_line) for f in out.findings) == [
        ("hidden.py", 2),
        ("settings.py", 2),
    ]
    assert key not in json.dumps([vars(f) | {"location": vars(f.location)} for f in out.findings])


def test_gitleaks_plugin_without_files_is_skipped(client, tmp_path):
    run, _ = scan(client, tmp_path, {})
    assert run.status is RunStatus.SKIPPED
