"""The Semgrep plug-in image through the runner, on a small vulnerable file.

The image is about 1.6 GB, so CI doesn't build it and this test is skipped where it is missing.
Build it with: docker build -t sieve-plugin-semgrep:1.183.0-16b9e6d plugins/semgrep
"""

import json
import uuid
from pathlib import Path

import docker
import docker.errors
import pytest

from app.runner import (
    DockerEngine,
    InMemoryRunStore,
    PluginManifest,
    PluginRegistry,
    PluginRunner,
    RunnerSettings,
    RunStatus,
    ScanTarget,
)

PLUGINS_DIR = Path(__file__).resolve().parents[2] / "plugins"
MANIFEST = PLUGINS_DIR / "semgrep" / "plugin.toml"

VULNERABLE = """\
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    sql_query = f"SELECT * FROM users WHERE username='{username}'"
    c = sqlite3.connect("users.db").cursor()
    return str(c.execute(sql_query).fetchone())
"""


def test_the_semgrep_plugin_in_the_repository_loads():
    manifest = PluginManifest.load(MANIFEST)
    assert manifest.name == "semgrep"
    assert manifest.image == "sieve-plugin-semgrep:1.183.0-16b9e6d"
    assert manifest.tool_version == "1.183.0"
    assert manifest.rules_version == "semgrep-rules@16b9e6d45f10649f6a531ec4838ed9924372c3bc"
    assert manifest.timeout_seconds == 600
    assert manifest.build is None


def test_every_plugin_in_the_repository_loads():
    registry = PluginRegistry.load(PLUGINS_DIR)
    assert "semgrep" in {manifest.name for manifest in registry.all()}


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


def test_semgrep_plugin_writes_valid_sarif(client, tmp_path):
    plugin = PluginManifest.load(MANIFEST)
    scan = ScanTarget(scan_id=str(uuid.uuid4()), repo_url="https://example.com/app")
    src = tmp_path / "scans" / scan.scan_id / "src"
    src.mkdir(parents=True)
    (src / "app.py").write_text(VULNERABLE, newline="\n")
    # The plug-in must not obey the scanned code's own ignore comments.
    (src / "hidden.py").write_text(
        VULNERABLE.replace("fetchone())", "fetchone())  # nosemgrep"), newline="\n"
    )

    store = InMemoryRunStore()
    runner = PluginRunner(DockerEngine(client), store, RunnerSettings(tmp_path, data_volume=None))
    run = runner.run(scan, plugin, store.create_run(scan.scan_id, plugin))

    log = (tmp_path / run.log_path).read_text(encoding="utf-8")
    assert run.status is RunStatus.SUCCEEDED, log
    assert run.files_scanned == 2
    assert run.result_count > 0
    assert (run.tool_version, run.rules_version) == (
        "1.183.0",
        "semgrep-rules@16b9e6d45f10649f6a531ec4838ed9924372c3bc",
    )
    assert "Semgrep OSS 1.183.0" in log

    sarif = json.loads((tmp_path / run.sarif_path).read_text(encoding="utf-8"))
    results = sarif["runs"][0]["results"]
    rules = {result["ruleId"] for result in results}
    assert "python.lang.security.audit.formatted-sql-query" in rules
    files = {
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for result in results
    }
    assert any(uri.endswith("hidden.py") for uri in files)
