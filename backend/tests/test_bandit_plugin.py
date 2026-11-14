"""The Bandit plug-in image through the runner, on a small vulnerable file.

CI doesn't build plug-in images, so this test is skipped where the image is missing.
Build it with: docker build -t sieve-plugin-bandit:1.9.4 plugins/bandit
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
MANIFEST = PLUGINS_DIR / "bandit" / "plugin.toml"

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


def test_the_bandit_plugin_in_the_repository_loads():
    manifest = PluginManifest.load(MANIFEST)
    assert manifest.name == "bandit"
    assert manifest.image == "sieve-plugin-bandit:1.9.4"
    assert manifest.languages == ("python",)
    assert manifest.adapter == "bandit"
    assert (manifest.tool_version, manifest.rules_version) == ("1.9.4", "bandit 1.9.4")
    assert manifest.timeout_seconds == 600
    assert manifest.build is None


def test_every_plugin_in_the_repository_loads():
    registry = PluginRegistry.load(PLUGINS_DIR)
    assert "bandit" in {manifest.name for manifest in registry.all()}


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


def run_plugin(client, tmp_path, files: dict[str, str]):
    plugin = PluginManifest.load(MANIFEST)
    scan = ScanTarget(scan_id=str(uuid.uuid4()), repo_url="https://example.com/app")
    src = tmp_path / "scans" / scan.scan_id / "src"
    src.mkdir(parents=True)
    for name, text in files.items():
        (src / name).write_text(text, newline="\n")
    store = InMemoryRunStore()
    runner = PluginRunner(DockerEngine(client), store, RunnerSettings(tmp_path, data_volume=None))
    run = runner.run(scan, plugin, store.create_run(scan.scan_id, plugin))
    return run, (tmp_path / run.log_path).read_text(encoding="utf-8")


def test_bandit_plugin_writes_valid_sarif(client, tmp_path):
    run, log = run_plugin(
        client,
        tmp_path,
        {
            "app.py": VULNERABLE,
            # The plug-in must not obey the scanned code's own ignore comments.
            "hidden.py": VULNERABLE.replace("'{username}'\"", "'{username}'\"  # nosec"),
            # A file Bandit can't parse is not counted as scanned.
            "broken.py": "def broken(:\n",
        },
    )
    assert run.status is RunStatus.SUCCEEDED, log
    assert run.files_scanned == 2
    assert (run.tool_version, run.rules_version) == ("1.9.4", "bandit 1.9.4")
    assert "Bandit 1.9.4" in log

    sarif = json.loads((tmp_path / run.sarif_path).read_text(encoding="utf-8"))
    results = sarif["runs"][0]["results"]
    flagged = {
        (result["ruleId"], result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])
        for result in results
    }
    assert flagged == {("B608", "file:///src/app.py"), ("B608", "file:///src/hidden.py")}
    assert run.result_count == 2


def test_bandit_plugin_with_nothing_to_scan(client, tmp_path):
    run, log = run_plugin(client, tmp_path, {"README.md": "# no Python here\n"})
    assert run.status is RunStatus.SKIPPED, log
    assert run.exit_code == 3
