"""The ESLint plug-in image through the runner, on small vulnerable files.

CI doesn't build plug-in images, so this test is skipped where the image is missing.
Build it with: docker build -t sieve-plugin-eslint:10.14.0-security4.2.1 plugins/eslint
"""

import uuid
from pathlib import Path

import docker
import docker.errors
import pytest

from app.adapters import EslintAdapter
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

MANIFEST = Path(__file__).resolve().parents[2] / "plugins" / "eslint" / "plugin.toml"

JAVASCRIPT = """\
const { exec } = require('child_process')

module.exports = function run (req) {
  exec(req.query.cmd) // eslint-disable-line
}
"""

TYPESCRIPT = """\
import * as fs from 'fs'

export function read (name: string): Buffer {
  return fs.readFileSync(`uploads/${name}`)
}
"""

# A configuration file in the scanned repository must never be loaded: it is code.
TARGET_CONFIG = "throw new Error('the scanned repository configuration was loaded')\n"


def test_the_eslint_plugin_in_the_repository_loads():
    manifest = PluginManifest.load(MANIFEST)
    assert manifest.name == "eslint"
    assert manifest.image == "sieve-plugin-eslint:10.14.0-security4.2.1"
    assert manifest.languages == ("javascript", "typescript")
    assert manifest.adapter == "eslint"
    assert manifest.tool_version == "10.14.0"
    assert manifest.rules_version == "eslint-plugin-security 4.2.1"
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


def test_eslint_plugin_writes_valid_sarif(client, tmp_path):
    plugin = PluginManifest.load(MANIFEST)
    scan = ScanTarget(scan_id=str(uuid.uuid4()), repo_url="https://example.com/app")
    src = tmp_path / "scans" / scan.scan_id / "src"
    (src / "lib").mkdir(parents=True)
    (src / "run.js").write_text(JAVASCRIPT, newline="\n")
    (src / "lib" / "read.ts").write_text(TYPESCRIPT, newline="\n")
    (src / "eslint.config.mjs").write_text(TARGET_CONFIG, newline="\n")
    (src / "README.md").write_text("not linted\n", newline="\n")

    store = InMemoryRunStore()
    runner = PluginRunner(DockerEngine(client), store, RunnerSettings(tmp_path, data_volume=None))
    run = runner.run(scan, plugin, store.create_run(scan.scan_id, plugin))

    log = (tmp_path / run.log_path).read_text(encoding="utf-8")
    assert run.status is RunStatus.SUCCEEDED, log
    # The repository's eslint.config.mjs is linted as a file like the others, not loaded.
    assert run.files_scanned == 3
    assert "ESLint 10.14.0" in log

    sarif = SarifValidator().validate(tmp_path / run.sarif_path)
    result = EslintAdapter().to_findings(sarif, run, CheckoutReader(src))
    found = {(f.rule_id, f.location.file, f.location.start_line, f.cwe[0]) for f in result.findings}
    # The eslint-disable-line comment doesn't hide the finding.
    assert ("security/detect-child-process", "run.js", 4, "CWE-78") in found
    assert ("security/detect-non-literal-fs-filename", "lib/read.ts", 4, "CWE-22") in found
    assert result.dropped == {}
