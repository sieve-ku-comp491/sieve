"""The scan service: the scope check, the export, the choice of plug-ins by language, and the
import of each succeeded run's findings. A fake engine stands in for Docker.

The Semgrep fixture of PyGoat (tests/adapter_fixture) has 9 results in
dockerized_labs/sql_injection_lab/app.py, and test_store_runs.py checks that each becomes a
finding, so a scan whose fake Semgrep run writes that file stores 9 findings.

F2 tests 4 and 5 clone from GitHub and are skipped when github.com can't be reached.
"""

import shutil
import socket
import uuid
from pathlib import Path

import pytest

from app.adapters import AdapterRegistry, SemgrepAdapter
from app.runner import (
    ContainerResult,
    ContainerSpec,
    InMemoryRunStore,
    PluginManifest,
    PluginRegistry,
    PluginRunner,
    RunnerSettings,
    RunStatus,
)
from app.scan import CheckoutExporter, ExportError, ScanService, ScopeEntry
from app.store.runs import ScanRequest

FIXTURE = Path(__file__).parent / "adapter_fixture"
PYGOAT = "https://github.com/adeyosemanputra/pygoat"
PINNED = "2aa4cc14f251e4a780e94e200aed6b36a5b15c21"
FORK_ONLY = "0dc3c4f403bea36b83a03c7c07a7d676b939eab3"


class MemoryStore(InMemoryRunStore):
    """The scans, runs and findings a scan service writes, kept in memory."""

    def __init__(self) -> None:
        super().__init__()
        self.scans: dict[str, dict] = {}
        self.findings: dict[str, list] = {}

    def add_scan(self, repo_url: str, commit_sha=None, requested_ref=None) -> str:
        scan_id = str(uuid.uuid4())
        self.scans[scan_id] = {
            "repo_url": repo_url,
            "commit_sha": commit_sha,
            "requested_ref": requested_ref,
            "status": "queued",
            "error": None,
            "languages": [],
        }
        return scan_id

    def get_scan(self, scan_id: str) -> ScanRequest:
        s = self.scans[scan_id]
        return ScanRequest(scan_id, s["repo_url"], s["commit_sha"], s["requested_ref"], s["status"])

    def update_scan(self, scan_id, status, *, error=None, languages=None, commit_sha=None):
        scan = self.scans[scan_id]
        scan["status"] = status
        scan["error"] = error
        if languages is not None:
            scan["languages"] = languages
        if commit_sha is not None:
            scan["commit_sha"] = commit_sha

    def save_findings(self, run, result):
        self.update(run)
        self.findings[run.run_id] = list(result.findings)
        return [str(n) for n in range(len(result.findings))]


class FakeExporter:
    """Copies a folder instead of cloning, and records what it was asked for."""

    def __init__(self, files: Path | None, error: str | None = None):
        self.files = files
        self.error = error
        self.calls: list[tuple[str, str]] = []

    def export(self, entry: ScopeEntry, ref: str, dest: Path) -> str:
        self.calls.append((entry.url, ref))
        if self.error:
            raise ExportError(self.error)
        shutil.copytree(self.files, dest)
        return PINNED


class FakeEngine:
    """Writes the SARIF file that each image is given in sarif, and records every container."""

    def __init__(self, sarif: dict[str, Path | None]):
        self.sarif = sarif
        self.specs: list[ContainerSpec] = []

    def image_digest(self, image: str) -> str:
        return f"sha256:{image}"

    def network_is_internal(self, name: str) -> bool:
        return True

    def remove_labeled(self, label: str, value: str) -> None:
        pass

    def run(self, spec: ContainerSpec, timeout_seconds: float) -> ContainerResult:
        self.specs.append(spec)
        source = self.sarif[spec.image]
        if source is None:
            return ContainerResult(exit_code=1, log="crashed")
        out = Path(next(m for m in spec.mounts if m.target == "/out").host_path)
        shutil.copyfile(source, out / "results.sarif")
        (out / "scan-info.json").write_text('{"files_scanned": 1}', encoding="utf-8")
        return ContainerResult(exit_code=0)


def manifest(name: str, languages: tuple[str, ...], adapter: str | None = None) -> PluginManifest:
    return PluginManifest(
        name=name,
        image=f"sieve-plugin-{name}:1",
        languages=languages,
        adapter=adapter or name,
        tool_version="1",
        rules_version="1",
    )


SEMGREP = manifest("semgrep", ("python", "java", "javascript", "typescript"))
SPOTBUGS = manifest("spotbugs", ("java",))
SECRETS = manifest("secrets", ("*",), adapter="no-such-adapter")
CRASHER = manifest("crasher", ("python",), adapter="semgrep")


def scope_file(tmp_path: Path, url: str = PYGOAT) -> Path:
    path = tmp_path / "scope.toml"
    path.write_text(f'[[repository]]\nurl = "{url}.git"\nreason = "test"\n', encoding="utf-8")
    return path


def service(tmp_path, store, exporter, engine, plugins) -> ScanService:
    data_dir = tmp_path / "data"
    settings = RunnerSettings(data_dir=data_dir, data_volume=None)
    return ScanService(
        scope_file(tmp_path),
        store=store,
        exporter=exporter,
        plugins=PluginRegistry(plugins),
        runner=PluginRunner(engine, store, settings),
        adapters=AdapterRegistry([SemgrepAdapter()]),
        data_dir=data_dir,
    )


def test_a_scan_runs_the_plugins_for_its_languages_and_stores_the_findings(tmp_path):
    store = MemoryStore()
    scan_id = store.add_scan(PYGOAT, requested_ref="HEAD")
    exporter = FakeExporter(FIXTURE / "pygoat")
    engine = FakeEngine({SEMGREP.image: FIXTURE / "semgrep-pygoat.sarif"})
    scans = service(tmp_path, store, exporter, engine, [SEMGREP, SPOTBUGS])

    assert scans.run_scan(scan_id) == "completed"
    # The URL written in the scope entry is cloned, not the one in the scan.
    assert exporter.calls == [(f"{PYGOAT}.git", "HEAD")]
    scan = store.scans[scan_id]
    assert (scan["status"], scan["commit_sha"], scan["languages"]) == (
        "completed",
        PINNED,
        ["python"],
    )
    # No Java files, so only Semgrep ran.
    assert [spec.image for spec in engine.specs] == [SEMGREP.image]
    (run,) = store.runs.values()
    assert (run.plugin, run.status) == ("semgrep", RunStatus.SUCCEEDED)
    assert len(store.findings[run.run_id]) == 9
    log = (tmp_path / "data" / run.log_path).read_text(encoding="utf-8")
    assert "adapter semgrep: 9 findings, 0 results dropped" in log


def test_failed_runs_make_the_scan_partial_and_the_others_still_run(tmp_path):
    store = MemoryStore()
    scan_id = store.add_scan(PYGOAT, commit_sha=PINNED)
    engine = FakeEngine({SEMGREP.image: FIXTURE / "semgrep-pygoat.sarif", CRASHER.image: None})
    plugins = [SEMGREP, SECRETS, CRASHER]
    scans = service(tmp_path, store, FakeExporter(FIXTURE / "pygoat"), engine, plugins)

    assert scans.run_scan(scan_id) == "partial"
    runs = {run.plugin: run for run in store.runs.values()}
    assert {name: (r.status, r.reason) for name, r in runs.items()} == {
        "semgrep": (RunStatus.SUCCEEDED, None),
        "secrets": (RunStatus.FAILED, "runner_error"),
        "crasher": (RunStatus.FAILED, "exit_code"),
    }
    # The plug-in whose adapter doesn't exist never got a container.
    assert sorted(spec.image for spec in engine.specs) == sorted([SEMGREP.image, CRASHER.image])
    log = (tmp_path / "data" / runs["secrets"].log_path).read_text(encoding="utf-8")
    assert "no adapter named 'no-such-adapter'" in log


def test_a_scan_whose_export_fails_ends_failed_before_any_plugin(tmp_path):
    store = MemoryStore()
    scan_id = store.add_scan(PYGOAT, requested_ref="main")
    engine = FakeEngine({})
    exporter = FakeExporter(None, error="cloning failed: repository not found")
    scans = service(tmp_path, store, exporter, engine, [SEMGREP])

    assert scans.run_scan(scan_id) == "failed"
    assert store.scans[scan_id]["error"] == "cloning failed: repository not found"
    assert engine.specs == [] and store.runs == {}


def test_a_repository_removed_from_the_scope_file_after_queueing_is_not_cloned(tmp_path):
    store = MemoryStore()
    scan_id = store.add_scan("https://github.com/adeyosemanputra/other", requested_ref="HEAD")
    exporter = FakeExporter(FIXTURE / "pygoat")
    engine = FakeEngine({})
    scans = service(tmp_path, store, exporter, engine, [SEMGREP])

    assert scans.run_scan(scan_id) == "failed"
    assert "is not in the scope file" in store.scans[scan_id]["error"]
    assert exporter.calls == [] and engine.specs == []


def github_reachable() -> bool:
    try:
        socket.create_connection(("github.com", 443), timeout=5).close()
    except OSError:
        return False
    return True


network = pytest.mark.skipif(not github_reachable(), reason="github.com can't be reached")


@network
def test_f2_5_a_commit_that_exists_only_in_a_fork_is_refused_before_any_container(tmp_path):
    store = MemoryStore()
    scan_id = store.add_scan(PYGOAT, commit_sha=FORK_ONLY)
    engine = FakeEngine({})
    scans = service(tmp_path, store, CheckoutExporter(), engine, [SEMGREP])

    assert scans.run_scan(scan_id) == "failed"
    error = store.scans[scan_id]["error"]
    assert error == f"commit {FORK_ONLY} is not on a branch or tag of {PYGOAT}.git"
    assert engine.specs == [] and store.runs == {}
    assert not (tmp_path / "data" / "scans" / scan_id / "src").exists()


@network
def test_f2_4_a_private_repository_cannot_be_cloned_even_when_listed(tmp_path):
    # GitHub answers an anonymous clone of a private repository exactly as one of a repository
    # that doesn't exist: 401 and a request for credentials. With no credential helper and
    # GIT_TERMINAL_PROMPT=0, as in the worker, the clone fails.
    private = "https://github.com/sieve-ku-comp491/private-scope-test"
    store = MemoryStore()
    scan_id = store.add_scan(private, requested_ref="HEAD")
    engine = FakeEngine({})
    scans = service(tmp_path, store, CheckoutExporter(), engine, [SEMGREP])
    scans.scope_path = scope_file(tmp_path, private)

    assert scans.run_scan(scan_id) == "failed"
    assert store.scans[scan_id]["error"].startswith(f"cloning {private}.git failed")
    assert engine.specs == []


@network
def test_the_pinned_pygoat_commit_is_exported(tmp_path):
    dest = tmp_path / "src"
    entry = ScopeEntry(PYGOAT, "test")
    assert CheckoutExporter().export(entry, "2aa4cc1", dest) == PINNED
    assert (dest / "dockerized_labs" / "sql_injection_lab" / "app.py").read_bytes() == (
        FIXTURE / "pygoat" / "dockerized_labs" / "sql_injection_lab" / "app.py"
    ).read_bytes()
