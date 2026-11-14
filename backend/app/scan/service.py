"""The scan service (docs/class-diagrams.md, docs/sequences.md "Scan and import").

start_scan() runs in the API: it checks the repository against the scope file before anything
is created, then stores the scan with its job. run_scan() runs in the worker: it checks the scope
file again, exports the commit from the URL in the scope entry, finds the languages, runs the
plug-ins for them, at most two at a time, turns each succeeded run's SARIF file into findings
with the plug-in's adapter and stores them.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from app.adapters import AdapterError, AdapterRegistry, AdapterResult
from app.checkout import CheckoutReader
from app.runner.languages import detect_languages
from app.runner.manifest import PluginManifest, PluginRegistry
from app.runner.runner import (
    PluginRun,
    PluginRunner,
    Reason,
    RunLog,
    RunStatus,
    ScanTarget,
    scan_status,
)
from app.runner.sarif import SarifValidator
from app.scan.exporter import CheckoutExporter, ExportError, split_ref
from app.scan.scope import OutOfScope, ScopeError, ScopeFile, UrlError
from app.store.runs import ScanRequest

log = logging.getLogger(__name__)

MAX_PARALLEL_RUNS = 2


class NoQueue(RuntimeError):
    """The scan passed the scope check, but there is no database to queue it in."""


@dataclass(frozen=True)
class StartedScan:
    scan_id: str
    job_id: str
    repo_url: str


class ScanQueue(Protocol):
    def create_scan(
        self, repo_url: str, commit_sha: str | None, requested_ref: str | None
    ) -> tuple[str, str]: ...


class ScanStore(Protocol):
    def get_scan(self, scan_id: str) -> ScanRequest: ...

    def update_scan(
        self,
        scan_id: str,
        status: str,
        *,
        error: str | None = None,
        languages: list[str] | None = None,
        commit_sha: str | None = None,
    ) -> None: ...

    def create_run(self, scan_id: str, plugin: PluginManifest) -> PluginRun: ...

    def update(self, run: PluginRun) -> None: ...

    def save_findings(self, run: PluginRun, result: AdapterResult) -> list[str]: ...


class ScanService:
    def __init__(
        self,
        scope_path: Path,
        *,
        queue: ScanQueue | None = None,
        store: ScanStore | None = None,
        exporter: CheckoutExporter | None = None,
        plugins: PluginRegistry | None = None,
        runner: PluginRunner | None = None,
        adapters: AdapterRegistry | None = None,
        data_dir: Path = Path("/data"),
    ):
        self.scope_path = scope_path
        self.queue = queue
        self.store = store
        self.exporter = exporter or CheckoutExporter()
        self.plugins = plugins
        self.runner = runner
        self.adapters = adapters or AdapterRegistry()
        self.data_dir = data_dir
        self.validator = SarifValidator()
        self.log = RunLog(data_dir)

    def start_scan(self, repo_url: str, commit: str | None = None) -> StartedScan:
        """Checks the repository against the scope file and queues the scan. Raises
        ScopeError, UrlError, OutOfScope or RefError, and then nothing has been created."""
        entry = ScopeFile.load(self.scope_path).allows(repo_url)
        commit_sha, requested_ref = split_ref(commit)
        if self.queue is None:
            raise NoQueue("DATABASE_URL is not set")
        url = entry.normalized_url
        scan_id, job_id = self.queue.create_scan(url, commit_sha, requested_ref)
        return StartedScan(scan_id, job_id, url)

    def run_scan(self, scan_id: str) -> str:
        """Runs a queued scan to its end and returns its final status."""
        store = self._need(self.store)
        scan = store.get_scan(scan_id)
        store.update_scan(scan_id, "running")
        source = self.data_dir / "scans" / scan_id / "src"
        try:
            entry = ScopeFile.load(self.scope_path).allows(scan.repo_url)
            commit_sha = self.exporter.export(entry, scan.commit_sha or scan.requested_ref, source)
            languages = detect_languages(source)
        except (ScopeError, UrlError, OutOfScope, ExportError) as error:
            store.update_scan(scan_id, "failed", error=str(error))
            return "failed"
        store.update_scan(scan_id, "running", languages=languages, commit_sha=commit_sha)

        plugins = self._need(self.plugins).for_languages(set(languages))
        runs = self._run_plugins(ScanTarget(scan_id, scan.repo_url), plugins, source)
        status = scan_status(runs)
        error = None
        if status == "failed":
            error = "every plug-in run failed or timed out"
        store.update_scan(scan_id, status, error=error)
        return status

    def _run_plugins(
        self, target: ScanTarget, plugins: list[PluginManifest], source: Path
    ) -> list[PluginRun]:
        """Creates every run as pending first, so the runs exist before any container starts,
        then runs them at most two at a time. Each succeeded run's findings are stored as soon
        as it ends, in this thread, one run at a time."""
        store = self._need(self.store)
        runner = self._need(self.runner)
        planned = [(plugin, store.create_run(target.scan_id, plugin)) for plugin in plugins]
        runs = []
        with ThreadPoolExecutor(max_workers=MAX_PARALLEL_RUNS) as pool:
            futures = {}
            for plugin, run in planned:
                try:
                    self.adapters.get(plugin.adapter)
                except AdapterError as error:
                    runs.append(self._fail(run, f"runner error: {error}"))
                    continue
                futures[pool.submit(runner.run, target, plugin, run)] = plugin
            for future in as_completed(futures):
                run = future.result()
                if run.status == RunStatus.SUCCEEDED:
                    run = self._import(futures[future], run, source)
                runs.append(run)
        return runs

    def _import(self, plugin: PluginManifest, run: PluginRun, source: Path) -> PluginRun:
        """Converts the run's SARIF file with the plug-in's adapter and stores the findings."""
        try:
            sarif = self.validator.validate(self.data_dir / (run.sarif_path or ""))
            result = self.adapters.get(plugin.adapter).to_findings(
                sarif, run, CheckoutReader(source)
            )
            for warning in result.warnings:
                self.log.append(run.run_id, warning)
            if result.more_warnings:
                self.log.append(run.run_id, f"{result.more_warnings} more warnings")
            dropped = ", ".join(f"{n} {reason}" for reason, n in sorted(result.dropped.items()))
            self.log.append(
                run.run_id,
                f"adapter {plugin.adapter}: {len(result.findings)} findings, "
                f"{result.dropped_count} results dropped" + (f" ({dropped})" if dropped else ""),
            )
            self._need(self.store).save_findings(run, result)
        except Exception as error:
            log.exception("storing the findings of run %s failed", run.run_id)
            return self._fail(run, f"runner error while storing findings: {error}")
        return run

    def _fail(self, run: PluginRun, message: str) -> PluginRun:
        self.log.append(run.run_id, message)
        run.log_path = run.log_path or f"runs/{run.run_id}/log"
        run.status = RunStatus.FAILED
        run.reason = Reason.RUNNER_ERROR
        run.finished_at = datetime.now(UTC)
        self._need(self.store).update(run)
        return run

    @staticmethod
    def _need[T](value: T | None) -> T:
        if value is None:
            raise RuntimeError("the scan service was created without what run_scan needs")
        return value
