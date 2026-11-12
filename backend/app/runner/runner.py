"""The plug-in runner (T2.1): the host side of the plug-in contract in docs/interfaces.md.

For one plug-in run it creates the run's folders, starts the build container if the plug-in has a
build step, then the scan container, all within the plug-in's time limit, and turns the result
into one of the run statuses of docs/interfaces.md. Every container gets the same fixed flags: no
network for the scan, a read-only root, a non-root user, no capabilities and no host environment.
"""

import hashlib
import json
import logging
import os
import shutil
import time
import uuid
from collections.abc import Callable, Iterable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

from app.runner.engine import ContainerEngine, ContainerResult, ContainerSpec, EngineError, Mount
from app.runner.languages import count_files
from app.runner.manifest import PluginManifest
from app.runner.sarif import (
    InvalidSarif,
    SarifValidator,
    read_plugin_file,
    result_count,
    tool_versions,
)

log = logging.getLogger(__name__)

PLUGIN_UID = 10001
PLUGIN_USER = f"{PLUGIN_UID}:{PLUGIN_UID}"
MAX_LOG_BYTES = 5 * 1024 * 1024
EXIT_NOTHING_TO_SCAN = 3
MAX_SCAN_INFO_BYTES = 64 * 1024


class RunStatus(StrEnum):
    PENDING = "pending"
    BUILDING = "building"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    SKIPPED = "skipped"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


FINAL_STATUSES = {RunStatus.SUCCEEDED, RunStatus.SKIPPED, RunStatus.FAILED, RunStatus.TIMED_OUT}


class Reason(StrEnum):
    """Why a run failed, as stored in analyzer_runs.reason (docs/database.md)."""

    EXIT_CODE = "exit_code"
    MISSING_SARIF = "missing_sarif"
    NOTHING_SCANNED = "nothing_scanned"
    INVALID_SARIF = "invalid_sarif"
    OUT_OF_MEMORY = "out_of_memory"
    BUILD_FAILED = "build_failed"
    RUNNER_ERROR = "runner_error"
    INTERRUPTED = "interrupted"


@dataclass
class PluginRun:
    """One plug-in run in a scan, the analyzer_runs row of docs/database.md."""

    run_id: str
    scan_id: str
    plugin: str
    image: str
    tool_version: str
    rules_version: str
    status: RunStatus = RunStatus.PENDING
    reason: Reason | None = None
    image_digest: str | None = None
    exit_code: int | None = None
    files_scanned: int | None = None
    result_count: int | None = None
    dropped_count: int = 0
    sarif_path: str | None = None
    log_path: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


@dataclass(frozen=True)
class ScanTarget:
    """What the runner needs from a scan. Its checkout is in scans/<scan_id>/src."""

    scan_id: str
    repo_url: str


class RunStore(Protocol):
    def create_run(self, scan_id: str, plugin: PluginManifest) -> PluginRun: ...

    def update(self, run: PluginRun) -> None: ...


class InMemoryRunStore:
    """Keeps runs in a dict. The findings store (T2.3) adds the analyzer_runs table."""

    def __init__(self) -> None:
        self.runs: dict[str, PluginRun] = {}
        self.history: list[tuple[str, RunStatus]] = []

    def create_run(self, scan_id: str, plugin: PluginManifest) -> PluginRun:
        run = PluginRun(
            run_id=str(uuid.uuid4()),
            scan_id=scan_id,
            plugin=plugin.name,
            image=plugin.image,
            tool_version=plugin.tool_version,
            rules_version=plugin.rules_version,
        )
        self.update(run)
        return run

    def update(self, run: PluginRun) -> None:
        self.runs[run.run_id] = run
        self.history.append((run.run_id, run.status))


@dataclass(frozen=True)
class RunnerSettings:
    """Where runs keep their files, and the limits every container gets.

    The worker mounts the sieve-data volume at data_dir, and containers get parts of the same
    volume through volume subpaths. With data_volume set to None, containers get the folders of
    data_dir as host folders instead, for tests and runs outside the worker container.
    """

    data_dir: Path = Path("/data")
    data_volume: str | None = "sieve-data"
    build_network: str = "sieve-build"
    memory: str = "4g"
    cpus: float = 2.0
    scan_pids_limit: int = 512
    build_pids_limit: int = 1024

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "RunnerSettings":
        environ = os.environ if environ is None else environ
        volume = environ.get("SIEVE_DATA_VOLUME", "sieve-data").strip()
        return cls(
            data_dir=Path(environ.get("SIEVE_DATA_DIR", "/data")),
            data_volume=volume or None,
            build_network=environ.get("SIEVE_BUILD_NETWORK", "sieve-build").strip()
            or "sieve-build",
        )


class RunLog:
    """The run's log file, runs/<run_id>/log, kept for every run and cut at 5 MB in total."""

    def __init__(self, data_dir: Path, max_bytes: int = MAX_LOG_BYTES):
        self.data_dir = data_dir
        self.max_bytes = max_bytes

    def path(self, run_id: str) -> Path:
        return self.data_dir / "runs" / run_id / "log"

    def append(self, run_id: str, text: str) -> None:
        path = self.path(run_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        size = path.stat().st_size if path.exists() else 0
        if size >= self.max_bytes:
            return
        data = (text if text.endswith("\n") else text + "\n").encode("utf-8", errors="replace")
        if size + len(data) > self.max_bytes:
            marker = b"\n[log cut at its size limit]\n"
            keep = max(self.max_bytes - size - len(marker), 0)
            data = (data[:keep] + marker)[: self.max_bytes - size]
        with path.open("ab") as file:
            file.write(data)


def maven_cache_volume(repo_url: str) -> str:
    """m2- and the first 16 hex characters of the SHA-256 of the normalized repository URL."""
    parts = urlsplit(repo_url.strip())
    path = parts.path.rstrip("/").removesuffix(".git")
    normalized = f"{parts.scheme.lower()}://{parts.netloc.lower()}{path}"
    return "m2-" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


class PluginRunner:
    def __init__(
        self,
        engine: ContainerEngine,
        store: RunStore,
        settings: RunnerSettings,
        validator: SarifValidator | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.engine = engine
        self.store = store
        self.settings = settings
        self.validator = validator or SarifValidator()
        self.log = RunLog(settings.data_dir)
        self._clock = clock

    def run(self, scan: ScanTarget, plugin: PluginManifest, run: PluginRun) -> PluginRun:
        """Runs one plug-in and returns the run in its final status. Never raises.

        A failure of any kind ends this run, so the scan's other plug-ins still run.
        """
        started = self._clock()
        run.started_at = datetime.now(UTC)
        run.log_path = self._relative(self.log.path(run.run_id))
        try:
            return self._run(scan, plugin, run, started)
        except Exception as error:
            log.exception("plug-in run %s failed in the runner", run.run_id)
            with suppress(Exception):
                self.log.append(run.run_id, f"runner error: {type(error).__name__}: {error}")
            return self._finish(run, RunStatus.FAILED, Reason.RUNNER_ERROR)

    def remove_leftovers(self, scan_id: str) -> None:
        """Removes the containers of a scan that was running when the worker stopped."""
        self.engine.remove_labeled("sieve.scan_id", scan_id)

    def _run(
        self, scan: ScanTarget, plugin: PluginManifest, run: PluginRun, started: float
    ) -> PluginRun:
        checkout = self.settings.data_dir / "scans" / scan.scan_id / "src"
        self.log.append(
            run.run_id,
            f"plug-in {plugin.name}, image {plugin.image}, tool {plugin.tool_version}, "
            f"rules {plugin.rules_version}, time limit {plugin.timeout_seconds} s",
        )
        if not checkout.is_dir():
            self.log.append(run.run_id, f"runner error: no checkout at {checkout}")
            return self._finish(run, RunStatus.FAILED, Reason.RUNNER_ERROR)
        build_digest = None
        try:
            run.image_digest = self.engine.image_digest(plugin.image)
            if plugin.build:
                build_digest = self.engine.image_digest(plugin.build.image)
                # The build runs code from the scanned project, so its network must have no
                # route out except through maven-proxy (docs/interfaces.md, Build step).
                if not self.engine.network_is_internal(self.settings.build_network):
                    raise EngineError(
                        f"the build network {self.settings.build_network} is not an internal "
                        "bridge network, so the build step won't run on it"
                    )
        except EngineError as error:
            self.log.append(run.run_id, f"runner error: {error}")
            return self._finish(run, RunStatus.FAILED, Reason.RUNNER_ERROR)
        self.log.append(run.run_id, f"image digest {run.image_digest}")
        if build_digest:
            self.log.append(run.run_id, f"build image digest {build_digest}")
        out_dir, build_dir = self._prepare_dirs(run, plugin)

        if plugin.build:
            run.status = RunStatus.BUILDING
            self.store.update(run)
            result = self.engine.run(
                self._build_spec(scan, plugin, run), self._left(plugin, started)
            )
            self.log.append(run.run_id, f"--- build step\n{result.log}")
            ended = self._container_ended(run, result, Reason.BUILD_FAILED, "build step")
            if ended:
                return ended

        if self._left(plugin, started) <= 0:
            self.log.append(run.run_id, "timed out after the build step")
            return self._finish(run, RunStatus.TIMED_OUT, None)
        run.status = RunStatus.RUNNING
        self.store.update(run)
        result = self.engine.run(
            self._scan_spec(scan, plugin, run, build_dir is not None),
            self._left(plugin, started),
        )
        self.log.append(run.run_id, f"--- scan step\n{result.log}")
        ended = self._container_ended(run, result, Reason.EXIT_CODE, "scan step")
        if ended:
            return ended
        run.exit_code = result.exit_code
        return self._check_output(checkout, out_dir, plugin, run)

    def _container_ended(
        self, run: PluginRun, result: ContainerResult, failed_reason: Reason, step: str
    ) -> PluginRun | None:
        """The run's end when the container didn't finish normally, or failed in the build."""
        if result.start_failed:
            return self._finish(run, RunStatus.FAILED, Reason.RUNNER_ERROR)
        if result.timed_out:
            self.log.append(run.run_id, f"the {step} reached the time limit and was stopped")
            return self._finish(run, RunStatus.TIMED_OUT, None)
        if result.out_of_memory:
            run.exit_code = result.exit_code
            return self._finish(run, RunStatus.FAILED, Reason.OUT_OF_MEMORY)
        if failed_reason is Reason.BUILD_FAILED and result.exit_code != 0:
            self.log.append(run.run_id, f"the build step exited with {result.exit_code}")
            return self._finish(run, RunStatus.FAILED, Reason.BUILD_FAILED)
        return None

    def _check_output(
        self, checkout: Path, out_dir: Path, plugin: PluginManifest, run: PluginRun
    ) -> PluginRun:
        files_in_languages = count_files(checkout, plugin.languages)
        if run.exit_code == EXIT_NOTHING_TO_SCAN:
            if files_in_languages == 0:
                return self._finish(run, RunStatus.SKIPPED, None)
            self.log.append(
                run.run_id,
                f"exit code 3 means nothing to scan, but the checkout has {files_in_languages} "
                "files in the plug-in's languages",
            )
            return self._finish(run, RunStatus.FAILED, Reason.NOTHING_SCANNED)
        if run.exit_code != 0:
            return self._finish(run, RunStatus.FAILED, Reason.EXIT_CODE)

        try:
            sarif = self.validator.validate(out_dir / "results.sarif")
            run.files_scanned = read_scan_info(out_dir / "scan-info.json")
        except InvalidSarif as error:
            self.log.append(run.run_id, f"{error.reason}: {error}")
            return self._finish(run, RunStatus.FAILED, Reason(error.reason))
        run.sarif_path = self._relative(out_dir / "results.sarif")
        run.result_count = result_count(sarif)
        self.log.append(
            run.run_id,
            f"the SARIF file names {', '.join(tool_versions(sarif))}, the manifest says "
            f"{plugin.tool_version}. {run.result_count} results, {run.files_scanned} files scanned",
        )
        if run.files_scanned == 0 and files_in_languages > 0:
            self.log.append(
                run.run_id,
                f"0 files scanned, but the checkout has {files_in_languages} files in the "
                "plug-in's languages",
            )
            return self._finish(run, RunStatus.FAILED, Reason.NOTHING_SCANNED)
        return self._finish(run, RunStatus.SUCCEEDED, None)

    def _finish(self, run: PluginRun, status: RunStatus, reason: Reason | None) -> PluginRun:
        run.status = status
        run.reason = reason
        run.finished_at = datetime.now(UTC)
        self.store.update(run)
        return run

    def _left(self, plugin: PluginManifest, started: float) -> float:
        return plugin.timeout_seconds - (self._clock() - started)

    def _prepare_dirs(self, run: PluginRun, plugin: PluginManifest) -> tuple[Path, Path | None]:
        """Creates runs/<run_id>/out, empty, and build for a build step, writable by the plug-in."""
        run_dir = self.settings.data_dir / "runs" / run.run_id
        out_dir = run_dir / "out"
        build_dir = run_dir / "build" if plugin.build else None
        for folder in (out_dir, build_dir):
            if folder is None:
                continue
            if folder.exists():
                shutil.rmtree(folder)
            folder.mkdir(parents=True)
            _give_to_plugin_user(folder)
        return out_dir, build_dir

    def _scan_spec(
        self, scan: ScanTarget, plugin: PluginManifest, run: PluginRun, with_build: bool
    ) -> ContainerSpec:
        mounts = [
            self._data_mount(f"scans/{scan.scan_id}/src", "/src", read_only=True),
            self._data_mount(f"runs/{run.run_id}/out", "/out", read_only=False),
        ]
        if with_build:
            mounts.append(self._data_mount(f"runs/{run.run_id}/build", "/build", read_only=True))
        return ContainerSpec(
            image=plugin.image,
            network="none",
            user=PLUGIN_USER,
            mounts=tuple(mounts),
            env={"SIEVE_SRC": "/src", "SIEVE_OUT": "/out", "HOME": "/tmp"},
            labels=_labels(scan, run, "scan"),
            memory=self.settings.memory,
            cpus=self.settings.cpus,
            pids_limit=self.settings.scan_pids_limit,
        )

    def _build_spec(
        self, scan: ScanTarget, plugin: PluginManifest, run: PluginRun
    ) -> ContainerSpec:
        assert plugin.build is not None
        mounts = (
            self._data_mount(f"scans/{scan.scan_id}/src", "/src", read_only=True),
            self._data_mount(f"runs/{run.run_id}/build", "/build", read_only=False),
            Mount(target="/cache/m2", read_only=False, volume=maven_cache_volume(scan.repo_url)),
        )
        return ContainerSpec(
            image=plugin.build.image,
            network=self.settings.build_network,
            user=PLUGIN_USER,
            mounts=mounts,
            env={"SIEVE_SRC": "/src", "SIEVE_BUILD": "/build", "HOME": "/tmp"},
            labels=_labels(scan, run, "build"),
            memory=self.settings.memory,
            cpus=self.settings.cpus,
            pids_limit=self.settings.build_pids_limit,
        )

    def _data_mount(self, subpath: str, target: str, read_only: bool) -> Mount:
        if self.settings.data_volume:
            return Mount(
                target=target,
                read_only=read_only,
                volume=self.settings.data_volume,
                subpath=subpath,
            )
        host_path = str((self.settings.data_dir / subpath).resolve())
        return Mount(target=target, read_only=read_only, host_path=host_path)

    def _relative(self, path: Path) -> str:
        return path.relative_to(self.settings.data_dir).as_posix()


def read_scan_info(path: Path) -> int:
    """files_scanned from scan-info.json. A missing or unreadable file counts as missing."""
    data = read_plugin_file(path, MAX_SCAN_INFO_BYTES)
    try:
        files_scanned = json.loads(data)["files_scanned"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
        raise InvalidSarif("missing_sarif", "scan-info.json has no files_scanned") from None
    if not isinstance(files_scanned, int) or isinstance(files_scanned, bool) or files_scanned < 0:
        raise InvalidSarif("missing_sarif", "files_scanned in scan-info.json is not a count")
    return files_scanned


def run_plugins(
    runner: PluginRunner, scan: ScanTarget, plugins: Iterable[PluginManifest]
) -> list[PluginRun]:
    """Runs each plug-in in turn. A failed run doesn't stop the ones after it."""
    runs = []
    for plugin in plugins:
        run = runner.store.create_run(scan.scan_id, plugin)
        runs.append(runner.run(scan, plugin, run))
    return runs


def scan_status(runs: Iterable[PluginRun]) -> str:
    """failed, partial or completed, by the rules in docs/interfaces.md, Run statuses."""
    statuses = [run.status for run in runs]
    if not all(status in FINAL_STATUSES for status in statuses):
        raise ValueError("every run must have ended before the scan gets a status")
    bad = any(status in (RunStatus.FAILED, RunStatus.TIMED_OUT) for status in statuses)
    if bad and RunStatus.SUCCEEDED not in statuses:
        return "failed"
    if bad:
        return "partial"
    return "completed"


def _labels(scan: ScanTarget, run: PluginRun, step: str) -> dict[str, str]:
    return {"sieve.scan_id": scan.scan_id, "sieve.run_id": run.run_id, "sieve.step": step}


def _give_to_plugin_user(folder: Path) -> None:
    """The plug-in runs as user 10001, so it must be able to write its own folders.

    The worker runs as root and hands the folder over. Anywhere else, such as in the tests, the
    folder is opened to everyone instead. On Windows, Docker Desktop doesn't check owners.
    """
    if os.name != "posix":
        return
    if os.geteuid() == 0:
        os.chown(folder, PLUGIN_UID, PLUGIN_UID)
    else:
        folder.chmod(0o777)

