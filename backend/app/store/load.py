"""Loads saved SARIF files of plug-in runs on one checkout into the findings store, as one
completed scan.

This is how findings get into the store before scans run end to end: from a SARIF file that the
plug-in wrote earlier, and the checkout it scanned. The checkout and the SARIF file are copied
into the data folder where the worker keeps them (scans/<scan ID>/src and runs/<run ID>/out), so
the API can show the code of each finding the same way it will for a real scan.
"""

import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from app.adapters import AdapterRegistry
from app.checkout import CheckoutReader
from app.runner.languages import count_files
from app.runner.manifest import PluginManifest
from app.runner.runner import Reason, RunLog, RunStatus, read_scan_info
from app.runner.sarif import InvalidSarif, SarifValidator, result_count
from app.store.migrate import migrate
from app.store.runs import PostgresRunStore


@dataclass(frozen=True)
class Loaded:
    scan_id: str
    run_id: str
    findings: int
    dropped: dict[str, int]


def load_sarif(
    conninfo: str,
    data_dir: Path,
    manifest_path: Path,
    sarif_path: Path,
    checkout: Path,
    repo_url: str,
    commit_sha: str,
    image_digest: str | None = None,
) -> Loaded:
    """Stores one scan with one succeeded run of the plug-in in manifest_path, and the findings
    its adapter makes from sarif_path. files_scanned is read from scan-info.json next to the
    SARIF file, when it is there."""
    runs = [SavedRun(manifest_path, sarif_path, image_digest)]
    return load_runs(conninfo, data_dir, runs, checkout, repo_url, commit_sha)[0]


@dataclass(frozen=True)
class SavedRun:
    manifest_path: Path
    sarif_path: Path
    image_digest: str | None = None


def load_runs(
    conninfo: str,
    data_dir: Path,
    runs: list[SavedRun],
    checkout: Path,
    repo_url: str,
    commit_sha: str,
) -> list[Loaded]:
    """Stores one scan with a succeeded run per saved run, such as Semgrep's and SpotBugs' on
    the same commit, so that deduplication can group their findings. Every SARIF file is
    checked before anything is stored."""
    if not runs:
        raise ValueError("no SARIF file to load")
    migrate(conninfo)
    checked = []
    for saved in runs:
        plugin = PluginManifest.load(saved.manifest_path)
        adapter = AdapterRegistry().get(plugin.adapter)
        checked.append((saved, plugin, adapter, SarifValidator().validate(saved.sarif_path)))
    if not checkout.is_dir():
        raise FileNotFoundError(f"{checkout} is not a folder")

    store = PostgresRunStore(conninfo)
    scan_id = store.create_scan(repo_url, commit_sha=commit_sha)
    loaded: list[Loaded] = []
    run = None
    saved_run = runs[0]
    saved = False
    try:
        store.update_scan(scan_id, "running")
        source = data_dir / "scans" / scan_id / "src"
        shutil.copytree(checkout, source, symlinks=True)
        languages: set[str] = set()
        for saved_run, plugin, adapter, sarif in checked:
            sarif_path = saved_run.sarif_path
            languages |= {lang for lang in plugin.languages if count_files(source, [lang])}
            saved = False
            run = store.create_run(scan_id, plugin)
            run.started_at = datetime.now(UTC)
            out = data_dir / "runs" / run.run_id / "out"
            out.mkdir(parents=True)
            shutil.copyfile(sarif_path, out / "results.sarif")
            run.sarif_path = (Path("runs") / run.run_id / "out" / "results.sarif").as_posix()
            run.log_path = (Path("runs") / run.run_id / "log").as_posix()
            run.image_digest = saved_run.image_digest
            run.result_count = result_count(sarif)
            try:
                run.files_scanned = read_scan_info(sarif_path.with_name("scan-info.json"))
            except InvalidSarif:
                run.files_scanned = None

            log = RunLog(data_dir)
            log.append(run.run_id, f"loaded from {sarif_path.name}, plug-in {plugin.name}")
            result = adapter.to_findings(sarif, run, CheckoutReader(source))
            for warning in result.warnings:
                log.append(run.run_id, warning)
            if result.more_warnings:
                log.append(run.run_id, f"{result.more_warnings} more warnings")

            run.status = RunStatus.SUCCEEDED
            run.finished_at = datetime.now(UTC)
            store.save_findings(run, result)
            saved = True
            loaded.append(Loaded(scan_id, run.run_id, len(result.findings), dict(result.dropped)))
        store.update_scan(scan_id, "completed", languages=sorted(languages))
    except BaseException as error:
        if run is not None and not saved:
            run.status = RunStatus.FAILED
            run.reason = Reason.RUNNER_ERROR
            run.finished_at = datetime.now(UTC)
            store.update(run)
        error_text = f"loading {saved_run.sarif_path.name} failed: {error}"
        store.update_scan(scan_id, "failed", error=error_text)
        raise
    return loaded
