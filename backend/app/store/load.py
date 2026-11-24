"""Loads a saved SARIF file of one plug-in run into the findings store, as a completed scan.

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
    migrate(conninfo)
    plugin = PluginManifest.load(manifest_path)
    adapter = AdapterRegistry().get(plugin.adapter)
    sarif = SarifValidator().validate(sarif_path)
    if not checkout.is_dir():
        raise FileNotFoundError(f"{checkout} is not a folder")

    store = PostgresRunStore(conninfo)
    scan_id = store.create_scan(repo_url, commit_sha=commit_sha)
    run = None
    saved = False
    try:
        store.update_scan(scan_id, "running")
        source = data_dir / "scans" / scan_id / "src"
        shutil.copytree(checkout, source, symlinks=True)
        languages = sorted(lang for lang in plugin.languages if count_files(source, [lang]))

        run = store.create_run(scan_id, plugin)
        run.started_at = datetime.now(UTC)
        out = data_dir / "runs" / run.run_id / "out"
        out.mkdir(parents=True)
        shutil.copyfile(sarif_path, out / "results.sarif")
        run.sarif_path = (Path("runs") / run.run_id / "out" / "results.sarif").as_posix()
        run.log_path = (Path("runs") / run.run_id / "log").as_posix()
        run.image_digest = image_digest
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
        store.update_scan(scan_id, "completed", languages=languages)
    except BaseException as error:
        if run is not None and not saved:
            run.status = RunStatus.FAILED
            run.reason = Reason.RUNNER_ERROR
            run.finished_at = datetime.now(UTC)
            store.update(run)
        store.update_scan(scan_id, "failed", error=f"loading {sarif_path.name} failed: {error}")
        raise
    return Loaded(scan_id, run.run_id, len(result.findings), dict(result.dropped))
