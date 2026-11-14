"""The worker: takes jobs from the queue and runs them (docs/architecture.md, "Background jobs").

python -m app.worker runs until it is stopped. It handles scan jobs. Sieve runs exactly one
worker. When it starts, every job still marked as running was interrupted: the job, its scan and
the scan's unfinished plug-in runs are marked failed, and the scan's containers are removed.

Settings, from the environment: DATABASE_URL, SIEVE_SCOPE_FILE, SIEVE_PLUGINS_DIR, and the
runner's SIEVE_DATA_DIR, SIEVE_DATA_VOLUME, SIEVE_BUILD_NETWORK and DOCKER_SOCKET
(plugins/README.md).
"""

import logging
import os
import sys
import time
from contextlib import suppress
from pathlib import Path

from app.adapters import AdapterRegistry
from app.runner import DockerEngine, PluginRegistry, PluginRunner, RunnerSettings
from app.scan.scope import DEFAULT_SCOPE_FILE
from app.scan.service import ScanService
from app.store.jobs import Job, PostgresJobQueue
from app.store.runs import PostgresRunStore

log = logging.getLogger("app.worker")

KINDS = ["scan"]
POLL_SECONDS = 2.0


class Worker:
    def __init__(self, queue: PostgresJobQueue, service: ScanService, runner: PluginRunner):
        self.queue = queue
        self.service = service
        self.runner = runner

    def recover(self) -> None:
        for scan_id in self.queue.recover_interrupted():
            log.warning("scan %s was interrupted, removing its containers", scan_id)
            self.runner.remove_leftovers(scan_id)

    def run_next(self) -> bool:
        """Runs the oldest queued job, if there is one. Returns whether there was."""
        job = self.queue.claim(KINDS)
        if job is None:
            return False
        log.info("job %s: %s %s", job.id, job.kind, job.payload)
        try:
            status = self._run(job)
        except Exception as error:
            log.exception("job %s failed", job.id)
            message = f"{type(error).__name__}: {error}"
            self._fail_scan(job, message)
            self.queue.finish(job.id, error=message)
        else:
            log.info("job %s finished, the scan is %s", job.id, status)
            self.queue.finish(job.id)
        return True

    def _run(self, job: Job) -> str:
        return self.service.run_scan(str(job.payload["scan_id"]))

    def _fail_scan(self, job: Job, message: str) -> None:
        scan_id = job.payload.get("scan_id")
        if scan_id and self.service.store is not None:
            with suppress(Exception):
                self.service.store.update_scan(str(scan_id), "failed", error=message)

    def forever(self, poll_seconds: float = POLL_SECONDS) -> None:
        self.recover()
        log.info("waiting for jobs")
        while True:
            if not self.run_next():
                time.sleep(poll_seconds)


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    conninfo = os.environ.get("DATABASE_URL")
    if not conninfo:
        print("DATABASE_URL is not set", file=sys.stderr)
        return 2
    settings = RunnerSettings.from_env()
    store = PostgresRunStore(conninfo)
    runner = PluginRunner(DockerEngine.from_env(), store, settings)
    plugins = PluginRegistry.load(Path(os.environ.get("SIEVE_PLUGINS_DIR", "/plugins")))
    log.info("plug-ins: %s", ", ".join(p.name for p in plugins.all()) or "none")
    service = ScanService(
        Path(os.environ.get("SIEVE_SCOPE_FILE", DEFAULT_SCOPE_FILE)),
        store=store,
        plugins=plugins,
        runner=runner,
        adapters=AdapterRegistry(),
        data_dir=settings.data_dir,
    )
    try:
        Worker(PostgresJobQueue(conninfo), service, runner).forever()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
