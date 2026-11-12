"""The runner against a real Docker Engine, with the small test plug-in in tests/plugin_fixture.

Skipped when Docker isn't running. CI's Ubuntu runners have Docker, so these run there.
"""

import socket
import sys
import threading
import time
import uuid
from pathlib import Path

import docker
import docker.errors
import pytest

from app.runner import (
    BuildStep,
    DockerEngine,
    InMemoryRunStore,
    PluginManifest,
    PluginRun,
    PluginRunner,
    Reason,
    RunnerSettings,
    RunStatus,
    ScanTarget,
    maven_cache_volume,
    run_plugins,
    scan_status,
)

FIXTURE_DIR = Path(__file__).with_name("plugin_fixture")
IMAGE = "sieve-test-plugin:1"


@pytest.fixture(scope="module")
def client() -> docker.DockerClient:
    try:
        client = docker.from_env()
        client.ping()
    except Exception:
        pytest.skip("Docker is not running")
    client.images.build(path=str(FIXTURE_DIR), tag=IMAGE, rm=True)
    return client


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    return tmp_path


def checkout(data_dir: Path, mode: str, **files: str) -> ScanTarget:
    scan = ScanTarget(scan_id=str(uuid.uuid4()), repo_url=f"https://example.com/{uuid.uuid4()}")
    src = data_dir / "scans" / scan.scan_id / "src"
    src.mkdir(parents=True)
    # newline="\n" keeps Windows from writing \r\n, which the plug-in's shell would read.
    (src / "mode").write_text(mode + "\n", newline="\n")
    (src / "app.py").write_text("print('hi')\n", newline="\n")
    for name, text in files.items():
        (src / name).write_text(text, newline="\n")
    return scan


def manifest(**changes) -> PluginManifest:
    fields = {
        "name": "fixture",
        "image": IMAGE,
        "languages": ("*",),
        "adapter": "fixture",
        "tool_version": "0.0.1",
        "rules_version": "none",
        "timeout_seconds": 60,
    }
    return PluginManifest(**(fields | changes))


def make_runner(client, data_dir: Path, **settings) -> PluginRunner:
    settings = {"data_dir": data_dir, "data_volume": None} | settings
    return PluginRunner(DockerEngine(client), InMemoryRunStore(), RunnerSettings(**settings))


def run_one(runner: PluginRunner, scan: ScanTarget, plugin: PluginManifest) -> PluginRun:
    run = runner.store.create_run(scan.scan_id, plugin)
    return runner.run(scan, plugin, run)


def containers_of(client, run: PluginRun) -> list:
    return client.containers.list(all=True, filters={"label": f"sieve.run_id={run.run_id}"})


def log_text(data_dir: Path, run: PluginRun) -> str:
    return (data_dir / run.log_path).read_text(encoding="utf-8")


def test_success_with_the_contract_flags(client, data_dir):
    scan = checkout(data_dir, "probe")
    run = run_one(make_runner(client, data_dir), scan, manifest())

    assert run.status is RunStatus.SUCCEEDED, log_text(data_dir, run)
    assert (run.files_scanned, run.result_count) == (2, 1)
    assert run.image_digest.startswith("sha256:")
    assert (data_dir / run.sarif_path).is_file()
    assert containers_of(client, run) == []

    probe = dict(
        line.split("=", 1)
        for line in (data_dir / "runs" / run.run_id / "out" / "probe.txt").read_text().split("\n")
        if "=" in line
    )
    assert probe["uid"] == "10001 gid=10001"
    assert probe["src"] == "read-only"
    assert probe["root"] == "read-only"
    assert probe["tmp"] == "writable"
    assert probe["caps"] == "CapEff:0000000000000000"
    assert probe["nonewprivs"] == "NoNewPrivs:1"
    # No route at all, so nothing outside the container can be reached. Some kernels add tunnel
    # interfaces such as sit0 to every namespace, so the interface list isn't compared.
    assert probe["routes"].strip() == "0"
    env = set(probe["env"].split())
    assert {"SIEVE_SRC", "SIEVE_OUT", "HOME"} <= env
    # Docker and the shell add PATH, HOSTNAME, PWD and SHLVL. Nothing from the host gets in.
    assert env <= {"SIEVE_SRC", "SIEVE_OUT", "HOME", "PATH", "HOSTNAME", "PWD", "SHLVL"}


def test_timeout_stops_and_removes_the_container(client, data_dir):
    scan = checkout(data_dir, "sleep")
    started = time.monotonic()
    run = run_one(make_runner(client, data_dir), scan, manifest(timeout_seconds=3))

    assert run.status is RunStatus.TIMED_OUT
    assert run.exit_code is None
    assert time.monotonic() - started < 30
    assert containers_of(client, run) == []
    assert "sleeping" in log_text(data_dir, run)


def test_failures_keep_their_logs_and_the_other_plugins_still_run(client, data_dir):
    runner = make_runner(client, data_dir)
    # The mode is a file in the checkout, so each plug-in gets its own checkout here.
    runs = []
    for mode in ("crash", "not-json", "bad-schema", "ok"):
        runs += run_plugins(runner, checkout(data_dir, mode), [manifest(name=mode)])

    assert [(r.plugin, r.status, r.reason) for r in runs] == [
        ("crash", RunStatus.FAILED, Reason.EXIT_CODE),
        ("not-json", RunStatus.FAILED, Reason.INVALID_SARIF),
        ("bad-schema", RunStatus.FAILED, Reason.INVALID_SARIF),
        ("ok", RunStatus.SUCCEEDED, None),
    ]
    assert runs[0].exit_code == 2
    assert "crashing on purpose" in log_text(data_dir, runs[0])
    assert "not JSON" in log_text(data_dir, runs[1])
    assert "fails the SARIF 2.1.0 schema" in log_text(data_dir, runs[2])
    assert scan_status(runs) == "partial"


def test_missing_output_and_nothing_scanned(client, data_dir):
    runner = make_runner(client, data_dir)
    cases = {
        "no-sarif": (RunStatus.FAILED, Reason.MISSING_SARIF),
        "no-scan-info": (RunStatus.FAILED, Reason.MISSING_SARIF),
        "zero": (RunStatus.FAILED, Reason.NOTHING_SCANNED),
        "nothing": (RunStatus.FAILED, Reason.NOTHING_SCANNED),
    }
    for mode, expected in cases.items():
        run = run_one(runner, checkout(data_dir, mode), manifest())
        assert (run.status, run.reason) == expected, mode


class Listener:
    """Counts the TCP connections that reach a port on this machine."""

    def __init__(self) -> None:
        # Docker Desktop sends host.docker.internal to the host's loopback. On Linux, containers
        # reach the host through the bridge, so the listener has to accept on every interface.
        host = "0.0.0.0" if sys.platform.startswith("linux") else "127.0.0.1"
        self.server = socket.create_server((host, 0))
        self.server.settimeout(0.2)
        self.port = self.server.getsockname()[1]
        self.connections = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self.server.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self.connections += 1
            connection.close()

    def close(self) -> None:
        self._stop.set()
        self._thread.join()
        self.server.close()


def test_a_plugin_cannot_reach_the_network(client, data_dir):
    listener = Listener()
    try:
        url = f"http://host.docker.internal:{listener.port}/"
        scan = checkout(data_dir, "network", targets=f"{url}\nhttp://1.1.1.1/\n")
        run = run_one(make_runner(client, data_dir), scan, manifest())

        assert (run.status, run.reason, run.exit_code) == (
            RunStatus.FAILED,
            Reason.EXIT_CODE,
            1,
        )
        log = log_text(data_dir, run)
        assert f"could not reach {url}" in log
        assert "reached" not in log.replace("could not reach", "")
        time.sleep(0.5)
        assert listener.connections == 0

        # The same request from a container with a network does arrive, so the listener works.
        try:
            client.containers.run(
                "busybox:1.37.0",
                ["wget", "-q", "-T", "3", "-O", "/dev/null", url],
                extra_hosts={"host.docker.internal": "host-gateway"},
                remove=True,
            )
        except docker.errors.ContainerError:
            pass  # the listener closes the connection without an HTTP answer
        time.sleep(0.5)
        if listener.connections == 0:
            pytest.skip("containers on this machine can't reach the host even with a network")
    finally:
        listener.close()


def test_out_of_memory(client, data_dir):
    scan = checkout(data_dir, "oom")
    run = run_one(make_runner(client, data_dir, memory="16m"), scan, manifest())
    assert (run.status, run.reason) == (RunStatus.FAILED, Reason.OUT_OF_MEMORY)
    assert containers_of(client, run) == []


def test_missing_image_is_a_runner_error(client, data_dir):
    scan = checkout(data_dir, "ok")
    plugin = manifest(image="sieve-plugin-does-not-exist:0.0.0")
    run = run_one(make_runner(client, data_dir), scan, plugin)
    assert (run.status, run.reason) == (RunStatus.FAILED, Reason.RUNNER_ERROR)
    assert "build it first" in log_text(data_dir, run)


@pytest.fixture
def build_network(client):
    network = client.networks.create(f"sieve-test-build-{uuid.uuid4().hex[:8]}", internal=True)
    yield network.name
    network.remove()


def test_build_step(client, data_dir, build_network):
    runner = make_runner(client, data_dir, build_network=build_network)
    plugin = manifest(build=BuildStep(image=IMAGE))

    scan = checkout(data_dir, "build")
    try:
        run = run_one(runner, scan, plugin)
        assert run.status is RunStatus.SUCCEEDED, log_text(data_dir, run)
        log = log_text(data_dir, run)
        assert log.index("--- build step") < log.index("build done") < log.index("--- scan step")
        assert (data_dir / "runs" / run.run_id / "build" / "built").is_file()

        failing = checkout(data_dir, "build-fail")
        run = run_one(runner, failing, plugin)
        assert (run.status, run.reason) == (RunStatus.FAILED, Reason.BUILD_FAILED)
        assert "the build broke" in log_text(data_dir, run)
    finally:
        for target in (scan, locals().get("failing")):
            if target is not None:
                try:
                    client.volumes.get(maven_cache_volume(target.repo_url)).remove()
                except docker.errors.NotFound:
                    pass


def test_remove_leftovers(client, data_dir):
    scan_id = str(uuid.uuid4())
    client.containers.create(
        "busybox:1.37.0", ["sleep", "300"], labels={"sieve.scan_id": scan_id}
    ).start()
    make_runner(client, data_dir).remove_leftovers(scan_id)
    assert client.containers.list(all=True, filters={"label": f"sieve.scan_id={scan_id}"}) == []
