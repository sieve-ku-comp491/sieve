"""The runner against a real Docker Engine, with the small test plug-in in tests/plugin_fixture.

Skipped when Docker isn't running. CI's Ubuntu runners have Docker, so these run there.
"""

import ipaddress
import os
import random
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
MAVEN_PROXY_DIR = Path(__file__).resolve().parents[2] / "maven-proxy"
MAVEN_PROXY_IMAGE = "sieve-test-maven-proxy:1"


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


def control_failed(message: str) -> None:
    """A positive control got nothing. Without it the test proves nothing, so on Linux and in CI,
    where the control works, the test fails. Elsewhere, such as a machine whose firewall stops
    containers from reaching the host, it is skipped."""
    if sys.platform.startswith("linux") or os.environ.get("CI"):
        pytest.fail(message)
    pytest.skip(message)


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
        # First the same request from a container with a network, which must arrive, so that a
        # listener that gets nothing can't pass the check below.
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
        reached = listener.connections
        if reached == 0:
            control_failed("a container with a network didn't reach the listener on the host")

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
        assert listener.connections == reached
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


def create_build_network(client):
    """An internal network with no host address on its bridge, like sieve-build in
    docker-compose.yml."""
    return client.networks.create(
        f"sieve-test-build-{uuid.uuid4().hex[:8]}",
        internal=True,
        options={"com.docker.network.bridge.inhibit_ipv4": "true"},
    )


@pytest.fixture
def build_network(client):
    network = create_build_network(client)
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


def test_a_build_network_with_a_host_address_is_refused(client, data_dir):
    network = client.networks.create(f"sieve-test-build-{uuid.uuid4().hex[:8]}", internal=True)
    try:
        runner = make_runner(client, data_dir, build_network=network.name)
        run = run_one(runner, checkout(data_dir, "build"), manifest(build=BuildStep(image=IMAGE)))
    finally:
        network.remove()
    assert (run.status, run.reason) == (RunStatus.FAILED, Reason.RUNNER_ERROR)
    assert "not an internal bridge network with no host address" in log_text(data_dir, run)
    assert containers_of(client, run) == []


@pytest.fixture(scope="module")
def maven_proxy(client):
    """maven-proxy as Compose starts it: on an internal build network, where build containers
    reach it as maven-proxy, and on an ordinary network that has a route out."""
    image, _ = client.images.build(path=str(MAVEN_PROXY_DIR), tag=MAVEN_PROXY_IMAGE, rm=True)
    suffix = uuid.uuid4().hex[:8]
    build = create_build_network(client)
    egress = client.networks.create(f"sieve-test-egress-{suffix}")
    proxy = client.containers.create(
        image.id,
        name=f"sieve-test-maven-proxy-{suffix}",
        network=egress.name,
        read_only=True,
        tmpfs={"/tmp": "", "/var/log/squid": "", "/var/spool/squid": ""},
        cap_drop=["ALL"],
        security_opt=["no-new-privileges"],
    )
    try:
        build.connect(proxy, aliases=["maven-proxy"])
        proxy.start()
        deadline = time.monotonic() + 30
        while b"Accepting HTTP Socket connections" not in proxy.logs():
            if time.monotonic() > deadline:
                pytest.fail(f"maven-proxy didn't start:\n{proxy.logs().decode()}")
            time.sleep(0.2)
        yield build.name
    finally:
        proxy.remove(force=True, v=True)
        build.remove()
        egress.remove()


def network_answers(client, data_dir: Path, build_network: str, targets: list[str]) -> dict:
    """Runs the test plug-in's build step on the build network. It tries each target and
    writes what it got: "resolved", "connected", "failed", or the proxy's HTTP status."""
    scan = checkout(data_dir, "build-network", targets="\n".join(targets) + "\n")
    runner = make_runner(client, data_dir, build_network=build_network)
    try:
        run = run_one(runner, scan, manifest(build=BuildStep(image=IMAGE)))
    finally:
        try:
            client.volumes.get(maven_cache_volume(scan.repo_url)).remove()
        except docker.errors.NotFound:
            pass
    assert run.status is RunStatus.SUCCEEDED, log_text(data_dir, run)
    lines = (data_dir / "runs" / run.run_id / "build" / "network.txt").read_text().splitlines()
    return {line.rsplit(" ", 1)[0]: line.rsplit(" ", 1)[1] for line in lines}


def test_a_build_step_reaches_no_host_but_maven_central(client, data_dir, maven_proxy):
    listener = Listener()
    try:
        host = f"host.docker.internal:{listener.port}"
        answers = network_answers(
            client,
            data_dir,
            maven_proxy,
            [
                "dns example.com",
                "dns repo.maven.apache.org",
                "direct 1.1.1.1:443",
                "connect example.com:443",
                f"connect {host}",
                "connect 1.1.1.1:443",
                "connect repo.maven.apache.org:80",
                "connect repo.maven.apache.org:22",
                "connect repo.maven.apache.org.example.com:443",
                "get http://repo.maven.apache.org/maven2/",
            ],
        )
        time.sleep(0.5)
        assert listener.connections == 0
    finally:
        listener.close()

    # The build network has no DNS for outside names and no route out.
    assert answers["dns example.com"] == "failed"
    assert answers["dns repo.maven.apache.org"] == "failed"
    assert answers["direct 1.1.1.1:443"] == "failed"
    # The proxy refuses every other host, every other port and plain HTTP before it connects.
    assert answers["connect example.com:443"] == "403"
    assert answers[f"connect {host}"] == "403"
    assert answers["connect 1.1.1.1:443"] == "403"
    assert answers["connect repo.maven.apache.org:80"] == "403"
    assert answers["connect repo.maven.apache.org:22"] == "403"
    assert answers["connect repo.maven.apache.org.example.com:443"] == "403"
    assert answers["get http://repo.maven.apache.org/maven2/"] == "403"


class HostListener:
    """Counts the TCP connections to a port in the Docker host's own network namespace, from a
    busybox container on the host network. On Linux that is this machine. Docker Desktop runs the
    engine in a VM, which owns the bridges' gateway addresses, so Listener wouldn't see those.

    The port is picked at random, and something on the host may already listen on it. nc then
    stops at once with "nc: bind: Address already in use", so the listener tries another port.
    """

    ATTEMPTS = 5

    def __init__(self, client) -> None:
        failures = []
        for _ in range(self.ATTEMPTS):
            self.port = random.randint(20000, 59999)
            self.container = client.containers.run(
                "busybox:1.37.0",
                ["nc", "-lk", "-p", str(self.port), "-e", "sh", "-c", "echo hit >> /tmp/hits"],
                name=f"sieve-test-host-listener-{uuid.uuid4().hex[:8]}",
                network_mode="host",
                detach=True,
            )
            failure = self._wait_until_listening()
            if failure is None:
                return
            failures.append(f"port {self.port}: {failure}")
            self.close()
        pytest.fail("the listener on the host network didn't start:\n" + "\n".join(failures))

    def _wait_until_listening(self) -> str | None:
        """None once nc listens, or else why it doesn't."""
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            self.container.reload()
            if self.container.status != "running":
                state = self.container.attrs["State"]
                output = self.container.logs().decode().strip() or "no output"
                return f"{state['Status']} with exit code {state['ExitCode']}: {output}"
            try:
                if f":{self.port} " in self._run("netstat -ltn"):
                    return None
            except docker.errors.APIError:
                pass  # nc stopped after the reload, and the next round reports it
            time.sleep(0.2)
        return "not listening after 10 s"

    def _run(self, command: str) -> str:
        return self.container.exec_run(["sh", "-c", command]).output.decode()

    def connections(self) -> int:
        time.sleep(0.5)
        return int(self._run("cat /tmp/hits 2>/dev/null | wc -l"))

    def close(self) -> None:
        self.container.remove(force=True, v=True)


def test_a_build_step_cannot_reach_the_docker_host(client, data_dir, build_network):
    listener = HostListener(client)
    # An internal network as `docker network create --internal` makes it, with the host's address
    # on its bridge.
    plain = client.networks.create(f"sieve-test-plain-{uuid.uuid4().hex[:8]}", internal=True)
    try:
        plain.reload()
        plain_gateway = plain.attrs["IPAM"]["Config"][0]["Gateway"]

        # First a container on the plain internal network reaches the listener through the
        # gateway, so the listener works and the missing host address is what stops the build
        # step below.
        try:
            client.containers.run(
                "busybox:1.37.0",
                ["nc", "-w", "3", plain_gateway, str(listener.port)],
                network=plain.name,
                remove=True,
            )
        except docker.errors.ContainerError:
            pass
        reached = listener.connections()
        if reached == 0:
            control_failed("a container didn't reach the host through a gateway address")

        # On a network without inhibit_ipv4, Docker gives the bridge the subnet's first address.
        subnet = client.networks.get(build_network).attrs["IPAM"]["Config"][0]["Subnet"]
        build_gateway = ipaddress.ip_network(subnet)[1]
        targets = [
            f"direct {build_gateway}:{listener.port}",
            f"direct {plain_gateway}:{listener.port}",
        ]
        answers = network_answers(client, data_dir, build_network, [*targets, "ipv6 addresses"])
        assert listener.connections() == reached
        # No IPv6 address either, so no link-local route to the bridge, which has one.
        assert answers == {target: "failed" for target in targets} | {"ipv6 addresses": "0"}
    finally:
        listener.close()
        plain.remove()


def test_a_build_step_reaches_maven_central_through_the_proxy(client, data_dir, maven_proxy):
    try:
        socket.getaddrinfo("repo.maven.apache.org", 443)
    except OSError:
        pytest.skip("this machine can't resolve repo.maven.apache.org")
    answers = network_answers(client, data_dir, maven_proxy, ["connect repo.maven.apache.org:443"])
    assert answers["connect repo.maven.apache.org:443"] == "200"


def test_remove_leftovers(client, data_dir):
    scan_id = str(uuid.uuid4())
    client.containers.create(
        "busybox:1.37.0", ["sleep", "300"], labels={"sieve.scan_id": scan_id}
    ).start()
    make_runner(client, data_dir).remove_leftovers(scan_id)
    assert client.containers.list(all=True, filters={"label": f"sieve.scan_id={scan_id}"}) == []
