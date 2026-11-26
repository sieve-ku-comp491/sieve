"""DockerEngine with a stub Docker client, so these tests need no Docker."""

from types import SimpleNamespace

import docker.errors
import pytest

from app.runner import DockerEngine, EngineError

BUILD_NETWORK = {
    "Driver": "bridge",
    "Internal": True,
    "EnableIPv6": False,
    "Options": {"com.docker.network.bridge.inhibit_ipv4": "true"},
}


class StubNetworks:
    def __init__(self, attrs: dict | None) -> None:
        self.attrs = attrs

    def get(self, name: str) -> SimpleNamespace:
        if self.attrs is None:
            raise docker.errors.NotFound(f"network {name} not found")
        return SimpleNamespace(attrs=self.attrs)


def network_is_internal(attrs: dict | None) -> bool:
    client = SimpleNamespace(networks=StubNetworks(attrs))
    return DockerEngine(client).network_is_internal("sieve-build")


def test_the_build_network_as_compose_makes_it_is_accepted():
    assert network_is_internal(BUILD_NETWORK)


@pytest.mark.parametrize(
    "changes",
    [
        pytest.param({"Internal": False}, id="route out"),
        pytest.param({"Options": {}}, id="host address on the bridge"),
        pytest.param({"Options": None}, id="no options"),
        pytest.param(
            {"Options": {"com.docker.network.bridge.inhibit_ipv4": "false"}},
            id="inhibit_ipv4 false",
        ),
        pytest.param({"EnableIPv6": True}, id="ipv6"),
        pytest.param({"Driver": "macvlan"}, id="not a bridge"),
    ],
)
def test_a_network_that_can_reach_out_or_the_host_is_refused(changes):
    assert not network_is_internal(BUILD_NETWORK | changes)


def test_a_missing_network_is_an_engine_error():
    with pytest.raises(EngineError, match="the network sieve-build doesn't exist"):
        network_is_internal(None)


class StubContainer:
    """A container whose OOMKilled flag appears after a number of reloads, the way Docker sets it
    when containerd's OOM event arrives after the exit."""

    def __init__(self, reloads_until_flag: int | None) -> None:
        self.reloads_until_flag = reloads_until_flag
        self.reloads = 0
        self.attrs = {"State": {"OOMKilled": reloads_until_flag == 0}}

    def reload(self) -> None:
        self.reloads += 1
        if self.reloads_until_flag is not None and self.reloads >= self.reloads_until_flag:
            self.attrs["State"]["OOMKilled"] = True


def out_of_memory(container: StubContainer, exit_code: int, wait: float = 2.0) -> bool:
    engine = DockerEngine(SimpleNamespace(), oom_flag_wait_seconds=wait)
    return engine._out_of_memory(container, exit_code)


def test_a_failed_container_waits_for_a_late_oom_flag():
    container = StubContainer(reloads_until_flag=3)
    assert out_of_memory(container, exit_code=1)
    assert container.reloads == 3


def test_a_failed_container_without_the_flag_waits_only_so_long():
    container = StubContainer(reloads_until_flag=None)
    assert not out_of_memory(container, exit_code=137, wait=0.3)
    assert 1 <= container.reloads <= 4


@pytest.mark.parametrize("exit_code", [0, 3])
def test_a_finished_plugin_doesnt_wait(exit_code):
    late = StubContainer(reloads_until_flag=1)
    assert not out_of_memory(late, exit_code)
    assert late.reloads == 0
    assert out_of_memory(StubContainer(reloads_until_flag=0), exit_code)
