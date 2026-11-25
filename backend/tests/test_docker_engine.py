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
