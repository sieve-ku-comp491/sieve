"""The container engine interface. The runner's tests use a fake engine, the worker uses Docker."""

from dataclasses import dataclass, field
from typing import Protocol


class EngineError(Exception):
    """The engine can't be reached, or the image is missing."""


@dataclass(frozen=True)
class Mount:
    """A part of the data volume, a named volume, or (for tests and local runs) a host folder.

    With `volume` and `subpath`, the container gets that folder of the named volume, which needs
    Docker Engine 26 or later. With only `volume`, it gets the whole volume. With `host_path`, it
    gets a folder of the machine that runs Docker.
    """

    target: str
    read_only: bool
    volume: str | None = None
    subpath: str | None = None
    host_path: str | None = None

    def __post_init__(self) -> None:
        if (self.volume is None) == (self.host_path is None):
            raise ValueError("a mount needs either a volume or a host path")


@dataclass(frozen=True)
class ContainerSpec:
    """Every flag the runner sets on a container, so the tests can check them without Docker."""

    image: str
    network: str
    user: str
    mounts: tuple[Mount, ...]
    env: dict[str, str]
    labels: dict[str, str]
    read_only: bool = True
    tmpfs: tuple[str, ...] = ("/tmp",)
    cap_drop: tuple[str, ...] = ("ALL",)
    no_new_privileges: bool = True
    memory: str = "4g"
    cpus: float = 2.0
    pids_limit: int = 512


@dataclass(frozen=True)
class ContainerResult:
    """How a container ended. `exit_code` is None when it timed out or never started."""

    exit_code: int | None
    timed_out: bool = False
    out_of_memory: bool = False
    start_failed: bool = False
    log: str = field(default="", repr=False)


class ContainerEngine(Protocol):
    def run(self, spec: ContainerSpec, timeout_seconds: float) -> ContainerResult:
        """Runs the container until it exits or the time is up, and removes it in every case."""
        ...

    def image_digest(self, image: str) -> str:
        """The ID of a local image. Raises EngineError when it isn't there."""
        ...

    def remove_labeled(self, label: str, value: str) -> None:
        """Removes every container, running or not, that has this label value."""
        ...

    def network_is_internal(self, name: str) -> bool:
        """Whether the network has no route out. Raises EngineError when it doesn't exist."""
        ...
