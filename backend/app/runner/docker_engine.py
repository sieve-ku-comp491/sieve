"""Runs plug-in containers on the host's Docker Engine through the Docker SDK.

The worker reaches the engine through the socket in DOCKER_SOCKET (docs/architecture.md). Without
that setting, the SDK's own defaults apply, which also covers Docker Desktop on Windows.
"""

import os
import time
from contextlib import suppress

import docker
import docker.errors
import docker.types
import requests.exceptions

from app.runner.engine import ContainerEngine, ContainerResult, ContainerSpec, EngineError, Mount

MAX_LOG_BYTES = 5 * 1024 * 1024


class DockerEngine(ContainerEngine):
    def __init__(self, client: docker.DockerClient, max_log_bytes: int = MAX_LOG_BYTES):
        self._client = client
        self._max_log_bytes = max_log_bytes

    @classmethod
    def from_env(cls) -> "DockerEngine":
        socket = os.environ.get("DOCKER_SOCKET", "").strip()
        try:
            if socket:
                client = docker.DockerClient(base_url=f"unix://{socket}")
            else:
                client = docker.from_env()
        except docker.errors.DockerException as error:
            raise EngineError(f"can't reach the Docker Engine: {error}") from None
        return cls(client)

    def image_digest(self, image: str) -> str:
        try:
            return self._client.images.get(image).id
        except docker.errors.ImageNotFound:
            raise EngineError(f"the image {image} is not on this machine, build it first") from None
        except (docker.errors.DockerException, requests.exceptions.RequestException) as error:
            raise EngineError(f"can't reach the Docker Engine: {error}") from None

    def network_is_internal(self, name: str) -> bool:
        try:
            network = self._client.networks.get(name)
        except docker.errors.NotFound:
            raise EngineError(f"the network {name} doesn't exist") from None
        except (docker.errors.DockerException, requests.exceptions.RequestException) as error:
            raise EngineError(f"can't reach the Docker Engine: {error}") from None
        return bool(network.attrs.get("Internal")) and network.attrs.get("Driver") == "bridge"

    def remove_labeled(self, label: str, value: str) -> None:
        containers = self._client.containers.list(all=True, filters={"label": f"{label}={value}"})
        for container in containers:
            with suppress(docker.errors.NotFound):
                container.remove(force=True)

    def run(self, spec: ContainerSpec, timeout_seconds: float) -> ContainerResult:
        try:
            container = self._client.containers.create(**create_arguments(spec))
        except (docker.errors.DockerException, requests.exceptions.RequestException) as error:
            return ContainerResult(
                None, start_failed=True, log=f"can't create the container: {error}"
            )
        try:
            try:
                container.start()
            except (docker.errors.DockerException, requests.exceptions.RequestException) as error:
                return ContainerResult(
                    None, start_failed=True, log=f"can't start the container: {error}"
                )

            started = time.monotonic()
            try:
                exit_code = container.wait(timeout=max(timeout_seconds, 1))["StatusCode"]
                timed_out = False
            except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
                # The SDK raises one of these when the wait itself times out. A connection error
                # long before the limit means the engine went away, which is not a timeout.
                if time.monotonic() - started < timeout_seconds - 1:
                    raise EngineError("lost the connection to the Docker Engine") from None
                exit_code, timed_out = None, True
                with suppress(docker.errors.DockerException):
                    container.kill()

            container.reload()
            out_of_memory = bool(container.attrs["State"].get("OOMKilled")) and not timed_out
            return ContainerResult(
                exit_code=exit_code,
                timed_out=timed_out,
                out_of_memory=out_of_memory,
                log=self._read_log(container),
            )
        finally:
            with suppress(docker.errors.DockerException, requests.exceptions.RequestException):
                container.remove(force=True)

    def _read_log(self, container) -> str:
        """The container's output and errors, cut at max_log_bytes."""
        chunks: list[bytes] = []
        size = 0
        for chunk in container.logs(stdout=True, stderr=True, stream=True, follow=False):
            chunks.append(chunk)
            size += len(chunk)
            if size >= self._max_log_bytes:
                break
        text = b"".join(chunks)[: self._max_log_bytes].decode("utf-8", errors="replace")
        if size >= self._max_log_bytes:
            text += f"\n[output cut at {self._max_log_bytes} bytes]\n"
        return text


def create_arguments(spec: ContainerSpec) -> dict:
    """The Docker SDK arguments for a spec: the docker run flags in docs/interfaces.md."""
    return {
        "image": spec.image,
        "network_mode": spec.network,
        "user": spec.user,
        "read_only": spec.read_only,
        "tmpfs": {path: "" for path in spec.tmpfs},
        "cap_drop": list(spec.cap_drop),
        "security_opt": ["no-new-privileges"] if spec.no_new_privileges else [],
        "mem_limit": spec.memory,
        "nano_cpus": int(spec.cpus * 1_000_000_000),
        "pids_limit": spec.pids_limit,
        "environment": dict(spec.env),
        "labels": dict(spec.labels),
        "mounts": [docker_mount(mount) for mount in spec.mounts],
        "detach": True,
    }


def docker_mount(mount: Mount) -> docker.types.Mount:
    if mount.host_path is not None:
        return docker.types.Mount(
            mount.target, mount.host_path, type="bind", read_only=mount.read_only
        )
    # A subpath of the data volume must not get the image's files copied into it. A whole
    # volume, the Maven cache, gets the owner of the image's folder the first time.
    return docker.types.Mount(
        mount.target,
        mount.volume,
        type="volume",
        read_only=mount.read_only,
        subpath=mount.subpath,
        no_copy=mount.subpath is not None,
    )
