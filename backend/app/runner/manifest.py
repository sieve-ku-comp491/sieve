"""Plug-in manifests: what the runner needs to know to run one analyzer (docs/interfaces.md)."""

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from app.runner.languages import EXTENSIONS

DEFAULT_TIMEOUT_SECONDS = 600
MAX_TIMEOUT_SECONDS = 3600

NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")
TOP_LEVEL_KEYS = {"name", "image", "languages", "adapter", "timeout_seconds", "versions", "build"}


class ManifestError(ValueError):
    """A plugin.toml that doesn't follow the plug-in contract."""


@dataclass(frozen=True)
class BuildStep:
    image: str


@dataclass(frozen=True)
class PluginManifest:
    name: str
    image: str
    languages: tuple[str, ...]
    adapter: str
    tool_version: str
    rules_version: str
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    build: BuildStep | None = None

    @classmethod
    def load(cls, path: Path) -> "PluginManifest":
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as error:
            raise ManifestError(f"{path}: {error}") from None
        try:
            return cls.from_dict(data)
        except ManifestError as error:
            raise ManifestError(f"{path}: {error}") from None

    @classmethod
    def from_dict(cls, data: dict) -> "PluginManifest":
        unknown = set(data) - TOP_LEVEL_KEYS
        if unknown:
            raise ManifestError(f"unknown keys {sorted(unknown)}")

        name = _text(data, "name")
        if not NAME.match(name):
            raise ManifestError(f"name {name!r} must be lowercase letters, digits and hyphens")
        image = _text(data, "image")
        _check_image(image)

        languages = data.get("languages")
        if (
            not isinstance(languages, list)
            or not languages
            or not all(isinstance(language, str) and language for language in languages)
        ):
            raise ManifestError('languages must be a list of names, or ["*"]')
        if "*" in languages and len(languages) > 1:
            raise ManifestError('languages is either ["*"] or a list of languages, not both')
        unknown_languages = set(languages) - set(EXTENSIONS) - {"*"}
        if unknown_languages:
            raise ManifestError(
                f"unknown languages {sorted(unknown_languages)}, known are {sorted(EXTENSIONS)}"
            )

        timeout = data.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
        if (
            not isinstance(timeout, int)
            or isinstance(timeout, bool)
            or not 1 <= timeout <= MAX_TIMEOUT_SECONDS
        ):
            raise ManifestError(f"timeout_seconds must be from 1 to {MAX_TIMEOUT_SECONDS}")

        versions = data.get("versions")
        if not isinstance(versions, dict) or set(versions) != {"tool", "rules"}:
            raise ManifestError("[versions] must have exactly tool and rules")

        build = None
        if "build" in data:
            if not isinstance(data["build"], dict) or set(data["build"]) != {"image"}:
                raise ManifestError("[build] must have exactly image")
            build_image = _text(data["build"], "image")
            _check_image(build_image)
            build = BuildStep(image=build_image)

        return cls(
            name=name,
            image=image,
            languages=tuple(languages),
            adapter=_text(data, "adapter"),
            tool_version=_text(versions, "tool"),
            rules_version=_text(versions, "rules"),
            timeout_seconds=timeout,
            build=build,
        )

    def scans_every_file(self) -> bool:
        return self.languages == ("*",)


class PluginRegistry:
    """Every plug-in in the plugins directory, one subdirectory with a plugin.toml each."""

    def __init__(self, manifests: list[PluginManifest]):
        self._manifests: dict[str, PluginManifest] = {}
        for manifest in manifests:
            if manifest.name in self._manifests:
                raise ManifestError(f"two plug-ins are named {manifest.name}")
            self._manifests[manifest.name] = manifest

    @classmethod
    def load(cls, plugins_dir: Path) -> "PluginRegistry":
        paths = sorted(plugins_dir.glob("*/plugin.toml"))
        return cls([PluginManifest.load(path) for path in paths])

    def get(self, name: str) -> PluginManifest:
        return self._manifests[name]

    def all(self) -> list[PluginManifest]:
        return list(self._manifests.values())

    def for_languages(self, languages: set[str]) -> list[PluginManifest]:
        """The plug-ins for at least one of these languages, and those that scan every file."""
        return [
            manifest
            for manifest in self._manifests.values()
            if manifest.scans_every_file() or languages & set(manifest.languages)
        ]


def _text(data: dict, key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ManifestError(f"{key} must be a non-empty string")
    return value


def _check_image(image: str) -> None:
    """The tag carries the tool and rules versions, so an image without one isn't allowed."""
    if "@sha256:" in image:
        return
    last = image.rsplit("/", 1)[-1]
    if ":" not in last or last.endswith(":latest"):
        raise ManifestError(f"image {image} needs a version tag other than latest")
