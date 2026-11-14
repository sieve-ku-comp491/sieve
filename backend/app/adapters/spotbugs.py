"""SpotBugs' SARIF output as findings, from the SpotBugs plug-in with Find Security Bugs.

SpotBugs writes each file path relative to the Java source folder it found the file in, such as
`org/owasp/webgoat/X.java`, with a `uriBaseId` whose entry in `originalUriBaseIds` is that
folder under /src. The shared mapping resolves those. When SpotBugs didn't find the file, it
writes the relative path with no base, and the adapter tries each source folder listed in
`originalUriBaseIds`, where the plug-in adds every folder the build step listed
(docs/finding-format.md, File paths, step 4).

SpotBugs' SARIF has no confidence and no fingerprint, so both stay empty. Its CWEs are
relationships to the CWE taxonomy, which the shared mapping reads.
"""

from typing import Any

from app.adapters.base import BaseSarifAdapter
from app.adapters.finding import AdapterResult
from app.checkout import CheckoutReader
from app.runner.runner import PluginRun


class SpotBugsAdapter(BaseSarifAdapter):
    tool = "spotbugs"

    def __init__(self, fingerprinter=None):
        super().__init__(fingerprinter)
        self._reader: CheckoutReader | None = None

    def to_findings(
        self, sarif: dict[str, Any], run: PluginRun, reader: CheckoutReader
    ) -> AdapterResult:
        self._reader = reader
        try:
            return super().to_findings(sarif, run, reader)
        finally:
            self._reader = None

    def normalize_path(self, uri: str, base_id: str | None, base_ids: dict) -> str | None:
        path = super().normalize_path(uri, base_id, base_ids)
        reader = self._reader
        if path is None or reader is None or reader.is_file(path):
            return path
        if base_id and base_id in base_ids:
            return path
        matches = {
            f"{root}/{path}"
            for root in self._source_folders(base_ids)
            if reader.is_file(f"{root}/{path}")
        }
        # A path that fits more than one folder could name either file, so it isn't guessed.
        return matches.pop() if len(matches) == 1 else path

    def _source_folders(self, base_ids: dict) -> set[str]:
        folders = set()
        for base in base_ids.values():
            if isinstance(base, dict) and isinstance(base.get("uri"), str):
                folder = super().normalize_path(base["uri"], base.get("uriBaseId"), base_ids)
                if folder and folder != ".":
                    folders.add(folder)
        return folders
