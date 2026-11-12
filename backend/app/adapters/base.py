"""The SARIF mapping that is the same for every tool (docs/finding-format.md, "How the adapters
map SARIF"). A tool's adapter overrides only what its tool does differently."""

import copy
import re
from pathlib import PurePosixPath
from typing import Any, Protocol
from urllib.parse import unquote, urljoin, urlsplit

from app.adapters.finding import SEVERITIES, AdapterResult, Finding, FlowStep, Location
from app.adapters.fingerprint import Fingerprinter
from app.checkout import CheckoutReader
from app.runner.languages import EXTENSIONS
from app.runner.runner import PluginRun

# Where every plug-in container mounts the checkout (docs/interfaces.md).
CHECKOUT_MOUNT = "/src/"

CWE_TAG = re.compile(r"^CWE-0*(\d+)\b", re.IGNORECASE)
CODEQL_CWE_TAG = re.compile(r"^external/cwe/cwe-0*(\d+)$", re.IGNORECASE)
CWE_ID = re.compile(r"^(?:CWE-)?0*(\d+)$", re.IGNORECASE)
MESSAGE_ARGUMENT = re.compile(r"\{(\d+)\}")

LANGUAGES = {suffix: language for language, suffixes in EXTENSIONS.items() for suffix in suffixes}
LANGUAGES |= {".html": "html", ".htm": "html"}


class SarifAdapter(Protocol):
    tool: str

    def to_findings(
        self, sarif: dict[str, Any], run: PluginRun, reader: CheckoutReader
    ) -> AdapterResult: ...


class BaseSarifAdapter:
    tool = ""

    def __init__(self, fingerprinter: Fingerprinter | None = None):
        self.fingerprinter = fingerprinter or Fingerprinter()

    def to_findings(
        self, sarif: dict[str, Any], run: PluginRun, reader: CheckoutReader
    ) -> AdapterResult:
        """The findings of one plug-in run. The SARIF file has passed SarifValidator."""
        result = AdapterResult()
        for sarif_run in sarif.get("runs") or []:
            base_ids = sarif_run.get("originalUriBaseIds") or {}
            for sarif_result in sarif_run.get("results") or []:
                finding = self._finding(sarif_run, sarif_result, base_ids, run, reader, result)
                if finding is not None:
                    result.findings.append(finding)

        file_lines = self._read_files(result.findings, reader)
        self.fingerprinter.assign(result.findings, file_lines)
        return result

    # The parts a tool's adapter can override ---------------------------------------------

    def find_rule(self, sarif_run: dict, result: dict) -> dict:
        """The result's rule: in the extension that result.rule.toolComponent names, else in
        the driver; by index if there is one, else by ID."""
        tool = sarif_run.get("tool") or {}
        component = tool.get("driver") or {}
        reference = result.get("rule") or {}
        target = reference.get("toolComponent")
        if target:
            extensions = tool.get("extensions") or []
            index = target.get("index")
            if isinstance(index, int) and 0 <= index < len(extensions):
                component = extensions[index]
            else:
                named = [e for e in extensions if e.get("name") == target.get("name")]
                if named:
                    component = named[0]
        rules = component.get("rules") or []
        index = result.get("ruleIndex", reference.get("index"))
        if isinstance(index, int) and 0 <= index < len(rules):
            return rules[index]
        rule_id = result.get("ruleId") or reference.get("id")
        for rule in rules:
            if rule.get("id") == rule_id:
                return rule
        return {}

    def normalize_path(self, uri: str, base_id: str | None, base_ids: dict) -> str | None:
        """A path relative to the repository root with / separators, or None if the URI
        doesn't name a path inside the checkout."""
        resolved = self._resolve_base(uri, base_id, base_ids, depth=0)
        if resolved is None:
            return None
        parts = urlsplit(resolved)
        if parts.scheme == "file" or (parts.scheme == "" and not parts.netloc):
            path = unquote(parts.path)
        else:
            return None
        if path.startswith(CHECKOUT_MOUNT):
            path = path[len(CHECKOUT_MOUNT) :]
        pure = PurePosixPath(path)
        if not path or pure.is_absolute() or ".." in pure.parts:
            return None
        return pure.as_posix()

    def cwes(self, rule: dict, result: dict) -> list[str]:
        """CWE IDs from the rule's tags (Semgrep's and CodeQL's forms) and from relationships
        and taxa that point to the CWE taxonomy, as CWE-<number>, sorted, without duplicates."""
        numbers: set[int] = set()
        for tag in (rule.get("properties") or {}).get("tags") or []:
            if isinstance(tag, str):
                match = CWE_TAG.match(tag) or CODEQL_CWE_TAG.match(tag)
                if match:
                    numbers.add(int(match.group(1)))
        targets = [r.get("target") or {} for r in rule.get("relationships") or []]
        targets += result.get("taxa") or []
        for target in targets:
            component = (target.get("toolComponent") or {}).get("name", "")
            match = CWE_ID.match(str(target.get("id", "")))
            if component.upper() == "CWE" and match:
                numbers.add(int(match.group(1)))
        return [f"CWE-{number}" for number in sorted(numbers)]

    def tool_severity(self, rule: dict, result: dict) -> str:
        level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
        return level if level in SEVERITIES else "warning"

    def tool_score(self, rule: dict) -> float | None:
        value = (rule.get("properties") or {}).get("security-severity")
        try:
            score = float(value)
        except TypeError, ValueError:
            return None
        return score if 0.0 <= score <= 10.0 else None

    def confidence(self, rule: dict, result: dict) -> str | None:
        """Tools that don't report a confidence leave it empty."""
        return None

    def tool_fingerprint(self, result: dict) -> str | None:
        """Kept only by adapters that know their tool's fingerprint is stable."""
        return None

    def keep(self, result: dict) -> bool:
        return result.get("kind", "fail") == "fail"

    def mask(self, lines: list[str], location: Location) -> list[str]:
        """The file's lines with anything that must not be hashed or stored replaced. Only the
        Gitleaks adapter masks; here the lines stay as they are."""
        return lines

    masks_snippets = False

    # The shared mapping -------------------------------------------------------------------

    def _finding(
        self,
        sarif_run: dict,
        result: dict,
        base_ids: dict,
        run: PluginRun,
        reader: CheckoutReader,
        out: AdapterResult,
    ) -> Finding | None:
        if not self.keep(result):
            out.drop(f"kind_{result.get('kind')}")
            return None
        rule = self.find_rule(sarif_run, result)
        rule_id = result.get("ruleId") or (result.get("rule") or {}).get("id") or rule.get("id")
        if not rule_id:
            out.drop("no_rule", "dropped a result without a rule ID")
            return None
        locations = result.get("locations") or []
        physical = (locations[0].get("physicalLocation") if locations else None) or {}
        location = self._location(physical, base_ids, reader)
        if isinstance(location, str):
            out.drop(location, f"dropped a {rule_id} result: {_reasons[location]}")
            return None

        related = []
        for item in result.get("relatedLocations") or []:
            mapped = self._location(item.get("physicalLocation") or {}, base_ids, reader)
            if isinstance(mapped, Location):
                related.append(mapped)
            else:
                out.warnings.append(f"left out a related location of a {rule_id} result")

        return Finding(
            scan_id=run.scan_id,
            run_id=run.run_id,
            tool=self.tool,
            tool_version=run.tool_version,
            rule_id=rule_id,
            rule_description=_text(rule.get("fullDescription"))
            or _text(rule.get("shortDescription")),
            rule_help_uri=rule.get("helpUri"),
            cwe=self.cwes(rule, result),
            message=_message(result, rule),
            tool_severity=self.tool_severity(rule, result),
            tool_score=self.tool_score(rule),
            tool_confidence=self.confidence(rule, result),
            location=location,
            related_locations=related,
            data_flow=self._data_flow(result, base_ids, reader, rule_id, out),
            suppressed=bool(result.get("suppressions")),
            tool_fingerprint=self.tool_fingerprint(result),
            language=LANGUAGES.get(PurePosixPath(location.file).suffix.lower(), "other"),
            raw=copy.deepcopy(result),
        )

    def _location(self, physical: dict, base_ids: dict, reader: CheckoutReader) -> Location | str:
        """A mapped location, or the reason it can't be mapped."""
        artifact = physical.get("artifactLocation") or {}
        uri = artifact.get("uri")
        if not uri:
            return "no_location"
        path = self.normalize_path(uri, artifact.get("uriBaseId"), base_ids)
        if path is None or not reader.is_file(path):
            return "path_outside_checkout"
        region = physical.get("region") or {}
        start = region.get("startLine")
        if not isinstance(start, int) or start < 1:
            return "no_line"
        end = region.get("endLine")
        end = end if isinstance(end, int) and end >= start else start
        return Location(
            file=path,
            start_line=start,
            end_line=end,
            start_column=region.get("startColumn"),
            end_column=region.get("endColumn"),
            snippet=_text(region.get("snippet")),
        )

    def _data_flow(
        self, result: dict, base_ids: dict, reader: CheckoutReader, rule_id: str, out
    ) -> list[FlowStep]:
        flows = result.get("codeFlows") or []
        threads = (flows[0].get("threadFlows") or []) if flows else []
        steps = []
        for item in (threads[0].get("locations") or []) if threads else []:
            location = item.get("location") or {}
            mapped = self._location(location.get("physicalLocation") or {}, base_ids, reader)
            if not isinstance(mapped, Location):
                out.warnings.append(f"left out a flow step of a {rule_id} result")
                continue
            message = _text(location.get("message"))
            steps.append(FlowStep(**vars(mapped), step=len(steps) + 1, message=message))
        return steps

    def _resolve_base(self, uri: str, base_id: str | None, base_ids: dict, depth: int):
        if not base_id or base_id not in base_ids:
            return uri
        if depth > 10:
            return None
        base = base_ids[base_id] or {}
        base_uri = base.get("uri")
        if not base_uri:
            return uri
        base_uri = self._resolve_base(base_uri, base.get("uriBaseId"), base_ids, depth + 1)
        return None if base_uri is None else urljoin(base_uri, uri)

    def _read_files(
        self, findings: list[Finding], reader: CheckoutReader
    ) -> dict[str, list[str] | None]:
        """Each flagged file read once and masked. When an adapter masks, the stored snippets
        come from the masked lines too, so a masked secret is never stored."""
        by_file: dict[str, list[Finding]] = {}
        for finding in findings:
            by_file.setdefault(finding.location.file, []).append(finding)
        file_lines: dict[str, list[str] | None] = {}
        for file, members in by_file.items():
            lines = reader.read_lines(file)
            if lines is not None:
                for finding in members:
                    lines = self.mask(lines, finding.location)
            file_lines[file] = lines
            if self.masks_snippets:
                for finding in members:
                    location = finding.location
                    flagged = (lines or [])[location.start_line - 1 : location.end_line]
                    location.snippet = "\n".join(flagged) if flagged else None
        return file_lines


_reasons = {
    "no_location": "it has no file",
    "path_outside_checkout": "its path is not a file inside the checkout",
    "no_line": "it has no start line",
}


def _text(message: Any) -> str | None:
    if isinstance(message, dict) and isinstance(message.get("text"), str):
        return message["text"]
    return None


def _message(result: dict, rule: dict) -> str:
    message = result.get("message") or {}
    if isinstance(message.get("text"), str):
        return message["text"]
    template = _text((rule.get("messageStrings") or {}).get(message.get("id"))) or ""
    arguments = message.get("arguments") or []

    def argument(match: re.Match) -> str:
        index = int(match.group(1))
        return str(arguments[index]) if index < len(arguments) else match.group(0)

    return MESSAGE_ARGUMENT.sub(argument, template)
