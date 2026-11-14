"""The SARIF mapping that is the same for every tool (docs/finding-format.md, "How the adapters
map SARIF"). A tool's adapter overrides only what its tool does differently.

The SARIF file comes from a plug-in that ran over code we don't control, so every value in it
is treated as untrusted: one result that can't be mapped is dropped with a warning and never
stops the rest of the run.
"""

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

# Bounded digit counts keep these linear and within int()'s limit on any input.
CWE_TAG = re.compile(r"^CWE-(\d{1,9})(?!\d)", re.IGNORECASE)
CODEQL_CWE_TAG = re.compile(r"^external/cwe/cwe-(\d{1,9})$", re.IGNORECASE)
CWE_ID = re.compile(r"^(?:CWE-)?(\d{1,9})$", re.IGNORECASE)
MESSAGE_PART = re.compile(r"\{\{|\}\}|\{(\d{1,9})\}")
URI_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")

MAX_LINE = 2**31 - 1
MAX_TEXT = 20_000
MAX_WARNING_ID = 200

LANGUAGES = {suffix: language for language, suffixes in EXTENSIONS.items() for suffix in suffixes}
LANGUAGES |= {".html": "html", ".htm": "html"}

DROP_REASONS = {
    "no_rule": "it has no rule ID",
    "no_location": "it has no file",
    "path_outside_checkout": "its path is not a file inside the checkout",
    "no_line": "it has no valid start line",
    "line_outside_file": "its start line is past the end of the file",
    "unreadable_result": "it couldn't be read",
}


class SarifAdapter(Protocol):
    tool: str

    def to_findings(
        self, sarif: dict[str, Any], run: PluginRun, reader: CheckoutReader
    ) -> AdapterResult: ...


class BaseSarifAdapter:
    tool = ""

    def __init__(self, fingerprinter: Fingerprinter | None = None):
        self.fingerprinter = fingerprinter or Fingerprinter()
        self._context: _RunContext | None = None

    def to_findings(
        self, sarif: dict[str, Any], run: PluginRun, reader: CheckoutReader
    ) -> AdapterResult:
        """The findings of one plug-in run. The SARIF file has passed SarifValidator."""
        out = AdapterResult()
        for sarif_run in sarif.get("runs") or []:
            self._context = context = _RunContext(sarif_run)
            for sarif_result in sarif_run.get("results") or []:
                # One result that can't be mapped must not stop the rest of the run.
                try:
                    finding = self._finding(context, _dict(sarif_result), run, reader, out)
                except Exception as error:
                    out.drop("unreadable_result", f"dropped a result: {_short(error)}")
                    continue
                if finding is not None:
                    out.findings.append(finding)

        file_lines = self._read_files(out, reader)
        self.fingerprinter.assign(out.findings, file_lines)
        return out

    # The parts a tool's adapter can override ---------------------------------------------

    def find_rule(self, sarif_run: dict, result: dict) -> dict:
        """The result's rule: in the extension that result.rule.toolComponent names, else in
        the driver; by index when the index and the ID agree, else by ID."""
        context = self._context
        if context is None or context.sarif_run is not sarif_run:
            context = _RunContext(sarif_run)
        return context.find_rule(result)

    def normalize_path(self, uri: str, base_id: str | None, base_ids: dict) -> str | None:
        """A path relative to the repository root with / separators, or None if the URI
        doesn't name a path inside the checkout.

        A URI without a scheme and without a known base is taken as a literal path, because
        tools such as Semgrep write raw file names there, with "#", "?" and "%" unencoded.
        Only file: URIs, and URIs built from an originalUriBaseIds base, are percent-decoded.
        """
        if not isinstance(uri, str) or "\x00" in uri:
            return None
        if not URI_SCHEME.match(uri) and not (base_id and base_id in base_ids):
            return _clean_path(uri)
        try:
            resolved = _resolve_base(uri, base_id, base_ids, depth=0)
            if resolved is None:
                return None
            parts = urlsplit(resolved)
        except ValueError:
            return None
        if parts.scheme == "file":
            if parts.netloc not in ("", "localhost"):
                return None
        elif parts.scheme or parts.netloc:
            return None
        return _clean_path(unquote(parts.path))

    def cwes(self, rule: dict, result: dict) -> list[str]:
        """CWE IDs from the rule's tags (Semgrep's and CodeQL's forms) and from relationships
        and taxa that point to the CWE taxonomy, as CWE-<number>, sorted, without duplicates."""
        # The cache keeps the rule itself next to its CWEs, so its id can't be reused.
        cache = self._context.rule_cwes if self._context is not None else {}
        cached = cache.get(id(rule))
        from_rule = cached[1] if cached is not None and cached[0] is rule else None
        if from_rule is None:
            from_rule = set()
            for tag in _dict(rule.get("properties")).get("tags") or []:
                if isinstance(tag, str):
                    match = CWE_TAG.match(tag) or CODEQL_CWE_TAG.match(tag)
                    if match:
                        from_rule.add(int(match.group(1)))
            targets = [_dict(_dict(r).get("target")) for r in rule.get("relationships") or []]
            from_rule |= _taxonomy_cwes(targets)
            cache[id(rule)] = (rule, from_rule)
        numbers = from_rule | _taxonomy_cwes([_dict(t) for t in result.get("taxa") or []])
        return [f"CWE-{number}" for number in sorted(numbers)]

    def tool_severity(self, rule: dict, result: dict) -> str:
        level = result.get("level") or _dict(rule.get("defaultConfiguration")).get("level")
        return level if level in SEVERITIES else "warning"

    def tool_score(self, rule: dict) -> float | None:
        value = _dict(rule.get("properties")).get("security-severity")
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

    def snippet(self, region: dict) -> str | None:
        """The tool's own snippet of a region. Without one, the snippet is read from the
        checkout."""
        return _clean_text(_text(region.get("snippet")))

    def keep(self, result: dict) -> bool:
        return result.get("kind", "fail") == "fail"

    def mask(self, lines: list[str], location: Location) -> list[str]:
        """The file's lines with anything that must not be hashed or stored replaced. Only the
        Gitleaks adapter masks; here the lines stay as they are."""
        return lines

    # The shared mapping -------------------------------------------------------------------

    @property
    def masks(self) -> bool:
        return type(self).mask is not BaseSarifAdapter.mask

    def _finding(
        self,
        context: "_RunContext",
        result: dict,
        run: PluginRun,
        reader: CheckoutReader,
        out: AdapterResult,
    ) -> Finding | None:
        if not self.keep(result):
            out.drop(f"kind_{_short(result.get('kind'))}")
            return None
        rule = self.find_rule(context.sarif_run, result)
        rule_id = result.get("ruleId") or _dict(result.get("rule")).get("id") or rule.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            out.drop("no_rule", "dropped a result without a rule ID")
            return None
        rule_id = _clean_text(rule_id)
        locations = result.get("locations") or []
        physical = _dict(_dict(locations[0]).get("physicalLocation")) if locations else {}
        location = self._location(physical, context.base_ids, reader)
        if isinstance(location, str):
            out.drop(location, f"dropped a {_short(rule_id)} result: {DROP_REASONS[location]}")
            return None

        related = []
        for item in result.get("relatedLocations") or []:
            physical_item = _dict(_dict(item).get("physicalLocation"))
            mapped = self._location(physical_item, context.base_ids, reader)
            if isinstance(mapped, Location):
                related.append(mapped)
            else:
                out.warn(f"left out a related location of a {_short(rule_id)} result")

        help_uri = rule.get("helpUri")
        return Finding(
            scan_id=run.scan_id,
            run_id=run.run_id,
            tool=self.tool,
            tool_version=run.tool_version,
            rule_id=rule_id,
            rule_description=_clean_text(
                _text(rule.get("fullDescription")) or _text(rule.get("shortDescription"))
            ),
            rule_help_uri=help_uri if _is_web_url(help_uri) else None,
            cwe=self.cwes(rule, result),
            message=_clean_text(_message(result, rule, context.global_messages)) or "",
            tool_severity=self.tool_severity(rule, result),
            tool_score=self.tool_score(rule),
            tool_confidence=self.confidence(rule, result),
            location=location,
            related_locations=related,
            data_flow=self._data_flow(result, context.base_ids, reader, rule_id, out),
            suppressed=_suppressed(result.get("suppressions")),
            tool_fingerprint=self.tool_fingerprint(result),
            language=LANGUAGES.get(PurePosixPath(location.file).suffix.lower(), "other"),
            raw=_clean_raw(copy.deepcopy(result)),
        )

    def _location(self, physical: dict, base_ids: dict, reader: CheckoutReader) -> Location | str:
        """A mapped location, or the reason it can't be mapped."""
        artifact = _dict(physical.get("artifactLocation"))
        uri = artifact.get("uri")
        if not uri or not isinstance(uri, str):
            return "no_location"
        path = self.normalize_path(uri, artifact.get("uriBaseId"), base_ids)
        if path is not None and not reader.is_file(path) and "%" in path:
            # A tool that does percent-encode a relative reference.
            decoded = _clean_path(unquote(path))
            if decoded is not None and reader.is_file(decoded):
                path = decoded
        if path is None or not reader.is_file(path):
            return "path_outside_checkout"
        region = _dict(physical.get("region"))
        start = region.get("startLine")
        if type(start) is not int or not 1 <= start <= MAX_LINE:
            return "no_line"
        end = region.get("endLine")
        end = end if type(end) is int and start <= end <= MAX_LINE else start
        return Location(
            file=path,
            start_line=start,
            end_line=end,
            start_column=_column(region.get("startColumn")),
            end_column=_column(region.get("endColumn")),
            snippet=self.snippet(region),
        )

    def _data_flow(
        self, result: dict, base_ids: dict, reader: CheckoutReader, rule_id: str, out
    ) -> list[FlowStep]:
        flows = result.get("codeFlows") or []
        threads = (_dict(flows[0]).get("threadFlows") or []) if flows else []
        items = (_dict(threads[0]).get("locations") or []) if threads else []
        steps = []
        for position, item in enumerate(items, start=1):
            location = _dict(_dict(item).get("location"))
            mapped = self._location(_dict(location.get("physicalLocation")), base_ids, reader)
            if not isinstance(mapped, Location):
                out.warn(f"left out flow step {position} of a {_short(rule_id)} result")
                continue
            message = _clean_text(_text(location.get("message")))
            # step keeps the position in the tool's path, so a left-out step shows as a gap.
            steps.append(FlowStep(**vars(mapped), step=position, message=message))
        return steps

    def _read_files(self, out: AdapterResult, reader: CheckoutReader) -> dict:
        """Each flagged file read once and masked. A finding whose start line is past the end
        of its file is dropped, and its end line is cut at the end of the file. A missing
        snippet is filled from the file, and when the adapter masks, every stored snippet is
        taken from the masked lines and the tool's own snippets are removed from raw."""
        by_file: dict[str, list[Finding]] = {}
        for finding in out.findings:
            by_file.setdefault(finding.location.file, []).append(finding)
        file_lines: dict[str, list[str] | None] = {}
        kept: set[int] = set()
        for file, members in by_file.items():
            lines = reader.read_lines(file)
            if lines is not None:
                for finding in members:
                    lines = self.mask(lines, finding.location)
            file_lines[file] = lines
            for finding in members:
                location = finding.location
                if lines is not None:
                    if location.start_line > len(lines):
                        out.drop(
                            "line_outside_file",
                            f"dropped a {_short(finding.rule_id)} result: "
                            f"{DROP_REASONS['line_outside_file']}",
                        )
                        continue
                    location.end_line = min(location.end_line, len(lines))
                else:
                    out.warn(
                        f"{_short(file)} couldn't be read, so a {_short(finding.rule_id)} "
                        "finding has no context hash"
                    )
                kept.add(id(finding))
        out.findings[:] = [f for f in out.findings if id(f) in kept]

        for finding in out.findings:
            for location in [finding.location, *finding.related_locations, *finding.data_flow]:
                lines = file_lines.get(location.file)
                if self.masks:
                    location.snippet = _snippet(lines, location)
                elif not location.snippet:
                    location.snippet = _snippet(lines, location) or location.snippet
            if self.masks:
                _remove_snippets(finding.raw)
        return file_lines


class _RunContext:
    """Per-run lookups, built once, so finding a rule costs the same for every result."""

    def __init__(self, sarif_run: dict | None):
        self.sarif_run = sarif_run
        sarif_run = _dict(sarif_run)
        tool = _dict(sarif_run.get("tool"))
        self.driver = _dict(tool.get("driver"))
        self.extensions = [_dict(e) for e in tool.get("extensions") or []]
        self.extensions_by_name: dict[str, dict] = {}
        self.components_by_guid: dict[str, dict] = {}
        for component in [self.driver, *self.extensions]:
            guid = component.get("guid")
            if isinstance(guid, str):
                self.components_by_guid.setdefault(guid.lower(), component)
        for extension in self.extensions:
            name = extension.get("name")
            if isinstance(name, str):
                self.extensions_by_name.setdefault(name, extension)
        self.rules_by_id: dict[int, dict[str, dict]] = {}
        self.rule_lists: dict[int, list[dict]] = {}
        self.rule_cwes: dict[int, tuple[dict, set[int]]] = {}
        self.base_ids = _dict(sarif_run.get("originalUriBaseIds"))
        self.global_messages = _dict(self.driver.get("globalMessageStrings"))

    def _component(self, result: dict) -> dict | None:
        target = _dict(_dict(result.get("rule")).get("toolComponent"))
        if not target:
            return self.driver
        index = target.get("index")
        if type(index) is int and 0 <= index < len(self.extensions):
            return self.extensions[index]
        name = target.get("name")
        if isinstance(name, str) and name in self.extensions_by_name:
            return self.extensions_by_name[name]
        if isinstance(name, str) and name == self.driver.get("name"):
            return self.driver
        guid = target.get("guid")
        if isinstance(guid, str) and guid.lower() in self.components_by_guid:
            return self.components_by_guid[guid.lower()]
        return None

    def find_rule(self, result: dict) -> dict:
        component = self._component(result)
        if component is None:
            return {}
        rules = self.rule_lists.get(id(component))
        if rules is None:
            rules = self.rule_lists[id(component)] = [
                _dict(r) for r in component.get("rules") or []
            ]
        reference = _dict(result.get("rule"))
        rule_id = result.get("ruleId") or reference.get("id")
        index = result.get("ruleIndex", reference.get("index"))
        if type(index) is int and 0 <= index < len(rules):
            if not isinstance(rule_id, str) or rules[index].get("id") == rule_id:
                return rules[index]
        if not isinstance(rule_id, str):
            return {}
        by_id = self.rules_by_id.get(id(component))
        if by_id is None:
            by_id = {}
            for rule in rules:
                if isinstance(rule.get("id"), str):
                    by_id.setdefault(rule["id"], rule)
            self.rules_by_id[id(component)] = by_id
        # A hierarchical ID such as "CA5350/md5" belongs to the rule "CA5350" (SARIF 3.27.5).
        return by_id.get(rule_id) or by_id.get(rule_id.split("/", 1)[0]) or {}


def _resolve_base(uri: str, base_id: str | None, base_ids: dict, depth: int) -> str | None:
    if not base_id or base_id not in base_ids:
        return uri
    if depth > 10:
        return None
    base = _dict(base_ids[base_id])
    base_uri = base.get("uri")
    if not isinstance(base_uri, str) or not base_uri:
        return uri
    base_uri = _resolve_base(base_uri, base.get("uriBaseId"), base_ids, depth + 1)
    return None if base_uri is None else urljoin(base_uri, uri)


def _clean_path(path: str) -> str | None:
    """A checkout-relative path, with the plug-ins' /src/ mount removed, or None. A path that
    isn't valid Unicode, such as a lone surrogate from the JSON, can't be stored or hashed."""
    if "\x00" in path:
        return None
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if path.startswith(CHECKOUT_MOUNT):
        path = path[len(CHECKOUT_MOUNT) :]
    pure = PurePosixPath(path)
    if not path or pure.is_absolute() or ".." in pure.parts:
        return None
    return pure.as_posix()


def _snippet(lines: list[str] | None, location: Location) -> str | None:
    if lines is None:
        return None
    flagged = lines[location.start_line - 1 : location.end_line]
    return _clean_text("\n".join(flagged)) if flagged else None


def _remove_snippets(value: Any) -> None:
    """Remove every region snippet from a raw SARIF result, for adapters that mask."""
    if isinstance(value, dict):
        region = value.get("region")
        if isinstance(region, dict):
            region.pop("snippet", None)
            region.pop("contextRegion", None)
        value.pop("contextRegion", None)
        for item in value.values():
            _remove_snippets(item)
    elif isinstance(value, list):
        for item in value:
            _remove_snippets(item)


def _taxonomy_cwes(targets: list[dict]) -> set[int]:
    """CWE numbers from relationship targets or taxa that point to the CWE taxonomy."""
    numbers = set()
    for target in targets:
        component = _dict(target.get("toolComponent")).get("name")
        match = CWE_ID.match(str(target.get("id", "")))
        if isinstance(component, str) and component.upper() == "CWE" and match:
            numbers.add(int(match.group(1)))
    return numbers


def _suppressed(suppressions: Any) -> bool:
    """Suppressed when the tool accepted at least one suppression (SARIF 3.27.23, 3.35.3): a
    suppression without a status counts as accepted, one under review or rejected doesn't."""
    if not isinstance(suppressions, list):
        return False
    statuses = [s.get("status", "accepted") for s in suppressions if isinstance(s, dict)]
    return "accepted" in statuses


def _message(result: dict, rule: dict, global_messages: dict) -> str:
    """The message text, with arguments filled into its placeholders (SARIF 3.11.5). Plain
    text without arguments is kept as it is: Semgrep writes "{{ }}" there as template syntax,
    not as escaped braces."""
    message = _dict(result.get("message"))
    arguments = message.get("arguments") or []
    template = message.get("text")
    if isinstance(template, str):
        if not arguments:
            return template
    else:
        message_id = message.get("id")
        strings = _dict(rule.get("messageStrings"))
        source = strings.get(message_id) or global_messages.get(message_id)
        template = _text(source) or ""
    parts: list[str] = []
    size = 0
    position = 0
    for match in MESSAGE_PART.finditer(template):
        parts.append(template[position : match.start()])
        token = match.group(0)
        if token in ("{{", "}}"):
            parts.append(token[0])
        else:
            index = int(match.group(1))
            parts.append(str(arguments[index]) if index < len(arguments) else token)
        position = match.end()
        size += len(parts[-1]) + len(parts[-2])
        if size > MAX_TEXT:
            break
    else:
        parts.append(template[position:])
    return "".join(parts)


def _text(message: Any) -> str | None:
    if isinstance(message, dict) and isinstance(message.get("text"), str):
        return message["text"]
    return None


def _clean_text(value: str | None) -> str | None:
    """Text without NUL characters or lone surrogates, which the findings store can't keep,
    and no longer than MAX_TEXT."""
    if value is None:
        return None
    value = value.replace("\x00", "").encode("utf-8", "replace").decode("utf-8")
    return value if len(value) <= MAX_TEXT else value[:MAX_TEXT] + " [cut]"


def _clean_raw(value: Any) -> Any:
    if isinstance(value, str):
        return value.replace("\x00", "").encode("utf-8", "replace").decode("utf-8")
    if isinstance(value, dict):
        return {_clean_raw(k): _clean_raw(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean_raw(item) for item in value]
    return value


def _column(value: Any) -> int | None:
    return value if type(value) is int and 1 <= value <= MAX_LINE else None


def _is_web_url(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def _dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _short(value: Any) -> str:
    text = _clean_text(str(value)) or ""
    return text if len(text) <= MAX_WARNING_ID else text[:MAX_WARNING_ID] + "..."
