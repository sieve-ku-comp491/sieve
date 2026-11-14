"""The SpotBugs adapter on real output of the SpotBugs plug-in from WebGoat
(tests/adapter_fixture/README.md), and the plug-in itself through the runner.

The expected values were worked out by hand from spotbugs-webgoat.sarif and the two WebGoat
files in adapter_fixture/webgoat: the file is the source folder from originalUriBaseIds
(file:/src/src/main/java/) without /src/, plus the result's uri; the CWE is the rule's
relationship to the CWE taxonomy; the snippet is the flagged line of the file. The
fingerprints and context hashes were computed with hashlib from the formula in
docs/finding-format.md, on the lines read from the fixture files, not with the adapter.
"""

import copy
import json
import time
import uuid
from pathlib import Path

import docker
import docker.errors
import pytest

from app.adapters import AdapterRegistry, SpotBugsAdapter
from app.checkout import CheckoutReader
from app.runner import (
    DockerEngine,
    InMemoryRunStore,
    PluginManifest,
    PluginRunner,
    RunnerSettings,
    RunStatus,
    SarifValidator,
    ScanTarget,
    maven_cache_volume,
)
from app.runner.runner import PluginRun

FIXTURE = Path(__file__).parent / "adapter_fixture"
SARIF = FIXTURE / "spotbugs-webgoat.sarif"
CHECKOUT = FIXTURE / "webgoat"
REPO = Path(__file__).resolve().parents[2]
MANIFEST = REPO / "plugins" / "spotbugs" / "plugin.toml"
HASHING = "src/main/java/org/owasp/webgoat/lessons/cryptography/HashingAssignment.java"
CHALLENGE = "src/main/java/org/owasp/webgoat/lessons/challenges/challenge5/Assignment5.java"
RUN = PluginRun(
    "run-0031",
    "scan-0009",
    "spotbugs",
    "sieve-plugin-spotbugs:4.10.5-fsb1.14.0",
    "4.10.5",
    "find-sec-bugs 1.14.0",
)


def load() -> dict:
    return json.loads(SARIF.read_text(encoding="utf-8"))


def convert(sarif: dict, checkout: Path = CHECKOUT):
    return SpotBugsAdapter().to_findings(sarif, RUN, CheckoutReader(checkout))


@pytest.fixture(scope="module")
def result():
    return convert(SarifValidator().validate(SARIF))


def find(result, rule_id, line):
    (finding,) = [
        f for f in result.findings if f.rule_id == rule_id and f.location.start_line == line
    ]
    return finding


def test_every_result_becomes_a_finding(result):
    assert len(result.findings) == 13
    assert result.dropped == {} and result.warnings == []
    assert {f.location.file for f in result.findings} == {HASHING, CHALLENGE}


def test_sql_injection(result):
    raw = load()
    finding = find(result, "SQL_INJECTION_JDBC", 44)
    assert finding.scan_id == "scan-0009" and finding.run_id == "run-0031"
    assert finding.tool == "spotbugs"
    assert finding.tool_version == "4.10.5"
    assert finding.rule_description.startswith(
        "The input values included in SQL queries need to be passed in safely."
    )
    assert finding.rule_help_uri == "https://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION_JDBC"
    assert finding.cwe == ["CWE-89"]
    # SpotBugs writes both message.text and message.id with arguments. The text wins.
    assert finding.message == "Potential JDBC Injection"
    assert finding.tool_severity == "warning"
    assert finding.tool_score is None
    assert finding.tool_confidence is None
    location = finding.location
    assert (location.file, location.start_line, location.end_line) == (CHALLENGE, 44, 44)
    assert (location.start_column, location.end_column) == (None, None)
    assert location.snippet == "          connection.prepareStatement("
    assert finding.fingerprint == "v1:856a9ba1308c17148e127fa627c7f891"
    assert finding.fingerprint_ambiguous is False
    assert finding.context_hash == "c1:f2dfcf6f2312237357b79a1d5a72ff63"
    assert finding.suppressed is False
    assert finding.tool_fingerprint is None
    assert finding.language == "java"
    assert finding.related_locations == [] and finding.data_flow == []
    assert finding.raw == raw["runs"][0]["results"][1]


def test_the_same_line_from_spotbugs_and_find_security_bugs(result):
    """Find Security Bugs and SpotBugs' own SQL rule both flag line 44: a duplicate for T3.2."""
    finding = find(result, "SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING", 44)
    assert finding.cwe == ["CWE-89"]
    assert finding.rule_help_uri == (
        "https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html"
        "#SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING"
    )
    assert finding.fingerprint == "v1:e96d23913ef8dca8ce351ae3ed79fdd8"
    assert finding.context_hash == "c1:f2dfcf6f2312237357b79a1d5a72ff63"


def test_rule_cwe_lines_and_severity_of_each_result(result):
    rows = sorted(
        (
            f.location.file == HASHING,
            f.rule_id,
            f.location.start_line,
            f.location.end_line,
            f.cwe,
            f.tool_severity,
        )
        for f in result.findings
    )
    assert rows == [
        (False, "SPRING_ENDPOINT", 36, 42, [], "note"),
        (False, "SQL_INJECTION_JDBC", 44, 44, ["CWE-89"], "warning"),
        (
            False,
            "SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING",
            44,
            44,
            ["CWE-89"],
            "warning",
        ),
        (True, "PREDICTABLE_RANDOM", 37, 37, ["CWE-330"], "warning"),
        (True, "PREDICTABLE_RANDOM", 55, 55, ["CWE-330"], "warning"),
        (True, "SPRING_CSRF_UNRESTRICTED_REQUEST_MAPPING", 34, 46, ["CWE-352"], "warning"),
        (True, "SPRING_CSRF_UNRESTRICTED_REQUEST_MAPPING", 53, 60, ["CWE-352"], "warning"),
        (True, "SPRING_ENDPOINT", 34, 46, [], "note"),
        (True, "SPRING_ENDPOINT", 53, 60, [], "note"),
        (True, "SPRING_ENDPOINT", 70, 80, [], "note"),
        (True, "UNSAFE_HASH_EQUALS", 74, 74, ["CWE-203"], "warning"),
        (True, "UNSAFE_HASH_EQUALS", 76, 76, ["CWE-203"], "warning"),
        (True, "WEAK_MESSAGE_DIGEST_MD5", 39, 39, ["CWE-328"], "warning"),
    ]


def test_weak_hash(result):
    finding = find(result, "WEAK_MESSAGE_DIGEST_MD5", 39)
    assert finding.location.snippet == '      MessageDigest md = MessageDigest.getInstance("MD5");'
    assert finding.message == "MD2, MD4 and MD5 are weak hash functions"
    assert finding.fingerprint == "v1:4166b2a60ae699ca087beefc713bf2eb"
    assert finding.context_hash == "c1:ec717a4f268925830397f28892729c55"


def test_the_same_line_twice_in_one_file_is_ambiguous(result):
    """Lines 37 and 55 are both `String secret = SECRETS[new Random().nextInt(...)];`, so the
    two findings differ only by their occurrence."""
    first = find(result, "PREDICTABLE_RANDOM", 37)
    second = find(result, "PREDICTABLE_RANDOM", 55)
    assert first.location.snippet == second.location.snippet
    assert first.fingerprint == "v1:30a0d6efb2fde6d06c5fa8d3cb496682"
    assert second.fingerprint == "v1:4e6e8f95905df09d5feee5a560a0f01d"
    assert first.fingerprint_ambiguous and second.fingerprint_ambiguous
    assert first.context_hash == "c1:3911069c06503f6b1ad9dd922f4b24dd"
    assert second.context_hash == "c1:7d7a0cd76052c840d58a01875bb8675b"
    assert not find(result, "WEAK_MESSAGE_DIGEST_MD5", 39).fingerprint_ambiguous


def without_base(sarif: dict) -> dict:
    """The same results with paths relative to the source folder and no uriBaseId, as
    SpotBugs writes them when it doesn't find the file."""
    sarif = copy.deepcopy(sarif)
    for item in sarif["runs"][0]["results"]:
        item["locations"][0]["physicalLocation"]["artifactLocation"].pop("uriBaseId")
    return sarif


def test_a_path_relative_to_a_listed_source_folder(result):
    out = convert(without_base(load()))
    assert out.dropped == {}
    assert [(f.location.file, f.fingerprint) for f in out.findings] == [
        (f.location.file, f.fingerprint) for f in result.findings
    ]


def test_a_path_that_fits_two_source_folders_is_dropped(tmp_path):
    """The plug-in lists every source folder of the build in originalUriBaseIds. A path that
    exists under two of them could be either file, so the adapter doesn't pick one."""
    for module in ("a", "b"):
        target = tmp_path / module / CHALLENGE
        target.parent.mkdir(parents=True)
        target.write_bytes((CHECKOUT / CHALLENGE).read_bytes())
    sarif = without_base(load())
    sarif["runs"][0]["originalUriBaseIds"] = {
        "SOURCE_FOLDER_0": {"uri": "file:/src/a/src/main/java/"},
        "SOURCE_FOLDER_1": {"uri": "file:/src/b/src/main/java/"},
    }
    sarif["runs"][0]["results"] = sarif["runs"][0]["results"][:3]
    out = convert(sarif, tmp_path)
    assert out.findings == []
    assert out.dropped == {"path_outside_checkout": 3}

    sarif["runs"][0]["originalUriBaseIds"].pop("SOURCE_FOLDER_1")
    out = convert(sarif, tmp_path)
    assert {f.location.file for f in out.findings} == {f"a/{CHALLENGE}"}


def test_a_relative_path_without_any_source_folder_is_dropped():
    sarif = without_base(load())
    sarif["runs"][0]["originalUriBaseIds"] = {}
    out = convert(sarif)
    assert out.findings == [] and out.dropped == {"path_outside_checkout": 13}


def test_registry_and_manifest():
    manifest = PluginManifest.load(MANIFEST)
    assert isinstance(AdapterRegistry().get(manifest.adapter), SpotBugsAdapter)
    assert manifest.name == "spotbugs"
    assert manifest.image == "sieve-plugin-spotbugs:4.10.5-fsb1.14.0"
    assert manifest.build.image == "sieve-plugin-spotbugs-build:jdk25-3.9.16"
    assert (manifest.tool_version, manifest.rules_version) == ("4.10.5", "find-sec-bugs 1.14.0")
    assert manifest.languages == ("java",)
    assert manifest.timeout_seconds == 1800


# The plug-in through the runner ------------------------------------------------------------
#
# Needs both plug-in images, which CI doesn't build, and network to Maven Central. Build them
# with the commands at the top of plugins/spotbugs/Dockerfile.

POM = """\
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0</version>
  <properties>
    <maven.compiler.release>25</maven.compiler.release>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
  <repositories>
    <repository>
      <id>elsewhere</id>
      <url>https://repo.example.com/maven2</url>
    </repository>
  </repositories>
</project>
"""

HASH_JAVA = """\
package com.example;

import java.security.MessageDigest;

public class Hash {
  public byte[] digest(byte[] data) throws Exception {
    return MessageDigest.getInstance("MD5").digest(data);
  }
}
"""


@pytest.fixture(scope="module")
def client() -> docker.DockerClient:
    plugin = PluginManifest.load(MANIFEST)
    try:
        client = docker.from_env()
        client.images.get(plugin.image)
        client.images.get(plugin.build.image)
    except docker.errors.ImageNotFound:
        pytest.skip("the SpotBugs plug-in's images aren't built on this machine")
    except Exception:
        pytest.skip("Docker is not running")
    return client


@pytest.fixture(scope="module")
def build_network(client):
    """An internal network with maven-proxy on it, as docker-compose.yml sets it up."""
    image, _ = client.images.build(path=str(REPO / "maven-proxy"), rm=True)
    suffix = uuid.uuid4().hex[:8]
    build = client.networks.create(f"sieve-test-spotbugs-build-{suffix}", internal=True)
    egress = client.networks.create(f"sieve-test-spotbugs-egress-{suffix}")
    proxy = client.containers.create(
        image.id,
        name=f"sieve-test-spotbugs-proxy-{suffix}",
        network=egress.name,
        read_only=True,
        tmpfs={"/tmp": ""},
        cap_drop=["ALL"],
        security_opt=["no-new-privileges"],
    )
    try:
        build.connect(proxy, aliases=["maven-proxy"])
        proxy.start()
        deadline = time.monotonic() + 30
        while b"Accepting HTTP Socket connections" not in proxy.logs():
            assert time.monotonic() < deadline, proxy.logs().decode()
            time.sleep(0.2)
        yield build.name
    finally:
        proxy.remove(force=True)
        build.remove()
        egress.remove()


def test_the_plugin_builds_and_scans_a_maven_project(client, build_network, tmp_path):
    plugin = PluginManifest.load(MANIFEST)
    scan = ScanTarget(scan_id=str(uuid.uuid4()), repo_url=f"https://example.com/{uuid.uuid4()}")
    src = tmp_path / "scans" / scan.scan_id / "src"
    java = src / "src" / "main" / "java" / "com" / "example"
    java.mkdir(parents=True)
    (src / "pom.xml").write_text(POM, newline="\n")
    (java / "Hash.java").write_text(HASH_JAVA, newline="\n")

    store = InMemoryRunStore()
    settings = RunnerSettings(tmp_path, data_volume=None, build_network=build_network)
    runner = PluginRunner(DockerEngine(client), store, settings)
    try:
        run = runner.run(scan, plugin, store.create_run(scan.scan_id, plugin))
    finally:
        try:
            client.volumes.get(maven_cache_volume(scan.repo_url)).remove()
        except docker.errors.NotFound:
            pass

    log = (tmp_path / run.log_path).read_text(encoding="utf-8")
    assert run.status is RunStatus.SUCCEEDED, log
    assert run.files_scanned == 1
    assert "BUILD SUCCESS" in log
    build = json.loads((tmp_path / "runs" / run.run_id / "build" / "java-build.json").read_text())
    assert build == {"class_dirs": ["target/classes"], "source_dirs": ["src/main/java"]}

    sarif = SarifValidator().validate(tmp_path / run.sarif_path)
    out = SpotBugsAdapter().to_findings(sarif, run, CheckoutReader(src))
    assert [(f.rule_id, f.location.file, f.location.start_line, f.cwe) for f in out.findings] == [
        ("WEAK_MESSAGE_DIGEST_MD5", "src/main/java/com/example/Hash.java", 7, ["CWE-328"])
    ]
