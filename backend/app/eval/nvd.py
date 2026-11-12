"""Published CVSS vectors from the NVD, for the severity evaluation (requirement F4, test 4)."""

import csv
import http.client
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import astuple, dataclass, fields
from datetime import date
from pathlib import Path

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVES_FILE = Path(__file__).with_name("cves.csv")
# The NVD allows 5 requests in 30 seconds without an API key, and 50 with one.
DELAY_SECONDS = 6.5
DELAY_WITH_KEY_SECONDS = 0.7
VERSIONS = (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"))


class NvdError(RuntimeError):
    """The NVD didn't answer, or answered with something we can't read."""


@dataclass(frozen=True)
class Cvss:
    version: str
    vector: str
    score: float
    source: str


@dataclass(frozen=True)
class CveRow:
    """One CVE of the severity evaluation, with its vector as the NVD published it."""

    cve_id: str
    cwe: str
    project: str
    repository: str
    vulnerable_commit: str
    cvss_version: str
    cvss_vector: str
    cvss_score: str
    cvss_source: str
    checked_on: str


COLUMNS = [field.name for field in fields(CveRow)]


def pick_cvss(cve: dict) -> Cvss | None:
    """The NVD's own vector in the newest CVSS version it has, else the newest from another source.

    The NVD's analysts publish as the Primary source. A CNA, such as GitHub, can publish its own
    vector as a Secondary source. CVSS 2.0 vectors are not used: our severity step picks CVSS
    3.1 and 4.0 metrics, so a CVE with only a 2.0 vector gets no row in the evaluation.
    """
    metrics = cve.get("metrics", {})
    for wanted in ("Primary", "Secondary"):
        for key, version in VERSIONS:
            for entry in metrics.get(key, []):
                if entry.get("type") == wanted:
                    data = entry["cvssData"]
                    return Cvss(
                        version,
                        data["vectorString"],
                        float(data["baseScore"]),
                        entry.get("source", ""),
                    )
    return None


def lookup(cve_id: str, api_key: str | None = None) -> dict:
    query = urllib.parse.urlencode({"cveId": cve_id})
    headers = {"User-Agent": "sieve-eval"}
    if api_key:
        headers["apiKey"] = api_key
    request = urllib.request.Request(f"{NVD_URL}?{query}", headers=headers)
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = json.load(response)
            break
        except urllib.error.HTTPError as error:
            # 403 and 503 are the NVD's rate limit and busy answers. Wait and try again.
            if error.code not in {403, 503} or attempt == 3:
                raise NvdError(f"{cve_id}: HTTP {error.code}") from None
            time.sleep(30)
        except (OSError, http.client.HTTPException) as error:
            # Covers a refused or dropped connection and a timeout. The NVD sometimes closes a
            # connection without an answer, and the next request goes through.
            if attempt == 3:
                raise NvdError(f"{cve_id}: {error}") from None
            time.sleep(10)
    vulnerabilities = body.get("vulnerabilities", [])
    if len(vulnerabilities) != 1:
        raise NvdError(f"{cve_id}: expected one record, got {len(vulnerabilities)}")
    return vulnerabilities[0]["cve"]


def cwe_bench_java_cves(
    root: Path,
    case_ids: set[str],
    fetch: Callable[[str], dict] | None = None,
    log: Callable[[str], None] = print,
) -> list[CveRow]:
    """Look up the NVD vector of every CWE-Bench-Java CVE that has a known vulnerable location."""
    api_key = os.environ.get("NVD_API_KEY")
    delay = 0.0 if fetch else DELAY_WITH_KEY_SECONDS if api_key else DELAY_SECONDS
    fetch = fetch or (lambda cve_id: lookup(cve_id, api_key))
    with (root / "data/project_info.csv").open(encoding="utf-8", newline="") as handle:
        projects = [row for row in csv.DictReader(handle) if row["cve_id"] in case_ids]
    rows = []
    today = date.today().isoformat()
    for index, project in enumerate(projects):
        if index and delay:
            time.sleep(delay)
        cvss = pick_cvss(fetch(project["cve_id"]))
        rows.append(
            CveRow(
                cve_id=project["cve_id"],
                cwe=f"CWE-{int(project['cwe_id'].removeprefix('CWE-'))}",
                project=project["project_slug"],
                repository=project["github_url"],
                vulnerable_commit=project["buggy_commit_id"],
                cvss_version=cvss.version if cvss else "",
                cvss_vector=cvss.vector if cvss else "",
                cvss_score=f"{cvss.score:.1f}" if cvss else "",
                cvss_source=cvss.source if cvss else "",
                checked_on=today,
            )
        )
        log(f"{project['cve_id']}: {cvss.vector if cvss else 'no CVSS 3 or 4 vector'}")
    return rows


def write_cves(rows: list[CveRow], path: Path = CVES_FILE) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(COLUMNS)
        writer.writerows(astuple(row) for row in sorted(rows, key=lambda row: row.cve_id))


def read_cves(path: Path = CVES_FILE) -> list[CveRow]:
    with path.open(encoding="utf-8", newline="") as handle:
        return [CveRow(**row) for row in csv.DictReader(handle)]
