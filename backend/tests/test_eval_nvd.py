"""Published CVSS vectors from the NVD. The tests answer for the NVD, so they need no network."""

import http.client
import io
import json

import pytest

from app.eval import nvd
from app.eval.nvd import Cvss, cwe_bench_java_cves, pick_cvss, read_cves, write_cves


def metric(kind: str, source: str, vector: str, score: float) -> dict:
    return {
        "source": source,
        "type": kind,
        "cvssData": {"vectorString": vector, "baseScore": score},
    }


V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"


def test_prefers_the_nvd_own_vector():
    cve = {
        "metrics": {
            "cvssMetricV40": [metric("Secondary", "security-advisories@github.com", V40, 8.7)],
            "cvssMetricV31": [metric("Primary", "nvd@nist.gov", V31, 7.5)],
        }
    }
    assert pick_cvss(cve) == Cvss("3.1", V31, 7.5, "nvd@nist.gov")


def test_newest_version_from_another_source_when_the_nvd_has_none():
    cve = {
        "metrics": {
            "cvssMetricV40": [metric("Secondary", "cna", V40, 8.7)],
            "cvssMetricV31": [metric("Secondary", "cna", V31, 7.5)],
        }
    }
    assert pick_cvss(cve).version == "4.0"


def test_cvss_2_only_gives_nothing():
    cve = {"metrics": {"cvssMetricV2": [metric("Primary", "nvd@nist.gov", "AV:N/AC:L", 5.0)]}}
    assert pick_cvss(cve) is None


def test_cwe_bench_java_cves(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data/project_info.csv").write_text(
        "project_slug,cve_id,cwe_id,github_url,buggy_commit_id\n"
        "acme__app_CVE-2020-1_1.0,CVE-2020-1,CWE-022,https://github.com/acme/app,bad1\n"
        "acme__app_CVE-2020-2_1.0,CVE-2020-2,CWE-079,https://github.com/acme/app,bad2\n"
        "acme__app_CVE-2020-3_1.0,CVE-2020-3,CWE-078,https://github.com/acme/app,bad3\n"
    )
    answers = {
        "CVE-2020-1": {"metrics": {"cvssMetricV31": [metric("Primary", "nvd@nist.gov", V31, 7.5)]}},
        "CVE-2020-2": {"metrics": {}},
    }
    rows = cwe_bench_java_cves(
        tmp_path, {"CVE-2020-1", "CVE-2020-2"}, fetch=answers.__getitem__, log=lambda _: None
    )
    assert [(r.cve_id, r.cwe, r.cvss_version, r.cvss_score) for r in rows] == [
        ("CVE-2020-1", "CWE-22", "3.1", "7.5"),
        ("CVE-2020-2", "CWE-79", "", ""),
    ]
    assert rows[0].vulnerable_commit == "bad1"

    path = tmp_path / "cves.csv"
    write_cves(rows, path)
    assert read_cves(path) == rows


class Answer:
    def __init__(self, body: bytes):
        self.body = body

    def __enter__(self):
        return io.BytesIO(self.body)

    def __exit__(self, *args):
        return False


def test_lookup_retries_a_dropped_connection(monkeypatch):
    body = json.dumps({"vulnerabilities": [{"cve": {"id": "CVE-2020-1", "metrics": {}}}]})
    calls = []

    def urlopen(request, timeout):
        calls.append(request.full_url)
        if len(calls) == 1:
            raise http.client.RemoteDisconnected("Remote end closed connection without response")
        return Answer(body.encode())

    monkeypatch.setattr(nvd.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(nvd.time, "sleep", lambda seconds: None)
    assert nvd.lookup("CVE-2020-1") == {"id": "CVE-2020-1", "metrics": {}}
    assert len(calls) == 2 and calls[0].endswith("cveId=CVE-2020-1")


def test_lookup_gives_up_after_four_tries(monkeypatch):
    def urlopen(request, timeout):
        raise TimeoutError("timed out")

    monkeypatch.setattr(nvd.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(nvd.time, "sleep", lambda seconds: None)
    with pytest.raises(nvd.NvdError, match="timed out"):
        nvd.lookup("CVE-2020-1")
