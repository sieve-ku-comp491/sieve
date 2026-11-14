"""Sieve's command-line interface (T2.4). It calls the REST API with the API token.

    python -m app.cli scan https://github.com/adeyosemanputra/pygoat --commit 2aa4cc1
    python -m app.cli findings <scan ID>

Run it from backend/. It uses only Python's standard library, so it needs no packages. The API
is at SIEVE_API_URL, http://127.0.0.1:8000 by default. The token is SIEVE_API_TOKEN from the
environment, or else from the .env file in the current folder or a folder above it.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, TextIO

DEFAULT_API = "http://127.0.0.1:8000"
FINAL = ("completed", "partial", "failed")
PAGE = 500


class ApiError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


class Api:
    def __init__(self, base_url: str, token: str, timeout: float = 30):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        query = "?" + urllib.parse.urlencode(params, doseq=True) if params else ""
        return self._send("GET", path + query)

    def post(self, path: str, body: dict[str, Any]) -> Any:
        return self._send("POST", path, json.dumps(body).encode("utf-8"))

    def _send(self, method: str, path: str, data: bytes | None = None) -> Any:
        request = urllib.request.Request(self.base_url + path, data=data, method=method)
        request.add_header("Authorization", f"Bearer {self.token}")
        request.add_header("Accept", "application/json")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read() or b"null")
        except urllib.error.HTTPError as error:
            raise ApiError(error.code, _detail(error.read())) from None
        except (urllib.error.URLError, OSError) as error:
            reason = getattr(error, "reason", error)
            raise ApiError(0, f"can't reach the API at {self.base_url}: {reason}") from None


def _detail(body: bytes) -> str:
    """The API's error message: FastAPI's detail, which is a text or a list of field errors."""
    try:
        detail = json.loads(body)["detail"]
    except ValueError, KeyError, TypeError:
        return body.decode("utf-8", "replace").strip() or "no details"
    if isinstance(detail, list):
        return "; ".join(
            f"{'.'.join(str(p) for p in item.get('loc', [])[1:])}: {item.get('msg')}"
            for item in detail
            if isinstance(item, dict)
        )
    return str(detail)


def find_token(environ: dict[str, str], folder: Path) -> str | None:
    """SIEVE_API_TOKEN from the environment, or from the nearest .env file."""
    if environ.get("SIEVE_API_TOKEN"):
        return environ["SIEVE_API_TOKEN"]
    for parent in [folder, *folder.parents]:
        env_file = parent / ".env"
        if env_file.is_file():
            for line in env_file.read_text(encoding="utf-8").splitlines():
                name, _, value = line.partition("=")
                if name.strip() == "SIEVE_API_TOKEN" and value.strip():
                    return value.strip().strip("'\"")
            return None
    return None


def scan(api: Api, args: argparse.Namespace, out: TextIO) -> int:
    body = {"repo_url": args.repo_url, "commit": args.commit}
    started = api.post("/scans", body)
    at = args.commit or "the default branch"
    print(f"scan {started['scan_id']} queued: {started['repo_url']} at {at}", file=out)
    if args.no_wait:
        return 0
    return follow(api, started["scan_id"], out, args.poll)


def follow(api: Api, scan_id: str, out: TextIO, poll: float) -> int:
    """Prints each change of the scan and its plug-in runs until the scan ends."""
    shown = {"status": "scan queued"}

    def show(key: str, line: str) -> None:
        if shown.get(key) != line:
            shown[key] = line
            print(line, file=out, flush=True)

    while True:
        detail = api.get(f"/scans/{scan_id}")
        if detail["commit_sha"]:
            languages = ", ".join(detail["languages"]) or "none found"
            show("commit", f"commit {detail['commit_sha']}, languages: {languages}")
        for run in detail["runs"]:
            show("run " + run["plugin"], f"  {run['plugin']}: {_run_text(run)}")
        status = detail["status"]
        if status in FINAL:
            line = f"scan {status}: {detail['finding_count']} findings"
            if detail["error"]:
                line += f". {detail['error']}"
            show("status", line)
            print(f"list them with: python -m app.cli findings {scan_id}", file=out)
            return 0 if status == "completed" else 1
        show("status", f"scan {status}")
        time.sleep(poll)


def _run_text(run: dict[str, Any]) -> str:
    text = run["status"]
    if run["reason"]:
        text += f" ({run['reason']})"
    if run["status"] == "succeeded":
        text += f", {run['result_count']} results from {run['files_scanned']} files"
    return text


def findings(api: Api, args: argparse.Namespace, out: TextIO) -> int:
    params: dict[str, Any] = {"include_hidden": args.include_hidden}
    if args.tool:
        params["tool"] = args.tool
    items: list[dict[str, Any]] = []
    total = None
    while total is None or len(items) < total:
        page = api.get(
            f"/scans/{args.scan_id}/findings", params | {"limit": PAGE, "offset": len(items)}
        )
        total = page["total"]
        items += page["items"]
        if not page["items"]:
            break
    if args.json:
        json.dump(items, out, indent=2)
        print(file=out)
        return 0
    print(f"{total} findings in scan {args.scan_id}", file=out)
    for item in items:
        level = item["severity"] or item["tool_severity"]
        where = f"{item['file']}:{item['start_line']}"
        print(f"{level:<8} {item['tool']:<9} {item['rule_id']}  {where}", file=out)
    return 0


def main(
    argv: list[str] | None = None,
    environ: dict[str, str] | None = None,
    out: TextIO = sys.stdout,
    err: TextIO = sys.stderr,
) -> int:
    environ = dict(os.environ) if environ is None else environ
    parser = argparse.ArgumentParser(prog="python -m app.cli", description=__doc__.split("\n")[0])
    parser.add_argument(
        "--api", default=environ.get("SIEVE_API_URL", DEFAULT_API), help="the API's URL"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("scan", help="scan a repository from the scope file")
    start.add_argument("repo_url", help="the repository's https URL, as in the scope file")
    start.add_argument("--commit", help="a commit hash, branch or tag. Default: the default branch")
    start.add_argument("--no-wait", action="store_true", help="queue the scan and return")
    start.add_argument("--poll", type=float, default=2.0, help=argparse.SUPPRESS)
    listing = commands.add_parser("findings", help="list a scan's findings")
    listing.add_argument("scan_id")
    listing.add_argument("--tool", action="append", help="only this plug-in, can be repeated")
    listing.add_argument(
        "--include-hidden", action="store_true", help="also findings an earlier review decided"
    )
    listing.add_argument("--json", action="store_true", help="print the findings as JSON")
    args = parser.parse_args(argv)

    token = find_token(environ, Path.cwd())
    if not token:
        print("set SIEVE_API_TOKEN, or run from the folder with Sieve's .env file", file=err)
        return 2
    api = Api(args.api, token)
    try:
        if args.command == "scan":
            return scan(api, args, out)
        return findings(api, args, out)
    except ApiError as error:
        print(f"error: {error.detail}", file=err)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
