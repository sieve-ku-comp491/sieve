#!/bin/sh
# Entry point of the Bandit plug-in.
# Without --ini, Bandit takes options such as skips and exclude from a .bandit file anywhere in
# the scanned code, and fails when it finds two. bandit.ini holds only the [bandit] section, so
# no options come from a file. --exit-zero makes Bandit exit with 0 when it finds issues, so any
# other code is a failure.
bandit -r "$SIEVE_SRC" --ini /opt/sieve/bandit.ini --ignore-nosec --exit-zero \
  -f sarif -o "$SIEVE_OUT/results.sarif" || exit 1
# Bandit lists every Python file it found in its metrics, and files it couldn't parse in
# toolConfigurationNotifications. Only the parsed files count as scanned.
python3 -c 'import json, sys
from urllib.parse import unquote, urlsplit
run = json.load(open(sys.argv[1]))["runs"][0]
found = set(run["properties"]["metrics"]) - {"_totals"}
skipped = {
    unquote(urlsplit(location["physicalLocation"]["artifactLocation"]["uri"]).path)
    for invocation in run.get("invocations", [])
    for notification in invocation.get("toolConfigurationNotifications", [])
    for location in notification.get("locations", [])
}
if not found:
    sys.exit(3)
json.dump({"files_scanned": len(found - skipped)}, sys.stdout)' \
  "$SIEVE_OUT/results.sarif" > "$SIEVE_OUT/scan-info.json"
