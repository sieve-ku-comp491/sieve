#!/bin/sh
# Entry point of the Semgrep plug-in.
cd /opt/semgrep-rules || exit 1
configs=$(find python java javascript typescript -type d -name security \
  | sort | sed 's/^/--config /')
# Semgrep exits with 0 when the scan finished, with or without findings.
semgrep scan $configs --metrics off --disable-version-check --no-git-ignore \
  --disable-nosem \
  --sarif-output "$SIEVE_OUT/results.sarif" \
  --json-output /tmp/semgrep.json "$SIEVE_SRC" || exit 1
# Semgrep's JSON output lists the scanned files, its SARIF output doesn't.
python3 -c 'import json, sys
d = json.load(open("/tmp/semgrep.json"))
json.dump({"files_scanned": len(d["paths"]["scanned"])}, sys.stdout)' \
  > "$SIEVE_OUT/scan-info.json" || exit 1
