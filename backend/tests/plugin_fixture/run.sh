#!/bin/sh
# Test plug-in. The first word of /src/mode says what to do. In the build step SIEVE_BUILD is set.

mode=$(head -n 1 "$SIEVE_SRC/mode")

write_results() {
  cat > "$SIEVE_OUT/results.sarif" <<'EOF'
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [{
    "tool": {"driver": {"name": "fixture", "semanticVersion": "0.0.1", "rules": [{"id": "fixture.rule"}]}},
    "results": [{
      "ruleId": "fixture.rule",
      "message": {"text": "found something"},
      "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 1}}}]
    }]
  }]
}
EOF
  printf '{"files_scanned": %s}' "$1" > "$SIEVE_OUT/scan-info.json"
}

if [ -n "$SIEVE_BUILD" ]; then
  case "$mode" in
    build) echo "built" > "$SIEVE_BUILD/built"; echo "build done"; exit 0 ;;
    build-fail) echo "the build broke" >&2; exit 1 ;;
    build-sleep) sleep 300; exit 0 ;;
    *) echo "no build step for mode $mode" >&2; exit 1 ;;
  esac
fi

case "$mode" in
  ok)
    echo "scanning"
    write_results 2 ;;
  zero)
    write_results 0 ;;
  sleep)
    echo "sleeping"
    sleep 300 ;;
  crash)
    echo "crashing on purpose" >&2
    exit 2 ;;
  not-json)
    echo "this is not json" > "$SIEVE_OUT/results.sarif"
    printf '{"files_scanned": 2}' > "$SIEVE_OUT/scan-info.json" ;;
  bad-schema)
    echo '{"version": "2.1.0", "runs": [{"results": []}]}' > "$SIEVE_OUT/results.sarif"
    printf '{"files_scanned": 2}' > "$SIEVE_OUT/scan-info.json" ;;
  no-sarif)
    echo "wrote nothing" ;;
  no-scan-info)
    write_results 2
    rm "$SIEVE_OUT/scan-info.json" ;;
  nothing)
    exit 3 ;;
  oom)
    # tail keeps everything it reads when there are no line breaks.
    head -c 500000000 /dev/zero | tail > /dev/null
    write_results 2 ;;
  network)
    # Each line of /src/targets is a URL. Exit 0 if any of them answers.
    reached=1
    while read -r url; do
      if wget -q -T 3 -O /dev/null "$url"; then
        echo "reached $url"
        reached=0
      else
        echo "could not reach $url"
      fi
    done < "$SIEVE_SRC/targets"
    exit $reached ;;
  probe)
    {
      echo "uid=$(id -u) gid=$(id -g)"
      touch "$SIEVE_SRC/new" 2>/dev/null && echo "src=writable" || echo "src=read-only"
      touch /new 2>/dev/null && echo "root=writable" || echo "root=read-only"
      touch /tmp/new 2>/dev/null && echo "tmp=writable" || echo "tmp=read-only"
      echo "caps=$(grep CapEff /proc/self/status | tr -d '\t')"
      echo "nonewprivs=$(grep NoNewPrivs /proc/self/status | tr -d '\t')"
      echo "routes=$(tail -n +2 /proc/net/route | wc -l)"
      env | cut -d= -f1 | sort | tr '\n' ' ' | sed 's/^/env=/'
      echo
    } > "$SIEVE_OUT/probe.txt"
    write_results 2 ;;
  build)
    # The scan step after the build step: /build holds the build's output, read-only.
    [ -f /build/built ] || { echo "no build output" >&2; exit 1; }
    touch /build/new 2>/dev/null && { echo "/build is writable" >&2; exit 1; }
    write_results 2 ;;
  *)
    echo "unknown mode $mode" >&2
    exit 1 ;;
esac
