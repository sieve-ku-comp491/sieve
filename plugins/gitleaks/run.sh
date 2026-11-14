#!/bin/sh
# Entry point of the Gitleaks plug-in. It scans the files in /src, not the Git history:
# the export has no .git folder, and we report on the checked-out commit.
files=$(find "$SIEVE_SRC" -type f | wc -l) || exit 1
[ "$files" -gt 0 ] || exit 3
# --redact keeps the secrets out of the SARIF file and the log. Gitleaks exits with 1 both
# on errors and, by default, when it finds leaks, so leaks get their own exit code here.
gitleaks dir "$SIEVE_SRC" --redact --no-banner --no-color --ignore-gitleaks-allow \
  --report-format sarif --report-path "$SIEVE_OUT/results.sarif" --exit-code 2
case $? in
  0 | 2) ;;
  *) exit 1 ;;
esac
printf '{"files_scanned": %d}\n' "$files" > "$SIEVE_OUT/scan-info.json" || exit 1
