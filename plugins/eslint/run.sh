#!/bin/sh
# Entry point of the ESLint plug-in. scan.cjs maps ESLint's outcome to the exit codes of the
# plug-in contract: 0, 3 for nothing to scan, 1 for a failure.
exec node /opt/sieve/scan.cjs
