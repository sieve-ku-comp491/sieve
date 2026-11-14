#!/bin/sh
# Entry point of the SpotBugs plug-in's scan step (docs/interfaces.md, Build step). It analyzes
# only the class folders the build step listed, with the libraries in /build/deps on the
# auxiliary classpath and the source folders under /src, so the SARIF file names files that
# exist in the checkout.
python3 /opt/sieve/java_build.py
status=$?
[ "$status" -eq 0 ] || exit "$status"

# The settings Find Security Bugs recommends: maximum effort, all confidence levels, and only
# the SECURITY category. SpotBugs exits with 0 when the analysis finished, with or without
# bugs. It has no option to ignore @SuppressFBWarnings in the scanned code: -omitVisitors
# doesn't turn off NoteSuppressedWarnings, and suppressed bugs never reach the SARIF file.
java -Xmx3g -jar /opt/spotbugs/lib/spotbugs.jar -textui \
  -effort:max -low -nested:false \
  -pluginList /opt/findsecbugs/findsecbugs-plugin-1.14.0.jar \
  -include /opt/sieve/security-only.xml \
  -auxclasspathFromFile /tmp/aux.txt \
  -sourcepath "$(cat /tmp/sourcepath)" \
  -analyzeFromFile /tmp/analyze.txt \
  -sarif="$SIEVE_OUT/results.sarif" || exit 1
python3 /opt/sieve/java_build.py --add-roots || exit 1
