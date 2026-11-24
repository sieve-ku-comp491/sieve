#!/bin/sh
# Entry point of the SpotBugs plug-in's build step (docs/interfaces.md, Build step). It builds
# the project in $SIEVE_BUILD/work, copies the libraries it is compiled against to
# $SIEVE_BUILD/deps, and lists the class and source folders of each module in
# $SIEVE_BUILD/java-build.json for the scan step.

work="$SIEVE_BUILD/work"
if [ ! -f "$SIEVE_SRC/pom.xml" ]; then
  echo "no pom.xml in the repository root, and the build step only runs Maven" >&2
  exit 1
fi

# Maven writes into the project folder, and /src is read-only.
mkdir -p "$work" && cp -R "$SIEVE_SRC/." "$work/" || exit 1
cd "$work" || exit 1

# One Maven run, so that in a project with several modules each module's copy-dependencies
# finds the modules it depends on, packaged earlier in the same run. includeScope=compile also
# copies provided and system libraries, such as the servlet API.
mvn -B -ntp -s /opt/sieve/settings.xml -DskipTests \
  package \
  org.apache.maven.plugins:maven-dependency-plugin:3.11.0:copy-dependencies \
  -DincludeScope=compile -DoutputDirectory="$SIEVE_BUILD/deps" || exit 1

# A module is a folder with a pom.xml. Its compiled classes are in target/classes and its
# sources in src/main/java. Paths with characters outside this set are left out, so the
# JSON needs no escaping. The scan step checks every path again.
safe='^[A-Za-z0-9._/-]*$'
classes=""
sources=""
find . -name pom.xml -not -path '*/target/*' | sort > /tmp/poms || exit 1
while IFS= read -r pom; do
  module=$(dirname "$pom" | sed 's#^\./##; s#^\.$##')
  if [ -n "$module" ] && ! printf '%s\n' "$module" | grep -Eq "$safe"; then
    echo "left out the module in $module: its path has unusual characters" >&2
    continue
  fi
  prefix=${module:+$module/}
  [ -d "${prefix}target/classes" ] && classes="$classes\"${prefix}target/classes\","
  [ -d "${prefix}src/main/java" ] && sources="$sources\"${prefix}src/main/java\","
done < /tmp/poms
printf '{"class_dirs": [%s], "source_dirs": [%s]}\n' "${classes%,}" "${sources%,}" \
  > "$SIEVE_BUILD/java-build.json" || exit 1
cat "$SIEVE_BUILD/java-build.json"
