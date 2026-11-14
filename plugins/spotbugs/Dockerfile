# The SpotBugs plug-in has two images, built from the two targets of this file with the tags
# in plugin.toml:
#
#   docker build --target build -t sieve-plugin-spotbugs-build:jdk25-3.9.16 plugins/spotbugs
#   docker build --target scan -t sieve-plugin-spotbugs:4.10.5-fsb1.14.0 plugins/spotbugs
#
# build: JDK 25 and Maven 3.9.16, for the build step (build.sh). Maven 3.10.0 came out on
# 12 Nov 2026, so we kept the 3.9 line we tested.
# scan: SpotBugs 4.10.5 with Find Security Bugs 1.14.0 on a Java 25 runtime (run.sh), with
# Python for java_build.py. The runtime is copied from the Temurin image, the way that image's
# documentation describes for other base images.
#
# Changing a version means changing the image tags in plugin.toml, because the tags name the
# versions (docs/interfaces.md). Base images are pinned by digest and downloads by SHA-256.

FROM maven:3.9.16-eclipse-temurin-25-noble@sha256:93b8a14ea2f412782e4e842651273b4d903e35cc496284f178fbbe2d67d00976 AS build

# The image's own entry point copies settings into /root/.m2, which a non-root build can't use.
ENV MAVEN_CONFIG=""
COPY settings.xml /opt/sieve/settings.xml
COPY --chmod=755 build.sh /opt/sieve/build.sh
# A new, empty Maven cache volume takes this folder's owner when it is first mounted.
RUN mkdir -p /cache/m2 && chown 10001:10001 /cache/m2

USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["/opt/sieve/build.sh"]


FROM eclipse-temurin:25-jre-noble@sha256:e3b6f7887a50f20d8f07abf279d8a81a5953fb398a9555bd9edd56b9bd15968c AS jre

FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS scan

ENV JAVA_HOME=/opt/java/openjdk
ENV PATH=/opt/java/openjdk/bin:$PATH
COPY --from=jre /opt/java/openjdk /opt/java/openjdk

# SpotBugs 4.10.5 from its GitHub release and Find Security Bugs 1.14.0 from Maven Central. The
# hashes are the one GitHub lists for the release asset and the one of the jar in Find Security
# Bugs' own command-line package, which matches the SHA-1 on Maven Central.
ADD --checksum=sha256:cce3244900cc215ccd9f5a8db29ed9468fc47824faf662f4fad005343d96007e \
    https://github.com/spotbugs/spotbugs/releases/download/4.10.5/spotbugs-4.10.5.tgz /tmp/spotbugs.tgz
ADD --checksum=sha256:6fa340344fa433ff46c2985dab1010e8bc739f9395c983594a5240095e92abc8 \
    https://repo.maven.apache.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/1.14.0/findsecbugs-plugin-1.14.0.jar \
    /opt/findsecbugs/findsecbugs-plugin-1.14.0.jar
RUN tar -xzf /tmp/spotbugs.tgz -C /opt \
 && mv /opt/spotbugs-4.10.5 /opt/spotbugs \
 && rm /tmp/spotbugs.tgz \
 && chmod 644 /opt/findsecbugs/findsecbugs-plugin-1.14.0.jar

COPY security-only.xml /opt/sieve/security-only.xml
COPY java_build.py /opt/sieve/java_build.py
COPY --chmod=755 run.sh /opt/sieve/run.sh

USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["/opt/sieve/run.sh"]
