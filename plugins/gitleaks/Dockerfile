# Gitleaks with its built-in rules. Changing the version means changing the tag in plugin.toml
# (docs/interfaces.md). The base image is pinned by digest, since a tag can be pushed again.
FROM ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f

COPY --chmod=755 run.sh /opt/sieve/run.sh

USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["/opt/sieve/run.sh"]
