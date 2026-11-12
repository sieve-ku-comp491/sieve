# Semgrep with the semgrep-rules repository at a pinned commit. Changing either version means
# changing the tag in plugin.toml, because the tag names both (docs/interfaces.md). The base
# image is pinned by digest too, since a tag can be pushed again.
FROM semgrep/semgrep:1.183.0@sha256:2e45517a85e13a9cca14a2a00df6bb48affd66b8ebfae1b0991cd57578362fb0

ARG RULES_COMMIT=16b9e6d45f10649f6a531ec4838ed9924372c3bc

# Fetching the commit by its full hash checks the content, and .git is dropped afterwards.
RUN git init -q /opt/semgrep-rules \
 && git -C /opt/semgrep-rules fetch -q --depth 1 https://github.com/semgrep/semgrep-rules.git "$RULES_COMMIT" \
 && git -C /opt/semgrep-rules checkout -q FETCH_HEAD \
 && test "$(git -C /opt/semgrep-rules rev-parse HEAD)" = "$RULES_COMMIT" \
 && rm -rf /opt/semgrep-rules/.git

COPY --chmod=755 run.sh /opt/sieve/run.sh

USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["/opt/sieve/run.sh"]
