# Bandit with the sarif extra. Changing Bandit means changing the tag in plugin.toml, because
# the tag names the version (docs/interfaces.md). The base image is pinned by digest, since a
# tag can be pushed again, and requirements.txt pins every package Bandit needs.
FROM python:3.14.10-slim@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f

COPY requirements.txt /opt/sieve/requirements.txt
RUN pip install --no-cache-dir --no-deps --disable-pip-version-check \
      -r /opt/sieve/requirements.txt \
 && pip check

COPY --chmod=755 run.sh /opt/sieve/run.sh

USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["/opt/sieve/run.sh"]
