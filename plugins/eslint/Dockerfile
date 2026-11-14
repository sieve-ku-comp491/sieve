# ESLint with eslint-plugin-security, typescript-eslint's parser and the SARIF formatter, at the
# versions in package-lock.json. Changing ESLint or eslint-plugin-security means changing the
# tag in plugin.toml, because the tag names both (docs/interfaces.md). The base image is
# Node.js 24, which Juice Shop v20.3.0 supports, pinned by digest since a tag can be pushed again.
FROM node:24.22.3-trixie-slim@sha256:af02d57b57719b9657a45199a79264a9437940cd55b3c7b3fc99615654f124a0

WORKDIR /opt/sieve
COPY package.json package-lock.json ./
# npm ci installs exactly the lock file. None of these packages needs an install script.
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
 && npm cache clean --force

COPY eslint.config.mjs scan.cjs ./
COPY --chmod=755 run.sh /opt/sieve/run.sh

USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["/opt/sieve/run.sh"]
