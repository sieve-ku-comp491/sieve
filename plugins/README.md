# Plug-ins

Each folder here is one analyzer, run by the plug-in runner in `backend/app/runner/` through the plug-in contract in docs/interfaces.md: the code read-only at /src, SARIF written to /out, no network.

| Plug-in | Tool | Rules | Image |
|---|---|---|---|
| `semgrep` | Semgrep 1.183.0 | semgrep-rules at commit `16b9e6d`, security rules for Python, Java, JavaScript and TypeScript | `sieve-plugin-semgrep:1.183.0-16b9e6d` |
| `bandit` | Bandit 1.9.4 with the `sarif` extra | built in, all of them | `sieve-plugin-bandit:1.9.4` |
| `eslint` | ESLint 10.14.0, with typescript-eslint 8.72.1's parser and TypeScript 6.0.3 | eslint-plugin-security 4.2.1, its recommended set, on JavaScript and TypeScript files | `sieve-plugin-eslint:10.14.0-security4.2.1` |
| `gitleaks` | Gitleaks 8.30.1 | built in, on every file of the checkout, run with `--redact` | `sieve-plugin-gitleaks:8.30.1` |
| `spotbugs` | SpotBugs 4.10.5 with Find Security Bugs 1.14.0, on classes built with Maven 3.9.16 and JDK 25 | the `SECURITY` category: the Find Security Bugs patterns and the few SpotBugs patterns in it | `sieve-plugin-spotbugs:4.10.5-fsb1.14.0`, and `sieve-plugin-spotbugs-build:jdk25-3.9.16` for the build step |

## Building the images

The runner never builds or pulls images. It runs the image named in each `plugin.toml`, and a run whose image is missing fails with the reason `runner_error`. Build each image once, with the tag from its manifest:

    docker build -t sieve-plugin-semgrep:1.183.0-16b9e6d plugins/semgrep
    docker build -t sieve-plugin-bandit:1.9.4 plugins/bandit
    docker build -t sieve-plugin-eslint:10.14.0-security4.2.1 plugins/eslint
    docker build -t sieve-plugin-gitleaks:8.30.1 plugins/gitleaks
    docker build --target build -t sieve-plugin-spotbugs-build:jdk25-3.9.16 plugins/spotbugs
    docker build --target scan -t sieve-plugin-spotbugs:4.10.5-fsb1.14.0 plugins/spotbugs

Building needs network, to fetch the tool and its rules. Scans don't. The Bandit image installs the exact versions in `plugins/bandit/requirements.txt`, Bandit and every package it needs. The ESLint image installs its npm packages from the committed `package-lock.json` with `npm ci`, and lints with its own `eslint.config.mjs`: it never loads a configuration file, parser or plug-in from the scanned repository, because those are code.

## Runner settings

The worker reads these from its environment. The defaults fit the Compose setup in docs/architecture.md.

| Variable | Default | Meaning |
|---|---|---|
| `SIEVE_DATA_DIR` | `/data` | where the worker mounts the `sieve-data` volume. Checkouts are in `scans/<scan ID>/src`, and each run writes to `runs/<run ID>/`. |
| `SIEVE_DATA_VOLUME` | `sieve-data` | the volume that analyzer containers get folders of, as volume subpaths (Docker Engine 26 or later). Empty means the folders of `SIEVE_DATA_DIR` are mounted as host folders instead, for runs outside the worker container. |
| `SIEVE_BUILD_NETWORK` | `sieve-build` | the network of build steps. It must be an internal bridge network with `com.docker.network.bridge.inhibit_ipv4` set and no IPv6, so that its bridge has no address of the host, or the runner refuses to start a build on it. Compose creates it with `maven-proxy` on it, which is the build's only way to Maven Central: `docker compose up -d maven-proxy` is enough for runs outside the worker. |
| `DOCKER_SOCKET` | the Docker SDK's default | the Docker Engine socket |

## Tests

`backend/tests/test_runner.py` checks the runner with a fake engine and needs no Docker. `test_runner_docker.py` runs the small test plug-in in `backend/tests/plugin_fixture/` on the real Docker Engine, and is skipped when Docker isn't running. It also builds `maven-proxy` and checks that a build step can open a tunnel to Maven Central through it and to no other host name. `test_semgrep_plugin.py` scans a small vulnerable file with the Semgrep image, and `test_bandit_plugin.py` and `test_eslint_plugin.py` do the same with the Bandit and ESLint images. `test_gitleaks_plugin.py` does the same with the Gitleaks image and a fake key made for the test. All of them are skipped when the image isn't built, which includes CI.
