# Plug-ins

Each folder here is one analyzer, run by the plug-in runner in `backend/app/runner/` through the plug-in contract in docs/interfaces.md: the code read-only at /src, SARIF written to /out, no network.

| Plug-in | Tool | Rules | Image |
|---|---|---|---|
| `semgrep` | Semgrep 1.183.0 | semgrep-rules at commit `16b9e6d`, security rules for Python, Java, JavaScript and TypeScript | `sieve-plugin-semgrep:1.183.0-16b9e6d` |
| `bandit` | Bandit 1.9.4 with the `sarif` extra | built in, all of them | `sieve-plugin-bandit:1.9.4` |

## Building the images

The runner never builds or pulls images. It runs the image named in each `plugin.toml`, and a run whose image is missing fails with the reason `runner_error`. Build each image once, with the tag from its manifest:

    docker build -t sieve-plugin-semgrep:1.183.0-16b9e6d plugins/semgrep
    docker build -t sieve-plugin-bandit:1.9.4 plugins/bandit

Building needs network, to fetch the tool and its rules. Scans don't. The Bandit image installs the exact versions in `plugins/bandit/requirements.txt`, Bandit and every package it needs.

## Runner settings

The worker reads these from its environment. The defaults fit the Compose setup in docs/architecture.md.

| Variable | Default | Meaning |
|---|---|---|
| `SIEVE_DATA_DIR` | `/data` | where the worker mounts the `sieve-data` volume. Checkouts are in `scans/<scan ID>/src`, and each run writes to `runs/<run ID>/`. |
| `SIEVE_DATA_VOLUME` | `sieve-data` | the volume that analyzer containers get folders of, as volume subpaths (Docker Engine 26 or later). Empty means the folders of `SIEVE_DATA_DIR` are mounted as host folders instead, for runs outside the worker container. |
| `SIEVE_BUILD_NETWORK` | `sieve-build` | the network of build steps. It must be an internal bridge network, such as one made with `docker network create --internal sieve-build`, or the runner refuses to start a build on it. |
| `DOCKER_SOCKET` | the Docker SDK's default | the Docker Engine socket |

## Tests

`backend/tests/test_runner.py` checks the runner with a fake engine and needs no Docker. `test_runner_docker.py` runs the small test plug-in in `backend/tests/plugin_fixture/` on the real Docker Engine, and is skipped when Docker isn't running. `test_semgrep_plugin.py` scans a small vulnerable file with the Semgrep image, and `test_bandit_plugin.py` does the same with the Bandit image. Both are skipped when the image isn't built, which includes CI.
