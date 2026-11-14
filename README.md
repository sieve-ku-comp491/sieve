# Sieve

Sieve is a pluggable framework for white-box security testing. Static analyzers plug in through SARIF, an AI agent removes duplicate findings, checks for false positives and scores severity, and a person approves each finding before Sieve writes a report. It is our COMP 491 project at Koç University. The project website is at https://sieve-ku-comp491.github.io.

The design documents are in docs/. How we write commits, issues and pull requests is in CONTRIBUTING.md.

## Setup

You need Python 3.14, Docker with Docker Compose, and git.

### Install Python 3.14

On macOS with Homebrew:

    brew install python@3.14

Check it with `python3.14 --version`. On other systems, download Python 3.14 from python.org.

### Create a virtual environment and install the dependencies

Run this in the repo root:

    python3.14 -m venv .venv
    source .venv/bin/activate
    pip install -r backend/requirements-dev.txt

`requirements.txt` has the packages the back end runs on, and `requirements-dev.txt` adds the test and lint tools. Every package is pinned to an exact version, so all of our machines, CI and the Docker image use the same ones. If you add a package, pin its exact version in the same pull request.

### Run the tests

    cd backend
    pytest
    ruff check .

### Start the environment

Copy the example environment file and fill in the values:

    cp .env.example .env

`POSTGRES_USER`, `POSTGRES_PASSWORD` and `POSTGRES_DB` can be anything you like for local development. Set `DATABASE_URL` to match them, for example `postgresql://sieve:secret@db:5432/sieve` when the user is `sieve`, the password is `secret` and the database is `sieve`. The two API keys are only needed once the LLM provider interface exists. Set `SIEVE_API_TOKEN` to a random value, which every request to the API must carry, for example the output of:

    python3 -c "import secrets; print(secrets.token_urlsafe(32))"

Never commit `.env`.

Build the plug-in images once, as plugins/README.md describes. Then start the back end, the worker and PostgreSQL with one command:

    docker compose up --build

The back end is at http://localhost:8000. Before it starts, it creates or updates the database tables. Check that it is running, with the token from `.env`:

    curl -H "Authorization: Bearer <your SIEVE_API_TOKEN>" http://localhost:8000/health

It should answer `{"status":"ok"}`. Without the token, or with a `Host` other than `localhost` or `127.0.0.1`, the API refuses the request (docs/architecture.md). The web app at http://localhost:8080 adds the token itself. The API specification is in docs/openapi.json. The database lives in a Docker volume named `db-data`, so it survives restarts. To stop everything, press Ctrl+C, or run `docker compose down` from another terminal. To delete the database too, run `docker compose down -v`.

### Scope file

`scope.toml` in the repo root lists the repositories Sieve may scan (requirement F2). The API refuses a scan of any other repository before it clones anything or starts any container, and the worker clones the URL written in the scope file, not the one in the request.

The scope file is for public code only. Sieve sends code from these repositories to hosted LLM APIs, so never list confidential code, such as a client's private repository (requirement N4). Sieve clones without credentials, so a private repository fails even when it is listed.

Each entry has the repository's URL and the reason we may scan it: it is our own code, a deliberately vulnerable application, source code that a bug bounty program lists in its scope, or public code at a commit with a published CVE, scanned for our evaluation:

    [[repository]]
    url = "https://github.com/adeyosemanputra/pygoat"
    reason = "OWASP PyGoat, a deliberately vulnerable application"

Rules:

- A URL starts with `https://` and has no user name or password, port, query or fragment. URLs are compared with the host in lowercase and without a trailing `/` or `.git`, so `https://GitHub.com/adeyosemanputra/pygoat.git` matches the entry above. An entry allows exactly one repository, not the owner's other repositories.
- The commit must be on a branch or tag of the listed repository. GitHub serves a commit pushed to any fork through the original repository's URL, so a commit outside its branches and tags is refused.
- An entry without a `reason`, or with a URL that breaks these rules, stops the file from loading, and every scan is refused until it is fixed.

The API and the worker read the file on every scan, so an edit takes effect without a restart. Compose mounts it read-only at `/etc/sieve/scope.toml`.

### Scan a repository from the command line

The command-line interface calls the API with the token. It needs only Python 3.14, no packages. From `backend/`, with the environment started:

    python -m app.cli scan https://github.com/adeyosemanputra/pygoat --commit 2aa4cc1

`--commit` takes a commit hash, a branch or a tag, and the default branch is used without it. The command prints each step until the scan ends: the commit and the languages found, and each plug-in's status. The worker runs Semgrep, Bandit, ESLint and Gitleaks as the languages need. Then list the findings with the scan ID it printed:

    python -m app.cli findings <scan ID>

`--tool semgrep` keeps one plug-in's findings, and `--json` prints them as JSON. The CLI reads `SIEVE_API_TOKEN` from the environment, or from the `.env` file in the current folder or a folder above it, and reaches the API at `SIEVE_API_URL`, `http://127.0.0.1:8000` by default. `python -m app.cli scan https://github.com/OWASP/NodeGoat` shows the refusal for a repository that is not in the scope file. Scans can also be started with `POST /scans` (docs/openapi.json).

Each scan's checkout and each plug-in run's SARIF file and log stay in the `sieve-data` volume (docs/architecture.md). The worker is the only service with the Docker socket.

### Load a saved Semgrep run of PyGoat

Besides a scan, findings can get into the store from a SARIF file that the Semgrep plug-in wrote earlier. You need the SARIF file (`results.sarif`, and `scan-info.json` if you have it) and the PyGoat files it scanned, at commit `2aa4cc14f251e4a780e94e200aed6b36a5b15c21`. Put them in one folder, for example `~/sieve-import`:

    git clone https://github.com/adeyosemanputra/pygoat ~/pygoat
    mkdir -p ~/sieve-import/src
    git -C ~/pygoat archive 2aa4cc14f251e4a780e94e200aed6b36a5b15c21 | tar -x -C ~/sieve-import/src
    cp results.sarif scan-info.json ~/sieve-import/

Then, with the environment started, run from the repo root:

    docker compose run --rm \
      -v "$HOME/sieve-import:/import:ro" \
      worker python -m app.store load-sarif \
      --manifest /plugins/semgrep/plugin.toml \
      --sarif /import/results.sarif --checkout /import/src \
      --repo-url https://github.com/adeyosemanputra/pygoat \
      --commit 2aa4cc14f251e4a780e94e200aed6b36a5b15c21

It prints the new scan's ID and the number of findings, 153 for the run in docs/ui-mockups.md. The scan then shows up in `GET /scans`, and its findings in `GET /scans/<scan ID>/findings`. Each load is a new scan.
