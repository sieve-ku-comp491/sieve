# Sieve

Sieve is a pluggable framework for white-box security testing. Static analyzers plug in through SARIF, an AI agent removes duplicate findings, checks for false positives and scores severity, and a person approves each finding before Sieve writes a report. It is our COMP 491 project at Koç University.

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

`POSTGRES_USER`, `POSTGRES_PASSWORD` and `POSTGRES_DB` can be anything you like for local development. Set `DATABASE_URL` to match them, for example `postgresql://sieve:secret@db:5432/sieve` when the user is `sieve`, the password is `secret` and the database is `sieve`. The two API keys are only needed once the LLM provider interface exists. Never commit `.env`.

Then start the back end and PostgreSQL with one command:

    docker compose up --build

The back end is at http://localhost:8000. Check that it is running:

    curl http://localhost:8000/health

It should answer `{"status":"ok"}`. FastAPI also serves the API documentation at http://localhost:8000/docs. The database lives in a Docker volume named `db-data`, so it survives restarts. To stop everything, press Ctrl+C, or run `docker compose down` from another terminal. To delete the database too, run `docker compose down -v`.
