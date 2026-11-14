# Test data for the Gitleaks adapter (tests/adapter_fixture/README.md). The key is random
# and belongs to no account. .gitleaks.toml allows this file, so the secret scan in CI passes.
import os

DEBUG = os.environ.get("DEBUG") == "1"
api_key = "cKVrPQf3eD4W5LU1MfHYbG2QqpQGACEC"
TIMEOUT_SECONDS = 30
