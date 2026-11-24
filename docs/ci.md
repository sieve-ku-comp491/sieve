# Continuous integration

`.github/workflows/ci.yml` runs on every pull request and every push to main. It catches broken code and leaked API keys before they reach main (requirement N4), and checks that every image and dependency has a fixed version (requirement N6, test 4). Its four jobs run in parallel:

| Job | What it does | Fails when |
|---|---|---|
| Back end (ruff, pytest) | sets up Python 3.14, installs `backend/requirements-dev.txt` with pip, runs `ruff check` and `pytest` in `backend/`, with a PostgreSQL 17 service container for the findings store and call log tests (`SIEVE_TEST_DATABASE_URL`). Skipped while `backend/requirements-dev.txt` doesn't exist. | a lint error or a failing test |
| Front end (ESLint) | runs `npm ci` and `npm run lint` in `frontend/`. Skipped while `frontend/package.json` doesn't exist. | an ESLint error |
| Secret scan (Gitleaks) | checks out the full git history and runs Gitleaks 8.30.1, the version pinned in docs/requirements.md | Gitleaks finds anything, also in an old commit whose file was deleted later |
| Version pins | runs `scripts/check_pins.py` | a `FROM` line or a Compose image without a version or with `latest`, a requirements line without `==`, or a `package.json` without a committed `package-lock.json` |

The Gitleaks job uses the Gitleaks CLI, because gitleaks-action needs a license key for repositories owned by an organization.

Gitleaks reads `.gitleaks.toml` in the repository root. It keeps the built-in rules and allows only the adapter test files that hold secrets on purpose, each by its full path (backend/tests/adapter_fixture/README.md). A file added to that list is skipped in every commit of the history, so list single files, never folders. The job fetches every branch, so a test file with a secret on any open branch fails every pull request until it is listed here. A single line in a test can be allowed with a `gitleaks:allow` comment instead.

## Speed

pip and npm downloads are cached between runs (the `cache` option of actions/setup-python and actions/setup-node), each job installs only what it needs, and a new push to a branch cancels the run still going for the previous one. The longest job is the back end, and on the current code each job needs well under a minute of work, so the workflow should finish in one to two minutes, under the 5 minutes of issue #16. Check the time on the first pull request. GitHub bills each job separately and rounds it up to a whole minute, so one run costs about four of the free plan's 2,000 minutes a month for private repositories, about 500 runs.

## Checked before the first pull request

- On Python 3.14.6 with the exact versions in `backend/requirements-dev.txt` from Daniyal's pull request #31, `ruff check` reports nothing and `pytest` passes `tests/test_health.py`.
- Gitleaks 8.30.1 finds nothing in the 39 commits of all open pull requests on 11 Nov 2026, so the secret scan passes on the current history.
- `scripts/check_pins.py` passes on the back end, the front end and `docker-compose.yml`, and reports a planted unpinned image, `latest` tag, requirement and missing lock file.

## Testing that Gitleaks stops a leaked key

Issue #16 asks for a throwaway branch with a fake API key that fails the Gitleaks step. Generate the key, so nobody commits a real one by mistake. It has the shape of a GitHub token but belongs to no account.

    git switch main
    git pull
    git switch -c 16-gitleaks-fake-key
    python3 -c "import secrets, string; print('GITHUB_TOKEN = \"ghp_' + ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36)) + '\"')" > fake_secret.py
    git add fake_secret.py
    git commit -m "test(ci): add fake key to check the gitleaks step"
    git push -u origin 16-gitleaks-fake-key

Open a draft pull request from the branch, but don't merge it. The "Secret scan (Gitleaks)" job fails with the rule `github-pat`, and the other jobs pass. Take a screenshot for issue #16, close the pull request, and delete the branch:

    git switch main
    git push origin --delete 16-gitleaks-fake-key
    git branch -D 16-gitleaks-fake-key

If GitHub's push protection blocks the push, GitHub caught the key before Gitleaks could. Then use a generic key instead, which push protection doesn't know but Gitleaks flags with the rule `generic-api-key`:

    python3 -c "import secrets, string; print('api_key = \"' + ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32)) + '\"')" > fake_secret.py

A deleted branch's commits stay on GitHub for a while but are no longer in any branch, so the full-history scan of later pull requests doesn't see them.
