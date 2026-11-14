# Adapter test data

`semgrep-pygoat.sarif` is real output of the Semgrep plug-in (Semgrep 1.183.0, semgrep-rules at
commit 16b9e6d) on OWASP PyGoat at commit 2aa4cc14f251e4a780e94e200aed6b36a5b15c21, cut down to
the 9 results in `dockerized_labs/sql_injection_lab/app.py` and the 8 rules they use, and
indented for reading. The results and rules themselves were not edited.

`pygoat/` holds that one file from PyGoat at the same commit, under PyGoat's MIT license
(`pygoat/LICENSE.md`), so the adapter can read the flagged lines the way it reads a checkout.

`gitleaks-pygoat.sarif` is real output of the Gitleaks plug-in (Gitleaks 8.30.1, run with
`--redact`) on PyGoat at the same commit, cut down to the 5 results in
`dockerized_labs/auth_failure_lab/app.py` and `dockerized_labs/dependency_attack_lab/app.py` and
the one rule they use, and indented for reading. Every snippet in it is `REDACTED`. `pygoat/`
holds both files from PyGoat byte for byte.

`fake-key/settings.py` holds a key made at random for the test, which belongs to no account.
`gitleaks-fake-key.sarif` is the Gitleaks plug-in's real output on that folder, cut down the same
way.

The files with secrets in them are listed in `.gitleaks.toml` at the repository root, so the
secret scan in CI still finds nothing. The SARIF files contain no secret and aren't listed.

The fingerprints and context hashes in `test_adapters_gitleaks.py` were computed with the code in
docs/finding-format.md, not with the adapter: rule, file and lines read from the SARIF file, every
flagged line replaced by `REDACTED`, and the occurrence counted by line among the results with the
same rule and file.
