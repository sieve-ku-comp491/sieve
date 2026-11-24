# Adapter test data

`semgrep-pygoat.sarif` is real output of the Semgrep plug-in (Semgrep 1.183.0, semgrep-rules at
commit 16b9e6d) on OWASP PyGoat at commit 2aa4cc14f251e4a780e94e200aed6b36a5b15c21, cut down to
the 9 results in `dockerized_labs/sql_injection_lab/app.py` and the 8 rules they use, and
indented for reading. The results and rules themselves were not edited.

`bandit-pygoat.sarif` is real output of the Bandit plug-in (Bandit 1.9.4) on the same commit of
PyGoat, cut down to the 9 results in `dockerized_labs/sql_injection_lab/app.py` and
`dockerized_labs/dependency_attack_lab/app.py`, and to the metrics of those two files. All 20
rules are kept, because the results find their rule by `ruleIndex`. The results and rules
themselves were not edited. The expected values in `test_adapters_bandit.py` were read from this
file and the two source files by hand, and the fingerprints and context hashes were computed
with the formulas printed in docs/finding-format.md, not with the adapter.

`pygoat/` holds the PyGoat files these tests read, at the same commit, under PyGoat's MIT license
(`pygoat/LICENSE.md`), so the adapter can read the flagged lines the way it reads a checkout.

`eslint-juice-shop.sarif` is real output of the ESLint plug-in (ESLint 10.14.0,
eslint-plugin-security 4.2.1) on OWASP Juice Shop v20.3.0, commit
f189f521266f42c6bd05884468292000cee852ed, cut down to the 9 results in the six files under
`juice-shop/`. The whole run had 1,540 results in 657 files, 39 of which don't parse, the
deliberately incomplete files in `data/static/codefixes/`. The driver and its 7 rules are
complete, so each `ruleIndex` is right. `artifacts` is the run's full list of 657 file URIs,
one per line, so the `index` in each `artifactLocation` is right too. `invocations`, the
formatter's 39 parse errors, is left out. The results themselves were not edited.

`juice-shop/` holds those six files and Juice Shop's MIT license (`juice-shop/LICENSE`), byte
for byte from the commit's Git objects, with LF line endings. `EffectComposer.js` is a file of
three.js that Juice Shop includes.

The expected values in `test_adapters_eslint.py` were worked out by hand: rule, lines, columns
and level read from the SARIF file, CWEs from the table in docs/finding-format.md, and the
flagged lines read from the files and fed to the reference code for the fingerprint and context
hash in docs/finding-format.md, not to the adapter.

`gitleaks-pygoat.sarif` is real output of the Gitleaks plug-in (Gitleaks 8.30.1, run with
`--redact`) on PyGoat at the same commit, cut down to the 5 results in
`dockerized_labs/auth_failure_lab/app.py` and `dockerized_labs/dependency_attack_lab/app.py` and
the one rule they use, and indented for reading. Every snippet in it is `REDACTED`. Both files
are in `pygoat/`, byte for byte.

`fake-key/settings.py` holds a key made at random for the test, which belongs to no account.
`gitleaks-fake-key.sarif` is the Gitleaks plug-in's real output on that folder, cut down the same
way.

The files with secrets in them are listed in `.gitleaks.toml` at the repository root, so the
secret scan in CI still finds nothing. The SARIF files contain no secret and aren't listed.

The fingerprints and context hashes in `test_adapters_gitleaks.py` were computed with the code in
docs/finding-format.md, not with the adapter: rule, file and lines read from the SARIF file, every
flagged line replaced by `REDACTED`, and the occurrence counted by line among the results with the
same rule and file.

`spotbugs-webgoat.sarif` is real output of the SpotBugs plug-in (SpotBugs 4.10.5, Find Security
Bugs 1.14.0, through the runner) on OWASP WebGoat v2026.5 at commit
7e198f39189f33e1912f7cbb60e24e42635ca06a, cut down to the 9 results in
`HashingAssignment.java` and `challenge5/Assignment5.java`, and indented for reading. The
results, the rules and the rest of the run were not edited. All 35 rules stay, because the
results point to them by `ruleIndex`. The run is from the plug-in with SPRING_ENDPOINT left
out (`plugins/spotbugs/security-only.xml`): 219 results on WebGoat instead of 455, each of
them the same as in the run before that change, apart from `ruleIndex`.

`webgoat/` holds those two files from WebGoat at the same commit, at their paths in the
repository, under WebGoat's GPL-2.0-or-later license (`webgoat/LICENSE.txt`). SpotBugs writes
their paths relative to the source folder `src/main/java`, which `originalUriBaseIds` names as
`file:/src/src/main/java/`.
