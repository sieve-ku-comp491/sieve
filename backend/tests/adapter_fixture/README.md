# Adapter test data

`semgrep-pygoat.sarif` is real output of the Semgrep plug-in (Semgrep 1.183.0, semgrep-rules at
commit 16b9e6d) on OWASP PyGoat at commit 2aa4cc14f251e4a780e94e200aed6b36a5b15c21, cut down to
the 9 results in `dockerized_labs/sql_injection_lab/app.py` and the 8 rules they use, and
indented for reading. The results and rules themselves were not edited.

`pygoat/` holds that one file from PyGoat at the same commit, under PyGoat's MIT license
(`pygoat/LICENSE.md`), so the adapter can read the flagged lines the way it reads a checkout.

`eslint-juice-shop.sarif` is real output of the ESLint plug-in (ESLint 10.14.0,
eslint-plugin-security 4.2.1) on OWASP Juice Shop v20.3.0, commit
f189f521266f42c6bd05884468292000cee852ed, cut down to the 9 results in the six files under
`juice-shop/`. The whole run had 1,540 results in 657 files. The driver and its 7 rules are
complete, so each `ruleIndex` is right. `artifacts` keeps only the six files, so the `index` in
each `artifactLocation` still points into the run's full list of 657 files, and `invocations`,
the formatter's 39 parse errors from the deliberately incomplete files in
`data/static/codefixes/`, is left out. The results themselves were not edited.

`juice-shop/` holds those six files and Juice Shop's MIT license (`juice-shop/LICENSE`), byte
for byte from the commit's Git objects, with LF line endings. `EffectComposer.js` is a file of
three.js that Juice Shop includes.

The expected values in `test_adapters_eslint.py` were worked out by hand: rule, lines, columns
and level read from the SARIF file, CWEs from the table in docs/finding-format.md, and the
flagged lines read from the files and fed to the reference code for the fingerprint and context
hash in docs/finding-format.md, not to the adapter.
