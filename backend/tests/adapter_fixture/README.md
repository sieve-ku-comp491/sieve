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

`pygoat/` holds those two files from PyGoat at the same commit, under PyGoat's MIT license
(`pygoat/LICENSE.md`), so the adapter can read the flagged lines the way it reads a checkout.
