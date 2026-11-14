# Adapter test data

`semgrep-pygoat.sarif` is real output of the Semgrep plug-in (Semgrep 1.183.0, semgrep-rules at
commit 16b9e6d) on OWASP PyGoat at commit 2aa4cc14f251e4a780e94e200aed6b36a5b15c21, cut down to
the 9 results in `dockerized_labs/sql_injection_lab/app.py` and the 8 rules they use, and
indented for reading. The results and rules themselves were not edited.

`pygoat/` holds that one file from PyGoat at the same commit, under PyGoat's MIT license
(`pygoat/LICENSE.md`), so the adapter can read the flagged lines the way it reads a checkout.

`spotbugs-webgoat.sarif` is real output of the SpotBugs plug-in (SpotBugs 4.10.5, Find Security
Bugs 1.14.0, through the runner) on OWASP WebGoat v2026.5 at commit
7e198f39189f33e1912f7cbb60e24e42635ca06a, cut down to the 13 results in
`HashingAssignment.java` and `challenge5/Assignment5.java`, and indented for reading. The
results, the rules and the rest of the run were not edited. All 36 rules stay, because the
results point to them by `ruleIndex`.

`webgoat/` holds those two files from WebGoat at the same commit, at their paths in the
repository, under WebGoat's GPL-2.0-or-later license (`webgoat/LICENSE.txt`). SpotBugs writes
their paths relative to the source folder `src/main/java`, which `originalUriBaseIds` names as
`file:/src/src/main/java/`.
