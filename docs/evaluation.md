# Evaluation

The evaluation harness collects every dataset with known answers and computes the metrics that measure each AI step against a baseline (objective O4, Table 5 of the proposal). The baseline run (T6.2) and the full evaluation (T6.4) both use it. The code is in `backend/app/eval/`, and it uses only the Python standard library and git.

## Datasets and target applications

`backend/app/eval/sources.toml` pins each source to a full commit hash. The versions are the ones in docs/requirements.md, "Analyzers, datasets and target applications", and `tests/test_eval_sources.py` fails if a source's version, or the commit of a source pinned by commit, differs from its row there. WebGoat and Juice Shop are pinned by tag in docs/requirements.md, and on 12 Nov 2026 we checked with `git ls-remote` that the tags point to the commits in `sources.toml`.

| Name | Kind | Version | Commit | Used for |
|---|---|---|---|---|
| `benchmark-java` | dataset | OWASP Benchmark for Java 1.2 | `0119da404a3418bc337beb529b72ae755f018f97` | false-positive check, Java |
| `benchmark-python` | dataset | OWASP Benchmark for Python 0.1 | `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` | false-positive check, Python |
| `cwe-bench-java` | dataset | CWE-Bench-Java | `afe0ebd0adc237abb46255f9cd479b1d71819136` | severity |
| `pygoat` | target | OWASP PyGoat | `2aa4cc14f251e4a780e94e200aed6b36a5b15c21` | duplicates, reports, PoC check |
| `webgoat` | target | OWASP WebGoat v2026.5 | `7e198f39189f33e1912f7cbb60e24e42635ca06a` | duplicates, reports, PoC check |
| `juice-shop` | target | OWASP Juice Shop v20.3.0 | `f189f521266f42c6bd05884468292000cee852ed` | duplicates, reports, PoC check, labeled sample |

The tags of WebGoat and Juice Shop are pinned by the commit they pointed to on 12 Nov 2026, so a moved tag can't change what we test.

## Running it

From `backend/`, with the virtual environment from the README:

    python -m app.eval fetch                       # check out every source at its commit
    python -m app.eval expected                    # write the expected results as CSV
    python -m app.eval neutral benchmark-java      # make a neutral copy, see below
    python -m app.eval neutral benchmark-python
    python -m app.eval cves                        # look up CVSS vectors in the NVD
    python -m app.eval findings --help             # analyzer SARIF files as a findings CSV
    python -m app.eval metrics --help              # the metric scripts
    python -m app.eval pilot --help                # the pilot triage, see below

Everything the commands write goes to `eval-data/` in the repository root, which is in .gitignore, except `cves`, which rewrites the committed `backend/app/eval/cves.csv` unless `--out` names another file. Set `SIEVE_EVAL_DIR` to use another folder. `fetch` checks out each source without history, about 350 MB in all, most of it the Java Benchmark, and doesn't download a source that is already at its commit. It always leaves the folder exactly as the commit has it: after a pin changes, the files that only the old version had are removed, and files changed or added by hand are restored or removed. `expected`, `neutral` and `cves` stop and say to run `fetch` when a source isn't checked out at its pinned commit, so their output never records a commit that the files don't match. `cves` waits 6.5 seconds between NVD requests, as the NVD allows without an API key, so it takes about 13 minutes. With `NVD_API_KEY` set, it waits 0.7 seconds.

## Expected results

`python -m app.eval expected` writes one CSV per dataset to `eval-data/expected/`, all in one format:

| Column | Meaning |
|---|---|
| `dataset` | the source name |
| `case_id` | the test case, such as `BenchmarkTest00001`, or the CVE ID |
| `cwe` | the expected CWE, as `CWE-22`, the form findings use |
| `file` | path from the root of the source |
| `start_line`, `end_line` | the lines of the vulnerable code. Empty when the whole file is the case. |
| `method` | the vulnerable method, for CVEs |
| `commit` | the commit the file and the lines refer to |
| `real` | `true` for a real vulnerability, `false` for code that only looks like one |

| Dataset | Rows | Real | What a row is |
|---|---|---|---|
| `benchmark-java` | 2,740 | 1,415 | one test case, which is one file, in 11 categories |
| `benchmark-python` | 1,230 | 452 | one test case, which is one file, in 14 categories |
| `cwe-bench-java` | 996 | 996 | one method that the CVE's fix changed, for 117 CVEs |

The Benchmark counts match docs/requirements.md. Each Benchmark case is judged as a whole file, the way the Benchmark's own scorecards do it.

Three things about CWE-Bench-Java that the evaluation has to keep in mind:

- Its `fix_info.csv` gives the line numbers in the fix commit, not in the vulnerable one: 995 of the 996 rows point to one of the CVE's fix commits. So each row keeps that commit and the method name, and T6.4 matches a finding by file and method, or maps the lines to the vulnerable commit, which is in `cves.csv`.
- 15 rows have no method lines and use the class lines, and 8 of those have no class lines either, so they cover the whole file.
- The two data files don't always use the same project slug for a CVE, so the rows are joined by CVE ID. 147 rows of `fix_info.csv` belong to CVEs that aren't among the 120 projects and are left out, and 3 of the 120 CVEs (CVE-2020-27219, CVE-2021-44667, CVE-2022-2712) have no location, which leaves 117.

## CVEs for the severity check

`backend/app/eval/cves.csv` lists the CVEs of CWE-Bench-Java with their published CVSS vector, so the severity evaluation doesn't depend on the NVD changing later. It is committed, and `python -m app.eval cves` makes it again. The vulnerable files, methods and lines of each CVE are in the expected results, `eval-data/expected/cwe-bench-java.csv`, one row per location (see above).

| Column | Meaning |
|---|---|
| `cve_id`, `cwe`, `project`, `repository` | from CWE-Bench-Java |
| `vulnerable_commit` | the commit where the vulnerability can be reproduced, the one we scan |
| `cvss_version`, `cvss_vector`, `cvss_score` | the published vector. Empty when the NVD has no CVSS 3 or 4 vector. |
| `cvss_source` | who published it, `nvd@nist.gov` for the NVD's own analysts |
| `checked_on` | the day we read it from the NVD |

For each CVE we take the NVD's own vector (the Primary source) in the newest CVSS version it has, and only when the NVD has none, the newest vector from another source such as GitHub. CVEs with only a CVSS 2.0 vector get no vector, because the severity step picks CVSS 3.1 and 4.0 metrics. Older CVEs often have a CVSS 3.0 vector, which has the same metrics as 3.1.

On 12 Nov 2026, 114 of the 117 CVEs with a known location have a vector: 93 in CVSS 3.1 and 21 in 3.0, by CWE 52 for CWE-22, 29 for CWE-79, 20 for CWE-94 and 13 for CWE-78. 113 come from the NVD's own analysts and one from the CNA that published the CVE. None has a CVSS 4.0 vector yet, because these CVEs are older. CVE-2011-2732, CVE-2011-4367 and CVE-2014-7816 have only CVSS 2.0 vectors, so they stay out of the severity check.

### Recent CVEs

The recent CVEs are published after the training cutoff of both models that the pilot triage chose. gpt-6-luna's cutoff is 18 May 2026, from its model page (see its note in models.json). DeepSeek doesn't publish a cutoff for V4.1 Flash, so we take the release of the snapshot we call, DeepSeek-V4.1-Flash-1017 on 17 Oct 2026 in DeepSeek's change log (https://api-docs.deepseek.com/updates), as the latest date it can know about. A CVE published on 18 Oct 2026 or later is newer than both. `deepseek-flash` is an alias for DeepSeek's latest model, so it can move to a newer snapshot before T6.4, and the cutoff with it. Before T6.4, the change log and the `model_version` that `llm_calls` records for a test call show whether it has.

On 25 Nov 2026 we searched GitHub's reviewed advisories for Maven packages published since 18 Oct 2026, with the four CWEs of the severity check and the related ones in `RELATED_CWES`, and looked each one up in the NVD. The publication date that counts is the NVD's, because a model can have seen a CVE from the day it was published, before GitHub reviewed it. Two are newer than both models:

| CVE | Project | CWE | Published in the NVD | Vector in the NVD | Fix commit |
|---|---|---|---|---|---|
| CVE-2026-63436 | zeroturnaround/zt-zip | CWE-22 | 3 Nov 2026 | CVSS 3.1, 6.1, from GitHub as the CNA | `59a76ad` |
| CVE-2026-63499 | zeroturnaround/zt-zip | CWE-23 | 3 Nov 2026 | CVSS 4.0, 6.9, from GitHub as the CNA | `1b62546` |

Both are still awaiting analysis in the NVD, so neither has the NVD's own vector yet, and `cves` would take the CNA's. For CVE-2026-63436 the two GitHub sources disagree: the CNA record in the NVD has `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:L` (6.1), and GitHub's reviewed advisory has `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L` (8.2). We use the one in the NVD, as for the other CVEs, and check it again before T6.4 in case the NVD's analysts add their own.

The search also gave two Keycloak CVEs, CVE-2026-9083 (CWE-22) and CVE-2026-9086 (CWE-79). GitHub reviewed them on 29 Oct 2026, but the NVD published them on 25 Jun 2026, before DeepSeek's snapshot, so they are not recent enough. Two more fit the CWEs but not the language: CVE-2026-75598 in GradleUp/shadow (CWE-22) is in Kotlin, and CVE-2026-76090 in softwaremill/tapir (CWE-94, CVSS 4.0) is in Scala. No Java candidate is in CWE-78 or CWE-94.

We propose the two zt-zip CVEs, whose fix commits give the vulnerable location. Only CVE-2026-63499 has a CVSS 4.0 vector. Two CVEs are too few for a severity check of their own, so before T6.4 we can also search the NVD for CVEs that GitHub hasn't reviewed, or wait for more to be published. Ali helps choose them.

## Neutral copies

A model may have seen the OWASP Benchmarks during training and recognize a test case by its name, its category in the URL or the project's headers, instead of judging the code (docs/data-flow.md, proposal Table 6). The Benchmarks' comments also hint at the answer: in the Java Benchmark, a comment such as "which is safe" or "get the last 'safe' value" appears in 609 of the 2,740 test cases, and "which is safe" is in 131 cases that are not real and 18 that are. `python -m app.eval neutral <dataset>` makes a copy without those names:

- It keeps only what a scan needs: `pom.xml`, `src/main` and `src/config` for Java, and the app, helpers, templates and test code for Python. The answers, the tools' saved results, the scorecards, the README and the scripts stay out.
- Every test case gets a random name such as `Case01067`, and every category a name such as `area08`, in file names, class names, URLs and folders. The order is shuffled, so the number of a case says nothing about its category.
- It removes every comment from the Java, Python, HTML and XML files and the properties files, with a parser for each language, so `//` inside a string such as a URL stays. A line that held only a comment is dropped. Each Benchmark case is judged as a whole file, so no line number depends on the comments.
- It renames the form inputs' `class="safe"`, which the Benchmark's crawler uses, to `class="input"`. It is on about half of the real and half of the other cases, so it doesn't give the answer away, but the word does nudge a model.
- It renames the values in the test code that hint at the answer. In the weak randomness cases, a user name starts with "Safe", as in `'SafeToby'` or `"SafeInga"`, only when the case is not real, so the copy drops the prefix and every user name looks like the real cases' `'Toby'`. The constants `'safe!'`, `'safe'`, `'moresafe'` and `'alsosafe'`, in 299 Python and 753 Java cases, become `'constant!'`, `'constant'`, `'moreconstant'` and `'alsoconstant'`, `SafeStuff` becomes `Stuff`, and the Python test input "safe data" becomes "plain data". No code compares these values, so the code does the same thing. Only values inside quotes change, so a name such as `safeDocBuilderFactory` stays.
- It removes the pom's description, which names the project and its authors, and the two lines of the properties file that give the Benchmark's version and the number of cases per folder, which no code reads. It renames the package `org.owasp.benchmark` to `org.example.app`, and leaves out the category index pages, whose headings name each vulnerability class.
- Real uses of OWASP libraries stay, such as the ESAPI encoder and ESAPI's own properties file, because ordinary applications use them too.

Each copy is then a git repository with one commit. Its files are written with `\n` line endings, and the commit has a fixed author and date and ignores the machine's `core.autocrlf` and `commit.gpgsign`, so the same seed gives the same commit on every machine. A leak check reads every file and path of the copy, and the command fails if anything still names the Benchmark, a category or an author, if a source file still has a comment, or if a "safe" value is left in the test code. On the pinned commits, it finds nothing in either copy. The Java copy keeps all 2,766 classes in the folder of their package with the file name of their class, and every Python file still compiles and has the same tokens as the original, apart from the removed license header. Without the Benchmark's libraries, `javac` gives the copy exactly the same 54,500 errors as the original, apart from the new names, all from missing libraries such as the servlet API, so removing the comments and renaming the values broke no code. The Java copy builds with Maven on JDK 25 in 89 seconds when Spotless is skipped, which the SpotBugs plug-in doesn't do yet (see the baseline run).

The answers go to `eval-data/answers/<dataset>/`, outside the copy: `expected.csv` with the neutral names, `mapping.csv` from every original name to its neutral one, `seed.txt` and the copy's commit. The triage agent's tools read only the scanned checkout (docs/architecture.md), so they can't reach the answers. Never put the answers folder inside a scanned checkout, and `neutral` refuses to write it there. `--seed` makes the same names again.

The copies stay on the machine that made them, and evaluation runs load them into the findings store from there. Requirement F2 lets Sieve scan only public repositories listed in the scope file, cloned over `https://`, and a copy is a local repository, so it can't go through a scan request. We don't push the copies to a public repository to get around that: both Benchmarks are GPL, which asks a published copy to keep the copyright notices that name OWASP Benchmark, and a public copy could end up in a later model's training data, which is what the copy is there to avoid.

The analyzers run on the copy as in the baseline run, and `python -m app.store load-sarif` stores each analyzer's SARIF file as a scan of the copy, from backend/:

    python -m app.store load-sarif --manifest ../plugins/bandit/plugin.toml \
        --sarif <bandit.sarif> --checkout ../eval-data/neutral/benchmark-python \
        --repo-url eval:benchmark-python/t6.4 \
        --commit $(git -C ../eval-data/neutral/benchmark-python rev-parse HEAD)

`load-sarif` copies the checkout into the data folder, where triage reads it like the checkout of any scan, and clones nothing. The `eval:` prefix marks these scans as evaluation runs, and it can't match a scope entry, since those start with `https://`. The part after the Benchmark names the run, here `t6.4`. Repeated scans are matched by repository URL, so two loads of the same copy under one URL would match, and findings rejected in an earlier run would come back hidden and skip grouping and triage. Each evaluation run gets its own name to keep them apart. On a throwaway PostgreSQL 17, this stored 536 Bandit findings for the Python copy and 3,176 Semgrep findings for the Java copy. docs/requirements.md gives this as the one exception to F2. Until #71 changes it, load-sarif accepts any URL, and from then on only these `eval:` URLs and the repositories in the scope file.

The code itself can still look familiar to a model, as docs/data-flow.md says, which is why the evaluation also uses CWE-Bench-Java and the recent CVEs.

## Metrics

`python -m app.eval metrics <metric>` reads CSV files and prints the result as JSON. Each metric has a test in `backend/tests/test_eval_metrics.py` on a small example whose answer was worked out by hand.

### False-positive check (requirement F4, test 3)

    python -m app.eval metrics false-positives --expected <expected.csv> --findings <findings.csv>

The findings CSV has `finding_id`, `file`, `cwe` (several separated by `;`) and `verdict`: `true_positive`, `false_positive`, `unsure`, or empty for the raw analyzer output. A test case is flagged when some finding in its file has its CWE or a related one. The output has the true and false positives, true- and false-positive rates and the Benchmark score (true-positive rate minus false-positive rate) for the raw output and after triage, overall and per CWE, and the two targets of F4:

- `false_positives_removed`: the share of the raw false positives that triage removed. Target at least 0.5.
- `true_positives_kept`: the share of the raw true positives still flagged after triage. Target at least 0.9.

Triage removes a finding only when its verdict is `false_positive`. Unsure findings stay, because the review screen still shows them. The output also counts `findings_without_case`, the findings whose file is no case's file, and `findings_without_cwe`, the findings with no CWE, which can't flag any case. A high count of the first usually means the paths don't match the dataset's, and of the second that an adapter didn't read the CWE of some rules. Either way the rates are lower than they should be.

Related CWEs are in `RELATED_CWES` in `backend/app/cwe.py`, for example CWE-77 and CWE-78. Weak hashing (CWE-328) and broken crypto (CWE-327) are related, because analyzers tag MD5 and SHA-1 as CWE-327 while the Benchmark files those cases under CWE-328. We checked this on the Bandit SARIF file that the Python Benchmark ships: Bandit tags all 45 of its findings on weak-hashing cases as CWE-327. With the two related, those Bandit results give a true-positive rate of 0.0996 and a false-positive rate of 0.1208 over the 1,230 cases.

### Deduplication (requirement F3, test 4)

    python -m app.eval metrics dedup --labeled <groups.csv> --predicted <groups.csv>

Both files have `finding_id` and `group`, with an empty group for a finding on its own. `python -m app.dedup csv <scan ID> --out groups.csv` writes Sieve's groups of a scan in this form. Merges are counted over pairs of findings: precision is the share of the pairs Sieve merged that the labels also merge, and recall the share of labeled pairs that Sieve merged. Target precision at least 0.9. The labeled groups come from T6.3, and DefectDojo's rule-based deduplication is the baseline.

### Severity (requirement F4, test 4)

    python -m app.eval metrics severity --cases <cases.csv>

The CSV has `case_id`, `published_vector`, `published_score`, `predicted_vector` and `predicted_score`, both vectors in the CVE's own CVSS version. The output has the share of base metrics that match (8 in CVSS 3.x, 11 in 4.0), the mean and largest score error, and `level_agreement`, the share of CVEs whose level (none, low, medium, high, critical) matches. Target level agreement at least 0.7. A row with an empty `predicted_vector`, a CVE the agent gave no answer for, is counted in `no_prediction` and left out of the averages.

### Cost and time per finding (requirements N1 and N2)

    python -m app.eval metrics cost --findings <costs.csv>

The CSV has `finding_id`, `cost_usd` and `seconds`. The output has the total, mean and median cost and time per finding. Manual triage for the N2 baseline uses the same file with a cost of 0.

## Baseline run

The baseline measures each analyzer on its own, before any triage. Its output is what the false-positive check has to improve (requirement F4, test 3, objective O2). The analyzers ran directly on the neutral copies of both Benchmarks, outside the pipeline, so the Java baseline doesn't wait for the SpotBugs plug-in.

### How it was run

The copies were made with seed 20261122 from the pinned Benchmarks. The Java copy is commit `d04f8626c8d9` and the Python copy is commit `24e7bb65bdf5`, and `eval-data/answers/` has the answers. Each copy was exported with `git archive`, as the runner does, and scanned like this:

| Analyzer | Version | How |
|---|---|---|
| Semgrep, Python and Java | 1.183.0, semgrep-rules at `16b9e6d` | the plug-in image `sieve-plugin-semgrep:1.183.0-16b9e6d` (built from plugins/semgrep), started with the flags of docs/interfaces.md: no network, a read-only root, user 10001, all capabilities dropped, 4 GB of memory, 2 CPUs |
| Bandit, Python | 1.9.4 with the sarif extra | `bandit -r . --ignore-nosec --exit-zero -f sarif -o bandit.sarif`, run from inside the exported folder, the settings of the Bandit plug-in in #66. Without `-o`, Bandit writes a progress line in front of the SARIF on stdout, and `findings` can't read the file. |
| SpotBugs with Find Security Bugs, Java | SpotBugs 4.10.5, Find Security Bugs 1.14.0 | `-effort:max -low -nested:false` and the filter `security-only.xml`, the settings of the SpotBugs plug-in in #70, on a build that skips Spotless, which the plug-in's build doesn't yet (see below) |

SpotBugs analyzes compiled code, so the Java copy was built first, with Maven 3.9.16 on JDK 25 (the image `maven:3.9.16-eclipse-temurin-25-noble`): `mvn -B -ntp -DskipTests package org.apache.maven.plugins:maven-dependency-plugin:3.11.0:copy-dependencies -DincludeScope=compile -Dspotless.apply.skip=true`. It builds 4,541 classes and copies 126 libraries. The Benchmark's pom runs Spotless, a code formatter that needs the project's git history and its `.prefs` files, which the copy doesn't have, so the build skips it with `-Dspotless.apply.skip=true`. The build step of the SpotBugs plug-in, plugins/spotbugs/build.sh, doesn't pass that flag yet, so its build of the copy would stop at Spotless. Until it does, the Java SpotBugs numbers below come from a build the pipeline can't repeat. Real projects use Spotless too, so the flag belongs in build.sh. The two SpotBugs downloads were checked against the SHA-256 values in the plug-in's Dockerfile.

`findings` turns each tool's SARIF file into the CSV that the false-positive check reads, and reads the CWE, the path and the severity with the code of the pipeline's adapter (`app.adapters.BaseSarifAdapter`). Run from backend/, like the other commands here:

    python -m app.eval findings --sarif semgrep=semgrep.sarif --sarif spotbugs=spotbugs.sarif \
        --root spotbugs=<the folder that was built> --out findings-java-combined.csv
    python -m app.eval metrics false-positives \
        --expected ../eval-data/answers/benchmark-java/expected.csv \
        --findings findings-java-combined.csv

SpotBugs names a file by a base folder inside the build, so `--root` makes its paths relative to the scanned folder. `findings` counts the results it can't place and prints a warning, and none of the runs here had one. Each analyzer has its own CSV, and the combined CSV has all of them, so the same command gives the rates of each analyzer and of their combined output.

The neutral copy gives the same results as the original: Bandit flags exactly the same 204 cases in both Python Benchmarks.

### Results

Each test case is scored as a whole, as in the Benchmark's own scorecards: a case is flagged when some finding in its file has its CWE or a related one. A true positive is a flagged real case, a false positive a flagged case that is not real, and the rates are over the cases. The cases of the Benchmarks are in the first column of the CWE tables.

Java Benchmark, 2,740 cases, 1,415 of them real:

| Analyzer | True positives | False positives | Missed | Clear | True-positive rate | False-positive rate |
|---|---|---|---|---|---|---|
| Semgrep | 1,248 | 552 | 167 | 773 | 0.882 | 0.417 |
| SpotBugs | 1,375 | 639 | 40 | 686 | 0.972 | 0.482 |
| Combined | 1,375 | 698 | 40 | 627 | 0.972 | 0.527 |

Python Benchmark, 1,230 cases, 452 of them real:

| Analyzer | True positives | False positives | Missed | Clear | True-positive rate | False-positive rate |
|---|---|---|---|---|---|---|
| Semgrep | 145 | 106 | 307 | 672 | 0.321 | 0.136 |
| Bandit | 179 | 25 | 273 | 753 | 0.396 | 0.032 |
| Combined | 239 | 117 | 213 | 661 | 0.529 | 0.150 |

The same rates for each CWE. A rate is a dash when the CWE has no case of that kind:

Java:

| CWE | Real | Not real | Semgrep TPR | Semgrep FPR | SpotBugs TPR | SpotBugs FPR | Combined TPR | Combined FPR |
|---|---|---|---|---|---|---|---|---|
| CWE-22 | 133 | 135 | 0.90 | 0.79 | 1.00 | 0.95 | 1.00 | 0.99 |
| CWE-78 | 126 | 125 | 0.93 | 0.87 | 1.00 | 0.89 | 1.00 | 1.00 |
| CWE-79 | 246 | 209 | 0.82 | 0.52 | 1.00 | 0.52 | 1.00 | 0.69 |
| CWE-89 | 272 | 232 | 0.93 | 0.73 | 1.00 | 0.91 | 1.00 | 0.91 |
| CWE-90 | 27 | 32 | 0.96 | 0.88 | 1.00 | 0.84 | 1.00 | 0.97 |
| CWE-327 | 130 | 116 | 1.00 | 0.00 | 1.00 | 0.00 | 1.00 | 0.00 |
| CWE-328 | 129 | 107 | 0.69 | 0.00 | 0.69 | 0.00 | 0.69 | 0.00 |
| CWE-330 | 218 | 275 | 1.00 | 0.00 | 1.00 | 0.00 | 1.00 | 0.00 |
| CWE-501 | 83 | 43 | 0.52 | 0.42 | 1.00 | 0.81 | 1.00 | 0.81 |
| CWE-614 | 36 | 31 | 1.00 | 0.00 | 1.00 | 0.00 | 1.00 | 0.00 |
| CWE-643 | 15 | 20 | 0.93 | 0.65 | 1.00 | 0.95 | 1.00 | 0.95 |

Python:

| CWE | Real | Not real | Semgrep TPR | Semgrep FPR | Bandit TPR | Bandit FPR | Combined TPR | Combined FPR |
|---|---|---|---|---|---|---|---|---|
| CWE-22 | 65 | 103 | 0.03 | 0.02 | 0.00 | 0.00 | 0.03 | 0.02 |
| CWE-78 | 13 | 7 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| CWE-79 | 31 | 58 | 0.00 | 0.28 | 0.00 | 0.00 | 0.00 | 0.28 |
| CWE-89 | 5 | 11 | 1.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| CWE-90 | 16 | 13 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| CWE-94 | 20 | 33 | 1.00 | 1.00 | 0.00 | 0.00 | 1.00 | 1.00 |
| CWE-328 | 71 | 80 | 0.76 | 0.00 | 1.00 | 0.00 | 1.00 | 0.00 |
| CWE-330 | 99 | 227 | 0.00 | 0.00 | 0.78 | 0.00 | 0.78 | 0.00 |
| CWE-501 | 18 | 19 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| CWE-502 | 18 | 36 | 1.00 | 0.33 | 0.72 | 0.19 | 1.00 | 0.33 |
| CWE-601 | 13 | 21 | 0.08 | 0.05 | 0.00 | 0.00 | 0.08 | 0.05 |
| CWE-611 | 8 | 20 | 1.00 | 1.00 | 0.00 | 0.00 | 1.00 | 1.00 |
| CWE-614 | 24 | 15 | 1.00 | 1.00 | 0.00 | 0.00 | 1.00 | 1.00 |
| CWE-643 | 51 | 135 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |

Some things the numbers say:

- No analyzer gives a clean answer. On the Java Benchmark, SpotBugs finds nearly every real case (0.972) but also flags about half of the cases that are not real (0.482). Semgrep misses more (0.882) and flags fewer false positives (0.417). On the Python Benchmark, Bandit finds 0.396 of the real cases with a false-positive rate of 0.032, Semgrep finds 0.321 with 0.136, and together they find 0.529 with 0.150, so about half of the real cases are missed.
- The rates are very different from one CWE to another. On the Java Benchmark, the weak randomness, weak crypto and insecure cookie cases (CWE-330, CWE-327 and CWE-614) are found with no false positive, while for CWE-22, CWE-78 and CWE-89 nearly every case is flagged, real or not. That is the noise that triage has to remove.
- Most of what Semgrep reports outside the test cases is in the Benchmarks' HTML pages and JavaScript files: 836 results in HTML and 24 in JavaScript on the Python Benchmark, and 743 and 24 on the Java Benchmark. They are not test cases, so they don't count in the rates, but a researcher and the triage agent would see them.
- Bandit's 0.00 on CWE-94 and CWE-611 doesn't mean it misses that code. It flags all 53 CWE-94 cases and all 28 CWE-611 cases, but tags its exec and eval findings CWE-78 and its XML findings CWE-20, which `RELATED_CWES` doesn't relate to either. Whether the Bandit adapter should give those rules better CWEs, as the ESLint adapter does for its own rules, is for #66 and #60.
- Four SpotBugs results have no CWE, and the check counts them in `findings_without_cwe`.

### What the target of O2 means in numbers

The target is to remove at least half of the false positives and keep at least 90% of the true positives (`false_positives_removed` at least 0.5 and `true_positives_kept` at least 0.9). On the combined output, that is:

| Benchmark | False positives now | Triage has to remove | True positives now | Triage has to keep |
|---|---|---|---|---|
| Java | 698 | at least 349 | 1,375 | at least 1238 |
| Python | 117 | at least 59 | 239 | at least 216 |

The Python Benchmark has only 239 flagged real cases to keep, so one lost true positive moves `true_positives_kept` by 0.4 points.

### Run times

The timings are for one Mac, with Docker Desktop and the container limits of the runner, 2 CPUs and 4 GB. They are for checking the time limits of the plug-ins (`timeout_seconds` in docs/interfaces.md, issue #20). The limit of a plug-in with a build step covers the build and the scan together.

| Step | Files | Time | Limit |
|---|---|---|---|
| Semgrep, Python Benchmark | 2,496 scanned | 129 s, with nothing else running | 600 s |
| Semgrep, Java Benchmark | 5,542 scanned | 336 s, with light work going on at the same time | 600 s |
| Bandit, Python Benchmark | 1,236 | 3.7 to 3.9 s, three runs | 600 s |
| Maven build of the Java Benchmark, Spotless skipped | 2,766 sources, 4,541 classes | 89 s | 1,800 s with the scan |
| SpotBugs, Java Benchmark | 4,541 classes | 73 s | 1,800 s |

These are the best times we got, and they don't show the margin that the limits really have. Semgrep on the Java Benchmark takes 56% of its 600 s. Later, with the Mac on battery and in Low Power Mode, the same scan had not finished after 62 minutes and was stopped, and an earlier run that was timed while the Mac slept in the middle of it also showed a wrong time, so the timings depend a lot on the machine. A repository larger than the Benchmark, or a slower machine, can pass 600 s. The run then ends as `timed_out`, the scan becomes `partial`, and Semgrep's findings are missing. The manifest's `timeout_seconds` can be raised to at most 3,600 s, and the SpotBugs plug-in already has 1,800 s. We suggest the same 1,800 s for Semgrep, until the scans are timed again on a computer that is plugged in with Low Power Mode off. To time them again, run the commands above one after another and take the time from `date` before and after each.

### Severity baseline

Table 5 of the proposal compares the severity step with "the analyzer's own severity". None of our tools gives a score (docs/finding-format.md), so the evaluation defines a mapping from the SARIF level in `tool_severity` to a CVSS level: error is high, warning is medium, note is low and none is none. No tool rates anything as critical. `python -m app.eval metrics severity-baseline --cases <cases.csv>` compares that level with the level of the published CVSS score. The CSV has one row per CVE, with `case_id`, `published_score` and the `tool_severity` of the most severe finding at the CVE's vulnerable location, and an empty value when the analyzers found nothing there.

The mapping and the metric are done and tested on a small example. The numbers are not: they need the analyzers to run on the vulnerable commit of each of the 117 CVEs of CWE-Bench-Java, which means building 117 projects. That is a separate job, and it can start from the CVE list in `cves.csv`.

## Pilot triage

The pilot sends 100 findings of the baseline run through LLMClient with the draft prompt `backend/app/llm/prompts/false_positive_check.md`, to measure the cost and time per finding (requirement N1, test 3) and to choose the two models of the evaluation. It has no tools and no second opinion: one call per finding, with the finding's tool, rule, CWEs, message and lines as values and the whole case file as the code, read from the neutral copy. Nothing of the case's original name or its answer reaches the model.

### How it was run

The analyzers ran again on the neutral copies of the baseline run, at the same commits and settings, except that SpotBugs ran in the plug-in's own scan image on the Maven build. Every analyzer gave the same true and false positives as in the baseline. Then, from backend/:

    python -m app.eval pilot sample --seed 20261122 \
        --sarif benchmark-java:semgrep=<semgrep.sarif> --sarif benchmark-java:spotbugs=<spotbugs.sarif> \
        --sarif benchmark-python:semgrep=<semgrep.sarif> --sarif benchmark-python:bandit=<bandit.sarif>
    python -m app.eval pilot run --model deepseek-flash --budget 0.05 --limit 10
    python -m app.eval pilot run --model deepseek-flash --budget 0.50 --limit 100
    python -m app.eval pilot run --model gpt-6-luna --budget 0.05 --limit 10
    python -m app.eval pilot run --model gpt-6-luna --budget 0.40 --limit 100
    python -m app.eval metrics cost --findings ../eval-data/pilot/<model>/results.csv
    python -m app.eval metrics false-positives --expected ../eval-data/pilot/expected-<dataset>.csv \
        --findings ../eval-data/pilot/<model>/results-<dataset>.csv

`pilot sample` reads the SARIF files with the pipeline's adapters and keeps the findings that flag a Benchmark case, a finding in the case's file with its CWE or a related one. It takes one finding per case, and visits the CWEs of each Benchmark in turn until it has 50 findings from each. It writes `sample.csv` and the answers of the sampled cases to `eval-data/pilot/`. `pilot run` sends the first `--limit` findings of the sample to one model, skips findings it already has, and stops at its budget, so the first 10 findings of each model were checked before the other 90. `--dry-run` prints the worst-case cost of the calls and sends nothing. The calls were logged in a PostgreSQL `llm_calls` table, with `max_tokens` 4,000 and no effort, so each model thought at its default.

The sample has 4 or 5 findings from each of the 11 CWEs that the analyzers flag in each Benchmark, apart from CWE-601 in Python, which has only 2 flagged cases. 65 of the 100 cases are real: 39 of the 50 in Java, because CWE-327, CWE-328, CWE-330 and CWE-614 have no false positive there, and 26 of the 50 in Python. The 100 findings come from SpotBugs (29), Semgrep (56) and Bandit (15).

The calls ran on 25 Nov 2026 between 06:28 and 07:15 UTC, inside DeepSeek's peak hours, so deepseek-flash was charged its full price. Off-peak it costs half. `llm_calls` has the 200 calls with one template version, `dd1e59257403`, no cache hit and no error.

### Results

| | deepseek-flash | gpt-6-luna |
|---|---|---|
| Total cost of 100 findings | US$0.2347 | US$0.0603 |
| Mean cost per finding | US$0.00235 | US$0.00060 |
| Median cost, most expensive finding | US$0.00198, US$0.00542 | US$0.00052, US$0.00164 |
| Mean time, median time, longest | 13.3 s, 8.2 s, 229 s | 7.3 s, 6.3 s, 21 s |
| Mean tokens in, out | 1,421, 1,695 | 1,355, 872 |
| Verdicts: true positive, false positive, unsure | 56, 31, 13 | 51, 40, 9 |
| Replies that aren't valid JSON | 12, all cut off at 4,000 tokens | 0 |
| Right and wrong verdicts, unsure left out | 81 and 6 | 72 and 19 |
| Real cases called a false positive | 4 | 13 |

Cost and time come from `metrics cost`. The output tokens include the models' thinking, which is most of deepseek-flash's output. Its 12 cut-off replies ran out of tokens while thinking, and they count as unsure, so only one of its 13 unsure verdicts was the model's own answer.

The targets of F4 on the sample, from `metrics false-positives`, as the share of false positives removed and the share of true positives kept. Every sampled case is flagged before triage, so these two shares are what triage changes. The targets are at least 0.5 and at least 0.9.

| Triage | Java removed | Java kept | Python removed | Python kept |
|---|---|---|---|---|
| deepseek-flash | 0.727 | 0.949 | 0.792 | 0.923 |
| gpt-6-luna | 0.636 | 0.769 | 0.833 | 0.846 |
| deepseek-flash, gpt-6-luna on its unsure findings | 0.727 | 0.897 | 0.875 | 0.923 |
| gpt-6-luna, deepseek-flash on its unsure findings | 0.818 | 0.769 | 0.833 | 0.846 |

The two orders are worked out from the same calls: the second model's verdict replaces the first one's where the first was unsure. deepseek-flash first sends 13 findings to gpt-6-luna and costs US$0.00245 and 14.6 s per finding. gpt-6-luna first sends 9 to deepseek-flash and costs US$0.00089 and 8.7 s per finding.

The sample is small. Java has 11 cases that are not real and Python 24, so one verdict moves the share removed by 9 or 4 points, and the share kept by 2.6 or 3.8 points. The numbers rank the models, but T6.4 measures them.

### The two models

gpt-6-luna is the cheaper model. It costs a quarter of deepseek-flash per finding at peak price and half off-peak, it answers faster, and every reply was valid JSON. It keeps too few true positives, though: it called 13 real cases false positives, and the share kept is 0.769 on Java and 0.846 on Python, under the 0.9 target.

deepseek-flash is the stronger model. It gave 81 right and 6 wrong verdicts against 72 and 19, and it is the only one that meets both targets on both Benchmarks on its own. Its weak point is the 12 replies cut off while thinking. A second opinion from gpt-6-luna on those adds about 4% to the cost but loses two Java true positives, so T3.3 should rather give deepseek-flash more room, with a higher `max_tokens` or a set effort. Its longest call took 229 s, so the triage needs a timeout per call.

So the evaluation uses gpt-6-luna as the cheaper model and deepseek-flash as the stronger one. In T6.4, deepseek-flash checks every finding, and its unsure findings stay unsure for the review screen. gpt-6-luna gives no second opinion: it checks every finding in a run of its own, only to be measured against deepseek-flash. Neither needs a stronger model on its unsure findings yet.

This is the opposite of the Triage API in docs/interfaces.md, where each finding goes to the cheaper model first and only its unsure findings go to the stronger one. With these two models that order can't work: gpt-6-luna was sure, not unsure, about the 13 real cases it called false positives, so they would never reach deepseek-flash, and the share kept stays at 0.769 on Java. T3.3 changes the Triage API to match: one model checks every finding, and a second model on the unsure findings is optional.

Both models get weak hashing, weak random and insecure cookie cases wrong more than the others: 12 of gpt-6-luna's 19 wrong verdicts and 3 of deepseek-flash's 6 are in CWE-327, CWE-328, CWE-330 and CWE-614. The draft prompt calls a finding a true positive when "data that an attacker can control reaches the flagged operation", which doesn't fit those CWEs, where the algorithm or the missing flag is the weakness. The prompt of T3.3 should say so.

### Budget per finding (N1, test 3)

The budget of N1 is US$0.02 per finding for the whole triage of a finding, for both models: US$0.01 for the false-positive check, which the pilot measured, and US$0.01 for the severity call of T3.4 and the grouping questions of #83 together, which it didn't. A triage run's limit is US$0.02 times the number of findings it triages. T3.4 and #83 check that their calls fit in their share, and T6.4 checks the whole.

The US$0.01 for the check is four times deepseek-flash's mean cost at peak price and nearly twice its most expensive finding, which leaves room for the `read_file` and `find_definition` tools of #61. Each tool call adds a turn that sends the conversation again. As an estimate, three turns of the pilot's size, with a tool result of about 1,000 tokens each, cost just under US$0.01 on deepseek-flash at peak price. gpt-6-luna stays far below the budget.

`pilot sample` prints each tool's number of findings and each Benchmark's number of findings that flag a case. For T6.4, 4,766 Java findings and 586 Python findings flag a case, 5,352 of the 13,389 in all, so the whole triage of both Benchmarks has a limit of US$107.04, and the false-positive check of those findings stays within US$53.52 of it. At the pilot's cost without tools the check would spend about US$12.60 on deepseek-flash at peak price and US$3.20 on gpt-6-luna. All 13,389 findings of the two Benchmarks would have a limit of US$267.78.

## Not covered yet

- The final list of recent CVEs, their vectors from the NVD and their vulnerable locations, see Recent CVEs above.
- The labeled duplicate groups and the labeled Juice Shop sample, made by hand in T6.3. The dedup metric reads the groups as they are. The Juice Shop sample is labeled per finding, with many findings in one file, while the false-positive check judges whole files, so it needs a per-finding mode, added with T6.3.
- The numbers of the severity baseline, which need the analyzers to run on the CVEs' projects, see the baseline run.
- The false-positive check with the tools of #61, and the changes the pilot suggests for it: more room for deepseek-flash's thinking, a timeout per call, and a prompt that fits weak hashing, weak random and insecure cookie findings. Its cost per finding has to stay within its US$0.01 share of the budget, and the Triage API changes to one model on every finding, see The two models.
- The target applications have no expected results of their own: they are scanned for duplicates, reports and the PoC check.
