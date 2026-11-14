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
    python -m app.eval metrics --help              # the metric scripts

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

Recent CVEs, published after the training cutoff of both models, are still to be chosen. docs/requirements.md says they are chosen in T6.1, but we pick the two models in the pilot run of T6.2, so the cutoff is known only then, and that table has to be updated to say T6.2. Ali helps choose them.

## Neutral copies

A model may have seen the OWASP Benchmarks during training and recognize a test case by its name, its category in the URL or the project's headers, instead of judging the code (docs/data-flow.md, proposal Table 6). The Benchmarks' comments also hint at the answer: in the Java Benchmark, a comment such as "which is safe" or "get the last 'safe' value" appears in 609 of the 2,740 test cases, and "which is safe" is in 131 cases that are not real and 18 that are. `python -m app.eval neutral <dataset>` makes a copy without those names:

- It keeps only what a scan needs: `pom.xml`, `src/main` and `src/config` for Java, and the app, helpers, templates and test code for Python. The answers, the tools' saved results, the scorecards, the README and the scripts stay out.
- Every test case gets a random name such as `Case01067`, and every category a name such as `area08`, in file names, class names, URLs and folders. The order is shuffled, so the number of a case says nothing about its category.
- It removes every comment from the Java, Python, HTML and XML files and the properties files, with a parser for each language, so `//` inside a string such as a URL stays. A line that held only a comment is dropped. Each Benchmark case is judged as a whole file, so no line number depends on the comments.
- It renames the form inputs' `class="safe"`, which the Benchmark's crawler uses, to `class="input"`. It is on about half of the real and half of the other cases, so it doesn't give the answer away, but the word does nudge a model.
- It renames the values in the test code that hint at the answer. In the weak randomness cases, a user name starts with "Safe", as in `'SafeToby'` or `"SafeInga"`, only when the case is not real, so the copy drops the prefix and every user name looks like the real cases' `'Toby'`. The constants `'safe!'`, `'safe'`, `'moresafe'` and `'alsosafe'`, in 299 Python and 753 Java cases, become `'constant!'`, `'constant'`, `'moreconstant'` and `'alsoconstant'`, `SafeStuff` becomes `Stuff`, and the Python test input "safe data" becomes "plain data". No code compares these values, so the code does the same thing. Only values inside quotes change, so a name such as `safeDocBuilderFactory` stays.
- It removes the pom's description, which names the project and its authors, and the two lines of the properties file that give the Benchmark's version and the number of cases per folder, which no code reads. It renames the package `org.owasp.benchmark` to `org.example.app`, and leaves out the category index pages, whose headings name each vulnerability class.
- Real uses of OWASP libraries stay, such as the ESAPI encoder and ESAPI's own properties file, because ordinary applications use them too.

Each copy is then a git repository with one commit. Its files are written with `\n` line endings, and the commit has a fixed author and date and ignores the machine's `core.autocrlf` and `commit.gpgsign`, so the same seed gives the same commit on every machine. A leak check reads every file and path of the copy, and the command fails if anything still names the Benchmark, a category or an author, if a source file still has a comment, or if a "safe" value is left in the test code. On the pinned commits, it finds nothing in either copy. The Java copy keeps all 2,766 classes in the folder of their package with the file name of their class, and every Python file still compiles and has the same tokens as the original, apart from the removed license header. Without the Benchmark's libraries, `javac` gives the copy exactly the same 54,500 errors as the original, apart from the new names, all from missing libraries such as the servlet API, so removing the comments and renaming the values broke no code. We haven't built the copy with Maven yet.

The answers go to `eval-data/answers/<dataset>/`, outside the copy: `expected.csv` with the neutral names, `mapping.csv` from every original name to its neutral one, `seed.txt` and the copy's commit. The triage agent's tools read only the scanned checkout (docs/architecture.md), so they can't reach the answers. Never put the answers folder inside a scanned checkout, and `neutral` refuses to write it there. `--seed` makes the same names again.

A scan can't reach a copy yet. Requirement F2 lets Sieve scan only public repositories listed in the scope file, cloned over `https://`, and the copy is a local repository. T6.2 chooses between pushing the copies to a public repository that the scope file lists, and a local mode for evaluation runs, which would need F2 to change.

The code itself can still look familiar to a model, as docs/data-flow.md says, which is why the evaluation also uses CWE-Bench-Java and the recent CVEs.

## Metrics

`python -m app.eval metrics <metric>` reads CSV files and prints the result as JSON. Each metric has a test in `backend/tests/test_eval_metrics.py` on a small example whose answer was worked out by hand.

### False-positive check (requirement F4, test 3)

    python -m app.eval metrics false-positives --expected <expected.csv> --findings <findings.csv>

The findings CSV has `finding_id`, `file`, `cwe` (several separated by `;`) and `verdict`: `true_positive`, `false_positive`, `unsure`, or empty for the raw analyzer output. A test case is flagged when some finding in its file has its CWE or a related one. The output has the true and false positives, true- and false-positive rates and the Benchmark score (true-positive rate minus false-positive rate) for the raw output and after triage, overall and per CWE, and the two targets of F4:

- `false_positives_removed`: the share of the raw false positives that triage removed. Target at least 0.5.
- `true_positives_kept`: the share of the raw true positives still flagged after triage. Target at least 0.9.

Triage removes a finding only when its verdict is `false_positive`. Unsure findings stay, because the review screen still shows them. The output also counts `findings_without_case`, the findings whose file is no case's file, and `findings_without_cwe`, the findings with no CWE, which can't flag any case. A high count of the first usually means the paths don't match the dataset's, and of the second that an adapter didn't read the CWE of some rules. Either way the rates are lower than they should be.

Related CWEs are in `RELATED_CWES` in `backend/app/eval/metrics.py`, for example CWE-77 and CWE-78. Weak hashing (CWE-328) and broken crypto (CWE-327) are related, because analyzers tag MD5 and SHA-1 as CWE-327 while the Benchmark files those cases under CWE-328. We checked this on the Bandit SARIF file that the Python Benchmark ships: Bandit tags all 45 of its findings on weak-hashing cases as CWE-327. With the two related, those Bandit results give a true-positive rate of 0.0996 and a false-positive rate of 0.1208 over the 1,230 cases.

### Deduplication (requirement F3, test 4)

    python -m app.eval metrics dedup --labeled <groups.csv> --predicted <groups.csv>

Both files have `finding_id` and `group`, with an empty group for a finding on its own. Merges are counted over pairs of findings: precision is the share of the pairs Sieve merged that the labels also merge, and recall the share of labeled pairs that Sieve merged. Target precision at least 0.9. The labeled groups come from T6.3, and DefectDojo's rule-based deduplication is the baseline.

### Severity (requirement F4, test 4)

    python -m app.eval metrics severity --cases <cases.csv>

The CSV has `case_id`, `published_vector`, `published_score`, `predicted_vector` and `predicted_score`, both vectors in the CVE's own CVSS version. The output has the share of base metrics that match (8 in CVSS 3.x, 11 in 4.0), the mean and largest score error, and `level_agreement`, the share of CVEs whose level (none, low, medium, high, critical) matches. Target level agreement at least 0.7. A row with an empty `predicted_vector`, a CVE the agent gave no answer for, is counted in `no_prediction` and left out of the averages.

### Cost and time per finding (requirements N1 and N2)

    python -m app.eval metrics cost --findings <costs.csv>

The CSV has `finding_id`, `cost_usd` and `seconds`. The output has the total, mean and median cost and time per finding. Manual triage for the N2 baseline uses the same file with a cost of 0.

## Not covered yet

- Recent CVEs, chosen after the pilot run of T6.2, see above.
- The labeled duplicate groups and the labeled Juice Shop sample, made by hand in T6.3. The dedup metric reads the groups as they are. The Juice Shop sample is labeled per finding, with many findings in one file, while the false-positive check judges whole files, so it needs a per-finding mode, added with T6.3.
- The severity baseline of Table 5, the analyzer's own severity. It needs a mapping from `tool_severity` to a level, which docs/finding-format.md leaves to the evaluation, so it comes with the baseline run of T6.2.
- How a scan reaches the neutral copies, see above.
- The target applications have no expected results of their own: they are scanned for duplicates, reports and the PoC check.
