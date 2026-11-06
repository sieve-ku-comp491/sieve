# Requirements specification

This document lists what Sieve must do (functional requirements, F) and the qualities it must have (non-functional requirements, N). Each requirement has an acceptance test that someone other than its author can run or check. It expands Table 1 of the project proposal, and later tasks and the final evaluation are checked against it.

Sieve is for security researchers who review public source code, such as hunters on open-source bug bounty programs. It runs static analyzers on a repository, groups duplicate findings, checks each finding for false positives with an LLM, scores its severity, and lets a person approve each finding before a report is exported.

Each requirement names the task where it is built and the task where it is verified.

## Functional requirements

### F1 Run SARIF analyzers as plug-ins

Sieve runs any analyzer that writes SARIF 2.1.0 as a plug-in, through the plug-in contract in docs/interfaces.md, and stores the findings of every plug-in in the format of docs/finding-format.md. Five analyzers cover Python, Java and JavaScript/TypeScript, so each language has at least two code analyzers (list below).

Each analyzer runs in its own container with no network access. A plug-in that fails, times out or writes invalid SARIF is marked as such, and the other plug-ins in the scan still run.

Acceptance tests:

1. Scans of PyGoat, WebGoat and Juice Shop run every plug-in for the application's languages, and their findings reach the findings store in the format of docs/finding-format.md.
2. Each adapter has a test that converts a saved SARIF file from a real run of its tool. The rule, CWEs, file, lines and tool severity of every finding match the SARIF file.
3. With the test plug-in from T2.1, a run that succeeds, times out, crashes, writes invalid SARIF, scans no files, or tries to reach the internet ends with the status that docs/interfaces.md gives for that case, and a second plug-in in the same scan still succeeds.
4. Every plug-in run records its image digest and the tool and rules versions it used.

Built in T2.1 and T2.2. Verified in T2.1 (tests 3 and 4) and T2.2 (tests 1 and 2).

### F2 Scan only repositories in the scope file

Sieve scans a repository only when the project's scope file lists it, and refuses any other repository before it clones anything or starts any container. Each entry gives the reason we are allowed to scan the repository: it is our own code, a deliberately vulnerable application, or source code that a bug bounty program lists in its scope. If a program has source code but doesn't list it in its scope, we don't test it.

The scope file lists public repositories only (requirement N4):

```toml
[[repository]]
url = "https://github.com/adeyosemanputra/pygoat"
reason = "OWASP PyGoat, a deliberately vulnerable application"

[[repository]]
url = "https://github.com/example-org/example-app"
reason = "Source code listed as an asset of the Example program: https://hackerone.com/example-org"
```

URLs are compared after normalizing them: the host in lowercase, without a trailing `/` or `.git`. An entry allows exactly one repository, so listing one repository of an owner doesn't allow the others.

Acceptance tests:

1. A scan of a repository that is not in the scope file is refused through both the CLI and the REST API, with an error that names the repository and the scope file. Nothing is cloned and no container starts.
2. `https://github.com/adeyosemanputra/pygoat.git`, `https://GitHub.com/adeyosemanputra/pygoat/` and the URL in the example all match the PyGoat entry. Another repository of the same owner is refused.
3. A scope file with an entry that has no `reason` is rejected when it is loaded, with an error that names the entry.
4. A private repository can't be scanned even when it is listed: the scan service clones without credentials, so the clone fails and the scan ends with an error.

Built in T2.4. Verified in T2.4. The stretch requirement S3 adds the scope imported from HackerOne.

### F3 Group duplicate findings

Sieve groups findings that describe the same issue, both across analyzers in one scan and across repeated scans of the same repository, and records why each group was formed.

Rules group findings first: the same file and nearby lines or the same function, and related CWEs such as CWE-77 and CWE-78. Text similarity groups the rest, and only the groups the rules can't decide go to the LLM. Findings from repeated scans are matched by their SARIF fingerprint, so a finding that was already reviewed is not shown again.

Acceptance tests:

1. A Semgrep finding and a Bandit finding on the same line of the same function, one tagged CWE-78 and the other CWE-77, end up in one group. Two findings from the same rule in different functions do not.
2. Every group records how it was formed: the rule that matched, the similarity score, or the LLM call that decided it.
3. Scanning the same commit of PyGoat twice adds nothing to the review queue, and every finding from the second scan is matched to one from the first.
4. Evaluation: precision and recall of merges on the hand-labeled duplicate groups of PyGoat, WebGoat and Juice Shop, against DefectDojo's rule-based deduplication as the baseline. Target: at least 90% precision.

Built in T3.2. Verified in T3.2 (tests 1 to 3) and T6.4 (test 4).

### F4 Give every finding a verdict and a severity score

Every finding gets a verdict (true positive, false positive or unsure), the reasoning behind it, the code lines the reasoning relies on, and a CVSS v4.0 base score. The LLM chooses each base metric with a one-line justification, and Sieve computes the score from the resulting vector with FIRST's official algorithm. The LLM never chooses the score itself.

Acceptance tests:

1. After triage of a test scan, every finding has a verdict, reasoning, at least one cited line, a CVSS v4.0 vector, a score, and a justification for each of the 11 base metrics. Every cited line exists in the scanned file.
2. For a set of published vectors, Sieve's calculator gives the same scores as FIRST's CVSS v4.0 calculator.
3. Evaluation: on both the Java and Python versions of the OWASP Benchmark, triage removes at least 50% of the false positives and keeps at least 90% of the true positives.
4. Evaluation: on real CVEs with published vectors, we report the share of CVSS metrics that match and the score error, in the CVE's own CVSS version. For CVEs that only have a v3.1 vector, the agent also chooses v3.1 metrics. Target: the severity level (low, medium, high or critical) matches the published one for at least 70% of the CVEs.

Built in T3.3 and T3.4. Verified in T3.3 and T3.4 (tests 1 and 2) and T6.4 (tests 3 and 4).

### F5 Export only approved findings

A finding is exported only after a person approves it on the review screen, with or without edits. The report service checks this itself when it exports, so no client can get around the check, including the CLI and the evaluation harness.

A finding counts as approved when its latest review decision is approve. A report for a duplicate group needs every finding in the group to be approved. Each review stores the reviewer, the time and the decision, and when the reviewer edits a finding or its report, the AI's original text is kept next to the edited one.

Acceptance tests:

1. End-to-end test through the REST API: exporting a report for an unreviewed finding, a rejected finding, and a finding that was approved and later rejected each fails with an error, and no file is written. Exporting a report for an approved finding succeeds.
2. A report for a duplicate group with one unapproved member can't be exported. Once every member is approved, it can.
3. Every exported report links to the review that approved it, with the reviewer and time. For an edited finding, both the AI's text and the reviewer's text are stored.

Built in T4.1 and T5.2. Verified in T5.2.

### F6 Generate a complete report for every approved finding

For every approved finding, Sieve generates a report with a title, summary, impact, steps to reproduce, fix and references, including the CWE, and exports it as Markdown.

Acceptance tests:

1. For every approved finding in a test run, the exported report has all six parts, none of them empty, and its references include the finding's CWE.
2. A rejected or unreviewed finding gets no report (shared with F5).
3. Evaluation: team members who did not write a report rate it with a rubric, against reports we write by hand for the same findings.

Built in T4.1. Verified in T4.1 (tests 1 and 2) and T6.4 (test 3).

## Non-functional requirements

### N1 Cost

The API cost per finding stays within the budget we set after the pilot run in week 4, and every run has a budget limit it can't go over.

Acceptance tests:

1. Every LLM call is logged with its tokens and cost, and every run reports its total cost when it ends.
2. A run whose budget is lower than its cost stops when the next call would go over the limit, with a clear error, and its total cost stays within the limit.
3. The pilot triage on about 100 findings reports the cost per finding, which sets the budget. The final evaluation reports the cost per finding for both models and stays within that budget.

Built in T3.1. Verified in T3.1 (tests 1 and 2), T6.2 and T6.4 (test 3).

### N2 Speed

Triaging a finding with Sieve takes a person less time than triaging it by hand.

Acceptance test: on a sample of findings from PyGoat, WebGoat and Juice Shop, we compare the minutes per finding a team member needs to decide on the review screen with the minutes needed to triage the raw analyzer output by hand.

Verified in T6.4.

### N3 Auditability

Every AI decision is stored with the prompt, the response and the exact model version that produced it.

Acceptance tests:

1. Every verdict, every CVSS metric choice and every duplicate group decided by the LLM links to its calls in the LLM calls table, and each call stores its prompt, response, model version, tokens and cost.
2. A database check finds no verdict without a linked call.
3. For every verdict in the evaluation, its logged calls can be found and their prompts and responses shown.

Built in T3.1. Verified in T3.1 (tests 1 and 2) and T6.4 (test 3).

### N4 Security and privacy

Sieve sends only public code to outside APIs, passes code to the LLM as marked data and never as instructions, and keeps API keys out of the repository.

Acceptance tests:

1. A scan of a repository that is not in the scope file is refused (shared with F2), and the documentation of the scope file says it is for public code only.
2. The prompt builder puts code only inside the marked data block of a prompt template.
3. Findings in files with planted comments that tell an AI to dismiss them get the same verdict as without the comments, and the review screen flags those comments.
4. Analyzer containers have no network access, except the build step of the Java plug-in.
5. API keys are read only from environment variables, and Gitleaks finds nothing when it scans the repository's full history in CI on every pull request.

Built in T1.3, T2.1, T3.1 and T5.1. Verified in T1.3 (test 5), T2.1 (test 4), T3.1 (test 2) and T6.4 (tests 1 and 3).

### N5 Extensibility

An analyzer, a model provider or a report format is added through its interface, without changing the core: the plug-in contract (docs/interfaces.md), the LLM provider interface and the report format interface (docs/class-diagrams.md).

Acceptance tests:

1. The evaluation runs five analyzers through the one plug-in contract and two hosted models through the one provider interface.
2. The pull request that adds the SpotBugs plug-in in week 5 changes only files in its plug-in directory, its adapter and the adapter's tests. The same holds for the pull request that adds the second model provider.
3. A team member who didn't write the runner adds the test plug-in from T2.1 by following the plug-in guide (T7.1), without help.

Built in T2.1, T2.2, T3.1 and T4.1. Verified in T2.2 and T3.1 (test 2), T6.4 (test 1) and T7.1 (test 3).

### N6 Reproducibility

The whole system is installed and started with one Docker Compose command by following the documentation, and the same inputs give the same results. Every tool, rule set, dataset and target application is pinned to a version or commit (the list below), and every LLM call is logged with its exact model version (requirement N3).

Acceptance tests:

1. On a clean machine with only Docker and Git installed, a team member follows the installation guide, runs `docker compose up`, scans PyGoat, and sees its findings on the review screen.
2. Two scans of the same PyGoat commit with the same plug-in images give the same findings with the same fingerprints.
3. Running a finished evaluation run again from the response cache gives the same verdicts and scores, and makes no API calls.
4. Every image, tool, rule set, dataset and target application in this document is pinned to a version or commit, and none uses `latest`.

Built in T1.3, T2.1 and T3.1. Verified in T2.1 (tests 2 and 4), T6.4 (test 3) and T7.3 (test 1).

### N7 Usability

A reviewer can decide on a finding from one screen that shows the verdict, the reasoning and the cited code.

Acceptance tests:

1. The finding screen shows, without opening another page: the code with the cited lines highlighted, the verdict and reasoning, the CVSS score with the justification of each metric, the analyzer's message, the flag for comments that look like instructions to an AI, and the approve, reject and edit actions. Checked against the mockups in D1.1.
2. Usability test: three to five students outside the team review the same 20 findings on the review screen and in the raw analyzer output. We report the time per finding, the wrong decisions and the System Usability Scale (SUS) score. Target: less time per finding than with the raw output, and a SUS score of at least 68, the average score in published SUS studies.

Built in T5.1. Verified in T5.1 (test 1) and T6.4 (test 2).

## Stretch requirements

These are built only after the minimum viable product works end to end (M5.3, week 7).

| ID | Requirement | Acceptance test | Task |
|---|---|---|---|
| S1 | A PoC guide lists the steps to reproduce an approved finding, and a sandboxed check runs the PoC against a local Docker copy of the target and marks the finding as verified. | A PoC runs in the sandbox for at least one confirmed finding in each of PyGoat, WebGoat and Juice Shop. | T4.3 |
| S2 | Reports can be exported in HackerOne format (CVSS-based severity) and Bugcrowd format (VRT priority). | Both formats fill every field of the platforms' report forms. | T4.2 |
| S3 | A program's scope is imported through the HackerOne Hacker API, and Sieve refuses to report on assets outside it. | The scope check rejects every out-of-scope asset in our tests. | T5.3 |
| S4 | Submission is built and tested only against a mock platform server. | A test submission reaches the mock server, and no request goes to a real platform. | T5.4 |

## Analyzers, datasets and target applications

These versions stay fixed from the baseline run in week 4 to the final evaluation in week 9, so that results can be compared. A version changes only through a pull request that updates this table and says why. Versions were checked on 6 Nov 2026.

### Analyzers

| Analyzer | Languages | Version we pin | Rules | How it writes SARIF |
|---|---|---|---|---|
| Semgrep CE | Python, Java, JavaScript/TypeScript | 1.183.0 | semgrep-rules at commit `16b9e6d` (21 Oct 2026), the `security` folders only | `--sarif` |
| Bandit | Python | 1.9.4 | built in | `-f sarif`, with the `bandit[sarif]` extra |
| SpotBugs with Find Security Bugs | Java | SpotBugs 4.10.5, Find Security Bugs 1.14.0 | built in, security patterns only | `-sarif` |
| ESLint with eslint-plugin-security | JavaScript/TypeScript | ESLint 10.14.0, eslint-plugin-security 4.2.1, typescript-eslint 8.72.1 | the plug-in's recommended set | the `@microsoft/eslint-formatter-sarif` 3.1.0 formatter |
| Gitleaks | secrets in any file | 8.30.1 | built in | `--report-format sarif`, run with `--redact` |

Notes:

- We tested Semgrep 1.183.0 with these rules on PyGoat (docs/finding-format.md). Semgrep 1.184.0 came out on 5 Nov 2026, but we keep the version we tested.
- SpotBugs analyzes compiled code, so the Java plug-in's build step needs JDK 25 and Maven: WebGoat v2026.5 requires Java 25. Find Security Bugs 1.14.0 is from June 2025, so T2.2 checks that it loads in SpotBugs 4.10.5 and works on Java 25 class files, and records a working pair if it doesn't.
- `@microsoft/eslint-formatter-sarif` was written for older ESLint versions. T2.2 checks it with ESLint 10 and writes our own small formatter if it fails.
- Gitleaks scans the files of the checked-out commit, not the Git history, because we report on that commit.
- The semgrep-rules repository has its own license, the Semgrep Rules License. We use the rules only inside our own setup and don't publish the plug-in image.

### Datasets

| Dataset | Version we pin | What it contains | Used for |
|---|---|---|---|
| OWASP Benchmark for Java | 1.2, commit `0119da4` | 2,740 test cases in 11 categories, 1,415 of them real vulnerabilities (`expectedresults-1.2.csv`) | false-positive check, Java |
| OWASP Benchmark for Python | 0.1, commit `f129148` | 1,230 test cases in 14 categories, 452 of them real vulnerabilities (`expectedresults-0.1.csv`) | false-positive check, Python |
| CWE-Bench-Java | commit `afe0ebd` | real Java vulnerabilities with known vulnerable locations, from the IRIS paper. We take the published CVSS vectors from the NVD. | severity |
| Recent CVEs | chosen in T6.1 | CVEs published after the training cutoff of both models, with a known vulnerable location and a published CVSS vector | severity, and a check that results don't depend on training data |
| Labeled duplicate groups | made in T6.3 | duplicates in the combined analyzer output for PyGoat, WebGoat and Juice Shop, labeled by hand | deduplication |
| Labeled Juice Shop sample | made in T6.3 | about 100 Juice Shop findings labeled as true or false positives, using its documented list of vulnerabilities | false-positive check, JavaScript/TypeScript |

### Target applications

| Application | Language | Version we pin |
|---|---|---|
| OWASP PyGoat | Python | commit `2aa4cc1` (1 Nov 2026), after release v3.0.0 |
| OWASP WebGoat | Java | v2026.5, needs Java 25 |
| OWASP Juice Shop | JavaScript/TypeScript | v20.3.0, needs Node.js 22 to 26 |

We scan these applications' source code and run them only as local Docker copies, for the PoC check (S1).

## Out of scope

- Confidential code, such as a paid review of a client's private repository. Sending it to hosted LLM APIs would expose it, and we have no compute for self-hosted models. The provider interface keeps that option open for later.
- Self-hosted models.
- Automatic submission to real bug bounty programs. A person approves every finding, and submission is tested only against a mock server (S4).
- Testing live systems. PoC code runs only against local copies of the target.
