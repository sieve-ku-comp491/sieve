# Requirements specification

This document lists what Sieve must do (functional requirements, F) and the qualities it must have (non-functional requirements, N). Each requirement has an acceptance test that someone other than its author can run or check. It expands Table 1 of the project proposal, and later tasks and the final evaluation are checked against it.

Sieve is for security researchers who review public source code, such as hunters on open-source bug bounty programs. It runs static analyzers on a repository, groups duplicate findings, checks each finding for false positives with an LLM, scores its severity, and lets a person approve each finding before a report is exported.

Each requirement names the task where it is built and the task where it is verified.

## Functional requirements

### F1 Run SARIF analyzers as plug-ins

To be written by Ali.

### F2 Scan only repositories in the scope file

To be written by Ali.

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

To be written by Ali.

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

To be written by Ali.

### N6 Reproducibility

To be written by Ali.

### N7 Usability

To be written by Ali.

## Stretch requirements

These are built only after the minimum viable product works end to end (M5.3, week 7).

| ID | Requirement | Acceptance test | Task |
|---|---|---|---|
| S1 | A PoC guide lists the steps to reproduce an approved finding, and a sandboxed check runs the PoC against a local Docker copy of the target and marks the finding as verified. | A PoC runs in the sandbox for at least one confirmed finding in each of PyGoat, WebGoat and Juice Shop. | T4.3 |
| S2 | Reports can be exported in HackerOne format (CVSS-based severity) and Bugcrowd format (VRT priority). | Both formats fill every field of the platforms' report forms. | T4.2 |
| S3 | A program's scope is imported through the HackerOne Hacker API, and Sieve refuses to report on assets outside it. | The scope check rejects every out-of-scope asset in our tests. | T5.3 |
| S4 | Submission is built and tested only against a mock platform server. | A test submission reaches the mock server, and no request goes to a real platform. | T5.4 |

## Analyzers, datasets and target applications

To be written by Ali.

## Out of scope

- Confidential code, such as a paid review of a client's private repository. Sending it to hosted LLM APIs would expose it, and we have no compute for self-hosted models. The provider interface keeps that option open for later.
- Self-hosted models.
- Automatic submission to real bug bounty programs. A person approves every finding, and submission is tested only against a mock server (S4).
- Testing live systems. PoC code runs only against local copies of the target.
