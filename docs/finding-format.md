# Finding format

Every analyzer writes SARIF 2.1.0, but each one fills it differently. Each plug-in has an adapter that turns its SARIF file into findings in the one format below. Everything after the scan works only with this format: the findings store keeps it in the `findings` and `locations` tables (docs/database.md), and the triage agent reads it (triage API in docs/interfaces.md).

One SARIF result becomes one finding. Grouping duplicates happens later, in deduplication (T3.2).

## Fields

| Field | Type | Required | Where it comes from in SARIF | Meaning |
|---|---|---|---|---|
| `finding_id` | string | yes | assigned by the findings store | |
| `scan_id` | string | yes | assigned by the scan service | the scan that produced the finding |
| `run_id` | string | yes | assigned by the runner | the plug-in run that produced it. The run records the image digest and the tool and rules versions. |
| `tool` | string | yes | the plug-in manifest's `name` | the plug-in's ID, such as `semgrep`. The tool's own name, such as "Semgrep OSS" in `tool.driver.name`, stays in `raw`. |
| `tool_version` | string | yes | the plug-in run, which takes it from the manifest's `versions.tool` | not taken from SARIF, because tools fill it wrongly: Gitleaks 8.30.1 writes `v8.0.0`, and SpotBugs and the ESLint formatter leave `semanticVersion` out. The SARIF value stays in `raw`. |
| `rule_id` | string | yes | `result.ruleId`, else `result.rule.id`, else the `id` of the rule at `result.ruleIndex` | |
| `rule_description` | string | no | the rule's `fullDescription.text`, else its `shortDescription.text` | what the rule looks for |
| `rule_help_uri` | string | no | the rule's `helpUri` | |
| `cwe` | list of strings | yes, can be empty | the rule's tags, or its relationships to the CWE taxonomy (see below) | CWE IDs in the form `CWE-89` |
| `message` | string | yes | `result.message.text`. If the result has only `message.id`, the rule's `messageStrings` with `message.arguments` filled in. | what the tool says about this result |
| `tool_severity` | `error`, `warning`, `note` or `none` | yes | `result.level`, else the rule's `defaultConfiguration.level`, else `warning`, which is the SARIF default | |
| `tool_score` | number from 0 to 10 | no | the rule's `properties.security-severity` | the tool's own numeric severity, when it gives one. None of our five tools does: no rule of Semgrep, Bandit, SpotBugs, ESLint or Gitleaks has this property. So the severity baseline in Table 5 of the proposal ("the analyzer's own severity") needs a mapping from `tool_severity`, which the evaluation defines. |
| `tool_confidence` | `high`, `medium` or `low` | no | depends on the tool (see below) | how sure the tool is |
| `location` | location | yes | `result.locations[0].physicalLocation` | where the finding is |
| `related_locations` | list of locations | no | `result.relatedLocations` | other places the tool points to |
| `data_flow` | list of flow steps | no | `result.codeFlows[0].threadFlows[0].locations` | the path from the source to the flagged call. None of our five tools writes code flows, so this stays empty for now. It is kept for tools that do, such as CodeQL. |
| `fingerprint` | string | yes | computed by the adapter (see below) | stays the same for the same finding across scans of different commits |
| `fingerprint_ambiguous` | boolean | yes | computed by the adapter (see below) | true when another finding in the same run has the same rule, file and flagged code, so a match with an earlier scan is less certain |
| `context_hash` | string | yes | computed by the adapter (see below) | a hash of the code around the finding, used to decide whether an earlier review still applies |
| `suppressed` | boolean | yes | true when the tool accepted one of the result's `suppressions`: one without a `status`, or with `accepted` | the scanned code asked the tool to ignore this result, for example with a `# nosemgrep` comment. The finding is kept and the review screen shows the mark. |
| `tool_fingerprint` | string | no | `result.partialFingerprints` or `result.fingerprints` | the tool's own fingerprint, kept only when the adapter knows it is stable |
| `language` | string | no | the file extension | `python`, `java`, `javascript`, `typescript`, `html` for templates, or `other` for configuration and other files. A third of the Semgrep findings on PyGoat are in HTML templates. |
| `raw` | object | yes | the whole SARIF result, without NUL characters, and without its snippets when the adapter masks lines | kept so we can check or redo the mapping later |

A location has these fields:

| Field | Type | Required | Where it comes from | Meaning |
|---|---|---|---|---|
| `file` | string | yes | `artifactLocation.uri`, normalized as described below | path relative to the repository root, with `/` as the separator |
| `start_line` | integer | yes | `region.startLine` | starts at 1 |
| `end_line` | integer | yes | `region.endLine`, else `start_line` | |
| `start_column`, `end_column` | integer | no | `region.startColumn`, `region.endColumn` | start at 1 |
| `snippet` | string | no | `region.snippet.text`, else the lines read from the checkout. For Gitleaks, the flagged lines replaced by `REDACTED` (see below). | the flagged code |

A flow step is a location plus `step`, its position in the path starting at 1, and `message`, from the step's `location.message.text` when the tool gives one.

If a result has more than one code flow, the finding keeps the first one, and the others stay in `raw`.

## How the adapters map SARIF

### Rules

The adapter finds the result's rule in `tool.driver.rules`, by `ruleIndex` or else by `ruleId`. When `result.rule.toolComponent` points to an extension, it looks in that extension's `rules` instead. Semgrep, for example, gives no `ruleIndex`, so its adapter finds rules by ID.

### File paths

1. Parse the URI with a URI parser, not by cutting strings. If it has a `uriBaseId` that `originalUriBaseIds` defines, resolve it against that base, and resolve the base's own `uriBaseId` the same way.
2. For a `file:` URI, take its path and decode percent-encoded characters. Both forms occur: `file:///src/...` and `file:/src/...`, which SpotBugs writes. A URI without a scheme and without a known `uriBaseId` is taken as a literal path, because Semgrep writes raw file names there: in `/src/lib#1/app.py`, the `#` is part of the name. Only if that path doesn't exist is it decoded.
3. Remove the `/src/` prefix, where the plug-in container mounts the checkout. Semgrep writes absolute paths such as `/src/app/views.py` even though it also sets `uriBaseId` to `%SRCROOT%`, and it leaves `originalUriBaseIds` out. SpotBugs gets its source roots under /src (docs/interfaces.md), so its paths end up there too.
4. If the path doesn't exist but a source root plus the path does, use that. SpotBugs writes paths relative to a Java source root, such as `com/example/Dao.java`, when it doesn't know the root. The adapter tries each source root that the Java build step listed, and uses the path only if exactly one matches.
5. The result must now be a relative path inside the repository, with no `..`, to a regular file in the checkout, and its start line must be inside the file. Otherwise the adapter drops the result and adds a warning to the run's log. One result that can't be mapped never stops the rest of the run.

### CWE

Tools put CWE IDs in different places. The adapter accepts all of these and turns each into `CWE-<number>`, without leading zeros:

| Form | Used by | Example |
|---|---|---|
| a rule tag that starts with the ID | Semgrep | `CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')` |
| a rule tag in CodeQL's form | CodeQL and tools that copy it | `external/cwe/cwe-089` |
| a relationship from the rule to the CWE taxonomy | tools that use SARIF taxonomies | `relationships[].target` with `id` `89` and `toolComponent.name` `CWE` |
| `result.taxa` with the same target | the same tools, per result | |

The list has no duplicates and is sorted by number. When a tool never gives CWEs, its adapter adds them:

- The Gitleaks adapter sets `CWE-798` (hard-coded credentials) on every finding.
- The ESLint adapter maps the 15 rules of eslint-plugin-security 4.2.1, which carry no CWE at all. This is our own mapping, checked again in T2.2:

| Rule | CWE |
|---|---|
| `detect-bidi-characters`, `detect-invisible-characters` | CWE-1007 |
| `detect-buffer-noassert` | CWE-119 |
| `detect-child-process` | CWE-78 |
| `detect-disable-mustache-escape` | CWE-79 |
| `detect-eval-with-expression` | CWE-95 |
| `detect-new-buffer` | CWE-908 |
| `detect-no-csrf-before-method-override` | CWE-352 |
| `detect-non-literal-fs-filename` | CWE-22 |
| `detect-non-literal-regexp`, `detect-unsafe-regex` | CWE-1333 |
| `detect-non-literal-require` | CWE-829 |
| `detect-object-injection` | CWE-1321 |
| `detect-possible-timing-attacks` | CWE-208 |
| `detect-pseudoRandomBytes` | CWE-338 |

The adapter keeps the CWEs the tool gives, even when they look wrong. Semgrep tags two of its SQL injection rules with CWE-915 and CWE-704, for example. Deduplication and the triage agent deal with that, not the adapter.

### Which results become findings

Results whose `kind` is missing or `fail` become findings. Results with another `kind`, such as `pass` or `notApplicable`, don't, and the run's log counts them.

Suppressed results are kept. The scanned repository is not ours, so a `# nosemgrep` or `# nosec` comment in it must not be able to hide a finding from Sieve (requirement N4). The plug-ins turn in-source suppression off where the tool allows it (docs/interfaces.md). When the tool still reports a result as suppressed, the adapter keeps it and sets `suppressed` to true.

### Confidence

| Tool | Where the confidence comes from |
|---|---|
| Semgrep | the rule tags `HIGH CONFIDENCE`, `MEDIUM CONFIDENCE` and `LOW CONFIDENCE`. Semgrep also writes `properties.precision`, but it is `very-high` on all 378 rules of the Python rule set, so the adapter ignores it. |
| Other tools | checked against real output in T2.2. Tools that don't report a confidence leave the field empty. |

## Fingerprint

A fingerprint identifies the same finding in scans of different commits, so a finding that was already reviewed is not shown again (requirement F3).

We compute our own fingerprint for every tool, because tools don't give a stable one. Semgrep, run without logging in to Semgrep's platform, writes `"matchBasedId/v1": "requires login"` in `fingerprints` for every result: all 227 results on PyGoat have this same value. When a tool's fingerprint is stable, the adapter also keeps it in `tool_fingerprint`, but `fingerprint` is always ours, so all tools behave the same.

The fingerprint is the first 32 hex characters of a SHA-256 hash over five values, prefixed with `v1:`:

1. the tool, such as `semgrep`
2. the rule ID
3. the file path
4. the flagged lines from the checkout, from `start_line` to `end_line`, normalized: all whitespace removed, single quotes turned into double quotes, and empty lines dropped
5. the occurrence: when several findings in one run have the same first four values, their position in that list, ordered by line and column, starting at 0

```python
import hashlib
import re


def normalize(lines: list[str]) -> str:
    out = (re.sub(r"\s+", "", line).replace("'", '"') for line in lines)
    return "\n".join(line for line in out if line)


def fingerprint(tool: str, rule_id: str, file: str, lines: list[str], occurrence: int) -> str:
    key = "\x1f".join([tool, rule_id, file, normalize(lines), str(occurrence)])
    return "v1:" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def context_hash(file_lines: list[str], start_line: int, end_line: int, window: int = 10) -> str:
    lines = file_lines[max(0, start_line - 1 - window) : end_line + window]
    return "c1:" + hashlib.sha256(normalize(lines).encode("utf-8")).hexdigest()[:32]
```

Removing whitespace and unifying quotes means that running a code formatter, such as Black, doesn't make a finding look new. A formatter changes `render(request,'login')` into `render(request, "login")`, and both give the same text here.

The adapter reads the checkout through the shared checkout reader (docs/class-diagrams.md), which refuses any path that leaves the checkout. It reads lines as UTF-8 and replaces bytes that aren't valid UTF-8, so a file in another encoding doesn't stop the run. If the file can't be read at all, it uses the SARIF snippet instead, and leaves the context hash empty, so no earlier review can hide the finding.

For Gitleaks findings, the adapter replaces every flagged line, from `start_line` to `end_line`, with `REDACTED` before it hashes the lines or stores them as the snippet. It masks whole lines, not the reported columns, because Gitleaks 8.30.1 reports columns that are off by one and private keys that span several lines. Every snippet the adapter stores is taken from the masked lines, and the tool's own snippets are removed from `raw`, so the Gitleaks finding itself never stores the secret. Other tools can still flag the same line, such as Semgrep's rules for hard-coded keys, and their snippets keep the code as it is: it is public code, as docs/data-flow.md explains.

The hash leaves out line numbers on purpose. When code above a finding is added or removed, the finding keeps its fingerprint. We checked this on the example below: after adding three lines at the top of the file, the finding moved from line 57 to line 60 and its fingerprint and context hash stayed the same.

A fingerprint changes, and the finding counts as new, when:

- the flagged lines themselves change
- the file is renamed or moved
- the rule ID changes. This happens when we update the rules on purpose, and also if the Semgrep plug-in's command changes, because Semgrep builds rule IDs from the path of the rules folder. The command is therefore part of the plug-in's version, like the rules.

The `v1:` prefix lets us change the method later without mixing old and new values. Deduplication matches findings from repeated scans of the same repository by their fingerprint.

### Ambiguous fingerprints

The occurrence number is the one weak point. When a file has two identical flagged pieces of code for the same rule, such as two functions that both start with `@csrf_exempt`, the fingerprints differ only by the occurrence. If code is added between them, or one is deleted, the numbers can shift, and a finding could be matched to the wrong one in the earlier scan. Hiding a real bug because a different copy was reviewed as a false positive is the worst mistake this matching can make.

So the adapter sets `fingerprint_ambiguous` to true on every finding whose first four values are shared with another finding in the same run. Two scans of the same commit are the exception: the code is identical, so the occurrence numbers are exact, and the matching treats such findings as not ambiguous.

### Context hash

The fingerprint covers only the flagged lines, but whether a finding is a false positive often depends on the code around them. For example, `c.execute(sql_query)` can be safe while `sql_query` is built from a constant, and become a real SQL injection when a later commit builds it from user input two lines above. The flagged line and its fingerprint stay the same.

So each finding also gets a context hash over the flagged lines plus 10 lines before and after, normalized the same way. An earlier review applies to a new finding only if the context hash is the same too.

This doesn't catch a change that is more than 10 lines away, such as a change in another function that now passes user input. That case is still hidden, and it is the remaining limit of the matching.

### When a finding is hidden

Deduplication links each new finding to the earlier findings of the same repository with the same fingerprint. The new finding is hidden from the review queue, with the earlier decision applied, only when all of these hold:

- An earlier finding with that fingerprint has a review. The latest such review counts, from any earlier scan, not only the previous one, so a finding that was hidden in the second scan stays hidden in the third.
- That earlier finding has the same context hash, and it isn't empty.
- Neither finding is ambiguous, except in two scans of the same commit.
- The tool is not Gitleaks. Its fingerprint hides the secret, so a test key and a real key on the same line look the same.

In every other case the finding is shown again, with the earlier decision as a suggestion. Showing a finding twice costs a reviewer a few seconds, while hiding a real bug defeats the purpose of Sieve, so every doubt goes towards showing.

### How well it works

We ran the Semgrep plug-in on three versions of PyGoat and on commit `2aa4cc1` twice, and compared the findings. We counted two findings as truly the same when they have the same rule and file, and a line-by-line comparison of the two versions, ignoring whitespace and quote style, maps the old start line to the new one.

| Scans compared | Truly the same | Matched correctly | Missed | Matched to the wrong finding | Hidden by the rules above |
|---|---|---|---|---|---|
| two separate scans of commit `2aa4cc1` | 153 | 153 | 0 | 0 | 153 |
| v3.0.0 and `2aa4cc1`, 11 days apart | 153 | 153 | 0 | 0 | 151. The 2 ambiguous ones are shown again. |
| v2.0.1 and `2aa4cc1`, 547 changed files apart | 3 | 3 | 0 | 0 | 0. The code around all three changed. |

What the test covers, and what it doesn't:

- Between v3.0.0 and `2aa4cc1`, the only change near a finding moved three findings down by one or two lines. So that row tests line shifts, not edits.
- Between v2.0.1 and `2aa4cc1`, the three findings that are truly the same were only reformatted: quotes and spaces. A first version of the fingerprint that only collapsed whitespace missed all three. Removing whitespace and unifying quotes fixed that.
- A finding whose flagged line was edited can't be in the "truly the same" column, because the comparison maps only unchanged lines. So the test can't show how often such findings are shown again. They are always shown again, which is the safe side.

No finding was ever matched to the wrong one, and none was hidden wrongly.

## Example: Semgrep on PyGoat

We ran the Semgrep plug-in's command (docs/interfaces.md) with Semgrep 1.183.0 and semgrep-rules at commit `16b9e6d`, on OWASP PyGoat at commit `2aa4cc1`. The lab in `dockerized_labs/sql_injection_lab/app.py` builds an SQL query from the login form with an f-string:

```python
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # Vulnerable SQL query construction (intentional)
        sql_query = (
            f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        )

        try:
            conn = sqlite3.connect("database.db")
            c = conn.cursor()
            result = c.execute(sql_query).fetchone()
```

### In SARIF

The result for line 57, and the parts of its run that the adapter reads. The rule's `help` text is left out.

```json
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Semgrep OSS",
          "semanticVersion": "1.183.0",
          "rules": [
            {
              "id": "python.lang.security.audit.formatted-sql-query",
              "name": "python.lang.security.audit.formatted-sql-query",
              "shortDescription": {"text": "Semgrep Finding: python.lang.security.audit.formatted-sql-query"},
              "fullDescription": {"text": "Detected possible formatted SQL query. Use parameterized queries instead."},
              "defaultConfiguration": {"level": "warning"},
              "properties": {
                "precision": "very-high",
                "tags": [
                  "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                  "LOW CONFIDENCE",
                  "OWASP-A01:2017 - Injection",
                  "OWASP-A03:2021 - Injection",
                  "OWASP-A05:2025 - Injection",
                  "security"
                ]
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "python.lang.security.audit.formatted-sql-query",
          "message": {"text": "Detected possible formatted SQL query. Use parameterized queries instead."},
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "/src/dockerized_labs/sql_injection_lab/app.py",
                  "uriBaseId": "%SRCROOT%"
                },
                "region": {
                  "startLine": 57,
                  "startColumn": 22,
                  "endLine": 57,
                  "endColumn": 42,
                  "snippet": {"text": "            result = c.execute(sql_query).fetchone()"}
                }
              }
            }
          ],
          "fingerprints": {"matchBasedId/v1": "requires login"},
          "properties": {}
        }
      ]
    }
  ]
}
```

### In our format

The IDs are illustrative. Everything else is what the adapter produces from the SARIF above, including the fingerprint and the context hash.

```json
{
  "finding_id": "fnd-0187",
  "scan_id": "scan-0007",
  "run_id": "run-0021",
  "tool": "semgrep",
  "tool_version": "1.183.0",
  "rule_id": "python.lang.security.audit.formatted-sql-query",
  "rule_description": "Detected possible formatted SQL query. Use parameterized queries instead.",
  "rule_help_uri": null,
  "cwe": ["CWE-89"],
  "message": "Detected possible formatted SQL query. Use parameterized queries instead.",
  "tool_severity": "warning",
  "tool_score": null,
  "tool_confidence": "low",
  "location": {
    "file": "dockerized_labs/sql_injection_lab/app.py",
    "start_line": 57,
    "end_line": 57,
    "start_column": 22,
    "end_column": 42,
    "snippet": "            result = c.execute(sql_query).fetchone()"
  },
  "related_locations": [],
  "data_flow": [],
  "fingerprint": "v1:418dc3c913dc63ec1ee12209f03b55f1",
  "fingerprint_ambiguous": false,
  "context_hash": "c1:a5b7da088c06eb2371e6939f52ee1e61",
  "suppressed": false,
  "tool_fingerprint": null,
  "language": "python",
  "raw": {
    "ruleId": "python.lang.security.audit.formatted-sql-query",
    "message": {"text": "Detected possible formatted SQL query. Use parameterized queries instead."},
    "locations": [
      {
        "physicalLocation": {
          "artifactLocation": {"uri": "/src/dockerized_labs/sql_injection_lab/app.py", "uriBaseId": "%SRCROOT%"},
          "region": {
            "startLine": 57,
            "startColumn": 22,
            "endLine": 57,
            "endColumn": 42,
            "snippet": {"text": "            result = c.execute(sql_query).fetchone()"}
          }
        }
      }
    ],
    "fingerprints": {"matchBasedId/v1": "requires login"},
    "properties": {}
  }
}
```

How each value was mapped:

- `tool_severity` is `warning` from the rule's `defaultConfiguration`, because Semgrep sets no `level` on its results.
- `cwe` comes from the rule's first tag, `tool_confidence` from its `LOW CONFIDENCE` tag.
- `file` lost the `/src/` prefix.
- `tool_fingerprint` is empty, because `requires login` is not a real fingerprint. Semgrep fills it only for users logged in to its platform, and our plug-ins have no network.
- `tool_version` comes from the manifest, which matches the SARIF here.
- `data_flow` is empty. Semgrep reported no code flows on PyGoat, even for its taint rules and with `--dataflow-traces` turned on. The triage agent collects the enclosing function itself, and can read more code with its tools (triage API).

### The same bug, reported six times

This one SQL injection gives six Semgrep results from five rules:

| Rule | Lines | CWE in the rule |
|---|---|---|
| `python.django.security.injection.sql.sql-injection-db-cursor-execute` | 46 to 69 | CWE-89 |
| `python.django.security.injection.sql.sql-injection-db-cursor-execute` | 47 to 69 | CWE-89 |
| `python.django.security.injection.tainted-sql-string` | 50 to 52 | CWE-915 |
| `python.flask.security.injection.tainted-sql-string` | 50 to 52 | CWE-704 |
| `python.lang.security.audit.formatted-sql-query` | 57 | CWE-89 |
| `python.sqlalchemy.security.sqlalchemy-execute-raw-query` | 57 | CWE-89 |

So duplicates come not only from different tools but also from one tool, with overlapping line ranges and CWEs that don't always match. Deduplication (T3.2) has to group all six, and these results are a good first test case for it.
