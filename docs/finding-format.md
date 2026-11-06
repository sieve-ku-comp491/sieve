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
| `tool_version` | string | yes | `tool.driver.semanticVersion`, else `tool.driver.version` | |
| `rule_id` | string | yes | `result.ruleId`, else `result.rule.id`, else the `id` of the rule at `result.ruleIndex` | |
| `rule_description` | string | no | the rule's `fullDescription.text`, else its `shortDescription.text` | what the rule looks for |
| `rule_help_uri` | string | no | the rule's `helpUri` | |
| `cwe` | list of strings | yes, can be empty | the rule's tags, or its relationships to the CWE taxonomy (see below) | CWE IDs in the form `CWE-89` |
| `message` | string | yes | `result.message.text`. If the result has only `message.id`, the rule's `messageStrings` with `message.arguments` filled in. | what the tool says about this result |
| `tool_severity` | `error`, `warning`, `note` or `none` | yes | `result.level`, else the rule's `defaultConfiguration.level`, else `warning`, which is the SARIF default | |
| `tool_score` | number from 0 to 10 | no | the rule's `properties.security-severity` | the tool's own numeric severity, when it gives one. The severity evaluation compares our CVSS scores against it (Table 5 of the proposal). |
| `tool_confidence` | `high`, `medium` or `low` | no | depends on the tool (see below) | how sure the tool is |
| `location` | location | yes | `result.locations[0].physicalLocation` | where the finding is |
| `related_locations` | list of locations | no | `result.relatedLocations` | other places the tool points to |
| `data_flow` | list of flow steps | no | `result.codeFlows[0].threadFlows[0].locations` | the path from the source to the flagged call, when the tool reports one |
| `fingerprint` | string | yes | computed by the adapter (see below) | stays the same for the same finding across scans of different commits |
| `fingerprint_ambiguous` | boolean | yes | computed by the adapter (see below) | true when another finding in the same run has the same rule, file and flagged code, so a match with an earlier scan is less certain |
| `tool_fingerprint` | string | no | `result.partialFingerprints` or `result.fingerprints` | the tool's own fingerprint, kept only when the adapter knows it is stable |
| `language` | string | no | the file extension | `python`, `java`, `javascript` or `typescript` |
| `raw` | object | yes | the whole SARIF result | kept so we can check or redo the mapping later |

A location has these fields:

| Field | Type | Required | Where it comes from | Meaning |
|---|---|---|---|---|
| `file` | string | yes | `artifactLocation.uri`, normalized as described below | path relative to the repository root, with `/` as the separator |
| `start_line` | integer | yes | `region.startLine` | starts at 1 |
| `end_line` | integer | yes | `region.endLine`, else `start_line` | |
| `start_column`, `end_column` | integer | no | `region.startColumn`, `region.endColumn` | start at 1 |
| `snippet` | string | no | `region.snippet.text`, else the lines read from the checkout. For Gitleaks, only the redacted text from SARIF. | the flagged code |

A flow step is a location plus `step`, its position in the path starting at 1, and `message`, from the step's `location.message.text` when the tool gives one.

If a result has more than one code flow, the finding keeps the first one, and the others stay in `raw`.

## How the adapters map SARIF

### Rules

The adapter finds the result's rule in `tool.driver.rules`, by `ruleIndex` or else by `ruleId`. When `result.rule.toolComponent` points to an extension, it looks in that extension's `rules` instead. Semgrep, for example, gives no `ruleIndex`, so its adapter finds rules by ID.

### File paths

1. If the URI has a `uriBaseId` that `originalUriBaseIds` defines, resolve it against that base.
2. Remove a `file://` scheme and decode percent-encoded characters.
3. Remove the `/src/` prefix, where the plug-in container mounts the checkout. Semgrep writes absolute paths such as `/src/app/views.py` even though it also sets `uriBaseId` to `%SRCROOT%`, and it leaves `originalUriBaseIds` out.
4. The result must now be a relative path inside the repository, with no `..`, to a file that exists in the checkout. Otherwise the adapter drops the result and adds a warning to the run's log.

### CWE

Tools put CWE IDs in different places. The adapter accepts all of these and turns each into `CWE-<number>`, without leading zeros:

| Form | Used by | Example |
|---|---|---|
| a rule tag that starts with the ID | Semgrep | `CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')` |
| a rule tag in CodeQL's form | CodeQL and tools that copy it | `external/cwe/cwe-089` |
| a relationship from the rule to the CWE taxonomy | tools that use SARIF taxonomies | `relationships[].target` with `id` `89` and `toolComponent.name` `CWE` |
| `result.taxa` with the same target | the same tools, per result | |

The list has no duplicates and is sorted by number. When a tool never gives CWEs, its adapter adds them: the Gitleaks adapter sets `CWE-798` (hard-coded credentials) on every finding.

The adapter keeps the CWEs the tool gives, even when they look wrong. Semgrep tags two of its SQL injection rules with CWE-915 and CWE-704, for example. Deduplication and the triage agent deal with that, not the adapter.

### Which results become findings

- Results whose `kind` is missing or `fail`. Results with another `kind`, such as `pass` or `notApplicable`, are not findings.
- Results without `suppressions`, or whose suppressions were all rejected. Code that is suppressed in the source with a comment is not reported again.

The run's log counts the results dropped for each reason.

### Confidence

| Tool | Where the confidence comes from |
|---|---|
| Semgrep | the rule tags `HIGH CONFIDENCE`, `MEDIUM CONFIDENCE` and `LOW CONFIDENCE`. Semgrep also writes `properties.precision`, but it is `very-high` on all 378 rules of the Python rule set, so the adapter ignores it. |
| Other tools | checked against real output in T2.2. Tools that don't report a confidence leave the field empty. |

## Fingerprint

A fingerprint identifies the same finding in scans of different commits, so a finding that was already reviewed is not shown again (requirement F3).

We compute our own fingerprint for every tool, because tools don't give a stable one. Semgrep OSS writes `"matchBasedId/v1": "requires login"` in `fingerprints` for every result: all 227 results on PyGoat have this same value. When a tool's fingerprint is stable, the adapter also keeps it in `tool_fingerprint`, but `fingerprint` is always ours, so all tools behave the same.

The fingerprint is the first 32 hex characters of a SHA-256 hash over five values, prefixed with `v1:`:

1. the tool, such as `semgrep`
2. the rule ID
3. the file path
4. the flagged lines from the checkout, from `start_line` to `end_line`, with each line's whitespace collapsed to single spaces and trimmed
5. the occurrence: when several findings in one run have the same first four values, their position in that list, ordered by line and column, starting at 0

```python
import hashlib
import re


def normalize(lines: list[str]) -> str:
    return "\n".join(re.sub(r"\s+", " ", line).strip() for line in lines)


def fingerprint(tool: str, rule_id: str, file: str, lines: list[str], occurrence: int) -> str:
    key = "\x1f".join([tool, rule_id, file, normalize(lines), str(occurrence)])
    return "v1:" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]
```

The adapter reads the lines as UTF-8 and replaces bytes that aren't valid UTF-8, so a file in another encoding doesn't stop the run. If the file can't be read at all, it uses the SARIF snippet instead.

For Gitleaks findings, the adapter first replaces the flagged columns, which hold the secret, with `REDACTED`, both in the text it hashes and in the snippet it stores. The secret never reaches the findings store, not even as part of a hash.

The hash leaves out line numbers on purpose. When code above a finding is added or removed, the finding keeps its fingerprint. We checked this on the example below: after adding three lines at the top of the file, the finding moved from line 57 to line 60 and its fingerprint stayed the same. Collapsing whitespace means that indenting the code differently doesn't change it either.

A fingerprint changes, and the finding counts as new, when:

- the flagged lines themselves change
- the file is renamed or moved
- the rule ID changes, which happens only when we update the rules on purpose

The `v1:` prefix lets us change the method later without mixing old and new values. Deduplication matches findings from repeated scans of the same repository by their fingerprint.

### Ambiguous fingerprints

The occurrence number is the one weak point. When a file has two identical flagged pieces of code for the same rule, such as two functions that both start with `@csrf_exempt`, the fingerprints differ only by the occurrence. If code is added between them, or one is deleted, the numbers can shift, and a finding could be matched to the wrong one in the earlier scan. Hiding a real bug because a different copy was reviewed as a false positive is the worst mistake this matching can make.

So the adapter sets `fingerprint_ambiguous` to true on every finding whose first four values are shared with another finding in the same run. Deduplication still links such a finding to its match in the earlier scan, but the review screen shows it again with the earlier decision as a suggestion, instead of hiding it. Only findings that are not ambiguous in either scan are hidden.

### How well it works

We compared the fingerprints of three scans of PyGoat with the Semgrep plug-in. We counted two findings as truly the same when they have the same rule and file, and Git's line-by-line comparison of the two versions maps the old start line to the new one.

| Scans compared | Truly the same | Matched correctly | Missed, so shown again | Matched to the wrong finding | Ambiguous in the later scan |
|---|---|---|---|---|---|
| commit `2aa4cc1` twice | 153 | 153 | 0 | 0 | 2 of 153 |
| v3.0.0 and `2aa4cc1`, 11 days and 12 changed files apart | 153 | 153 | 0 | 0 | 2 of 153 |
| v2.0.1 and `2aa4cc1`, 547 changed files apart | 3 | 0 | 3 | 0 | 2 of 153 |

For normal rescans, every finding was matched. After a large rewrite, the three findings whose functions changed were shown again, which is the safe side of the trade-off.

We also tried hashing only the first flagged line, which is closer to how GitHub's code scanning builds its line hash, so that edits inside a long flagged region don't count as a new finding. It matched the first two pairs equally well, but on the third it matched three `@csrf_exempt` findings to the wrong functions. We kept the whole region.

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

The IDs are illustrative. Everything else is what the adapter produces from the SARIF above, including the fingerprint.

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
  "fingerprint": "v1:4aef0ff3eeeaa51051da86d7be561fee",
  "fingerprint_ambiguous": false,
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
- `tool_fingerprint` is empty, because `requires login` is not a real fingerprint.
- `data_flow` is empty. Semgrep OSS reported no code flows on PyGoat, even for its taint rules and with `--dataflow-traces` turned on. The triage agent collects the enclosing function itself, and can read more code with its tools (triage API).

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
