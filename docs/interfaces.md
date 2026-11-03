# Component interfaces

This document fixes the interfaces between Sieve's components, so each of us can build one side without waiting for the other. The finding format itself is in docs/finding-format.md.

- Plug-in contract: how the scan service runs an analyzer.
- Triage API: what the triage agent reads and writes.
- Report schema: what the report service produces from an approved finding.

## Plug-in contract

To be written by Ali.

## Triage API

The triage agent takes the findings of one scan from the findings store, groups duplicates, checks each finding or group for false positives, scores its severity, and writes the results back. It reaches LLMs only through the provider interface (docs/class-diagrams.md), so every call is cached, counted against the run's budget and logged.

### Entry point

    triage_scan(scan_id, budget_usd, models) -> TriageRun

`models` names a cheaper and a stronger model. Each finding goes to the cheaper model first, and only the findings it is unsure about go to the stronger one.

A TriageRun records the scan, the models, the budget, the cost so far and a status: `running`, `finished` or `stopped_at_budget`. When the budget runs out, the run stops. Findings that were already triaged keep their results, and the rest stay untriaged, so a new run picks them up.

### Steps

| Step | Input | Output |
|---|---|---|
| Group | the scan's findings | duplicate groups, each with a record of how it was formed |
| Check | one triage item | a verdict |
| Score | one triage item and its verdict | a severity |

A triage item is one finding, or one duplicate group with its member findings. A group is checked and scored once, and the result applies to all of its members.

### Triage item

| Field | Type | Meaning |
|---|---|---|
| `item_id` | string | the finding ID, or the group ID for a duplicate group |
| `findings` | list of findings | the member findings, in the format of docs/finding-format.md |
| `context.function` | string | the enclosing function, extracted with tree-sitter |
| `context.location` | file, start line, end line | where that function is |
| `context.data_flow` | list of locations, optional | the path from user input to the flagged call, when the analyzer reports one |
| `context.injection_suspected` | boolean | true when the code has comments or strings that look like instructions to an AI |
| `repo` | scan ID and commit | the checkout that the agent's tools read from |

While it decides, the agent can call two tools:

- `read_file(path, start_line, end_line)` returns lines from the scanned checkout.
- `find_definition(symbol)` returns where a function, class or variable is defined, with its code.

Both tools read only from the scanned checkout. The agent can make at most 5 tool calls per item.

Code goes into a prompt only inside a marked data block, and the prompt tells the model that the block is data to analyze, never instructions to follow. This limits prompt injection through comments in the scanned code (requirement N4).

### Verdict

| Field | Type | Meaning |
|---|---|---|
| `verdict` | `true_positive`, `false_positive` or `unsure` | the decision |
| `reasoning` | string | why, in a few sentences a reviewer can check |
| `cited_lines` | list of file, start line, end line | the code the reasoning relies on |
| `injection_suspected` | boolean | copied from the item, so the review screen can flag it |
| `model` | string | the exact version of the model that gave the final verdict |
| `llm_calls` | list of call IDs | every call made for this verdict, in the LLM calls table |

### Severity

| Field | Type | Meaning |
|---|---|---|
| `cvss_v4.vector` | string | the CVSS v4.0 base vector |
| `cvss_v4.score` | number | computed from the vector with FIRST's CVSS v4.0 algorithm, never chosen by the LLM |
| `cvss_v4.level` | `none`, `low`, `medium`, `high` or `critical` | follows from the score |
| `cvss_v4.justifications` | metric to string | one line for each of the 11 base metrics |
| `cvss_v31` | the same four fields for CVSS v3.1, optional | filled only in evaluation runs, for CVEs that only have a v3.1 vector |
| `llm_calls` | list of call IDs | the calls that chose the metrics |

### Example

A triage result for a SQL injection finding. The values are illustrative.

```json
{
  "item_id": "grp-0042",
  "verdict": {
    "verdict": "true_positive",
    "reasoning": "The username parameter from the request is formatted into the SQL string on line 58 and passed to cursor.execute on line 59 without query parameters. Nothing validates it in between.",
    "cited_lines": [{"file": "app/views.py", "start_line": 52, "end_line": 59}],
    "injection_suspected": false,
    "model": "<exact model version>",
    "llm_calls": ["call-0193", "call-0194"]
  },
  "severity": {
    "cvss_v4": {
      "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
      "score": 9.3,
      "level": "critical",
      "justifications": {
        "AV": "Reachable over the network through the login form.",
        "AC": "A single request is enough, with no special conditions.",
        "AT": "No deployment conditions are needed.",
        "PR": "The form is available before login.",
        "UI": "No other user has to do anything.",
        "VC": "The attacker can read every table in the database.",
        "VI": "The attacker can change or delete rows.",
        "VA": "Dropping tables makes the application unusable.",
        "SC": "No other system is affected.",
        "SI": "No other system is affected.",
        "SA": "No other system is affected."
      }
    },
    "llm_calls": ["call-0195"]
  }
}
```

## Report schema

The report service turns an approved finding into a report. It drafts the text through the provider interface, and the reviewer can edit any field before export. Only approved findings get a report (requirements F5 and F6).

| Field | Type | Meaning |
|---|---|---|
| `report_id` | string | |
| `finding_ids` | list of strings | the approved finding, or every member of an approved group |
| `title` | string | the vulnerability type and where it is, for example "SQL injection in the login form" |
| `summary` | string | two or three sentences on what is wrong and where |
| `impact` | string | what an attacker can do, consistent with the severity |
| `steps_to_reproduce` | list of strings | numbered steps a program's triager can follow |
| `fix` | string | the change that removes the issue, with a code example when it helps |
| `references` | list of URLs | at least the CWE entry, plus any documentation the fix relies on |
| `severity` | the `cvss_v4` fields from the triage result | copied from the finding, or as edited by the reviewer |
| `locations` | list of file and line | the affected code |
| `status` | `draft` or `exported` | |
| `created_at`, `exported_at` | timestamps | |

Markdown is the core export format, with one file per report:

```markdown
# SQL injection in the login form

Severity: Critical (CVSS 4.0 score 9.3)
Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N

## Summary

## Impact

## Steps to reproduce

1.

## Fix

## References

- https://cwe.mitre.org/data/definitions/89.html
```

The HackerOne and Bugcrowd formats are stretch goals (T4.2). They use the same fields, with HackerOne's CVSS-based severity and Bugcrowd's VRT priority.
