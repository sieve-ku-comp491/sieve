# Database

Sieve keeps its data in one PostgreSQL database, the findings store. This document describes its tables: the scan side (scans, analyzer runs, findings, locations and duplicate groups) and the review side (verdicts, reviews, reports and LLM calls). The findings store and API (T2.3) and the LLM call log (T3.1) create these tables.

## ER diagram

The scan side is complete. The review-side tables show only their keys and their links to the scan side, and Furkan adds their columns and the links between them.

```mermaid
erDiagram
  scans ||--o{ analyzer_runs : "runs"
  scans ||--o{ findings : "contains"
  analyzer_runs ||--o{ findings : "produced"
  findings ||--o{ locations : "has"
  scans ||--o{ duplicate_groups : "contains"
  duplicate_groups |o--|{ findings : "groups"
  findings |o--o{ findings : "matches an earlier"
  duplicate_groups }o--o| llm_calls : "decided by"
  findings |o--o{ verdicts : "judged in"
  duplicate_groups |o--o{ verdicts : "judged in"
  findings ||--o{ reviews : "reviewed in"
  reports }o--|{ findings : "covers"

  scans {
    uuid id PK
    text repo_url
    text commit_sha
    text requested_ref
    text status
    text error
    text_array languages
    timestamptz created_at
    timestamptz started_at
    timestamptz finished_at
  }
  analyzer_runs {
    uuid id PK
    uuid scan_id FK
    text plugin
    text image
    text image_digest
    text tool_version
    text rules_version
    text status
    text reason
    int exit_code
    int files_scanned
    int result_count
    int dropped_count
    text sarif_path
    text log_path
    timestamptz started_at
    timestamptz finished_at
  }
  findings {
    uuid id PK
    uuid scan_id FK
    uuid run_id FK
    uuid group_id FK
    uuid matched_finding_id FK
    text tool
    text tool_version
    text rule_id
    text rule_description
    text rule_help_uri
    text_array cwe
    text message
    text tool_severity
    numeric tool_score
    text tool_confidence
    text file
    int start_line
    int end_line
    int start_column
    int end_column
    text snippet
    text fingerprint
    bool fingerprint_ambiguous
    text tool_fingerprint
    text language
    jsonb raw
    timestamptz created_at
  }
  locations {
    bigint id PK
    uuid finding_id FK
    text kind
    int position
    text file
    int start_line
    int end_line
    int start_column
    int end_column
    text snippet
    text message
  }
  duplicate_groups {
    uuid id PK
    uuid scan_id FK
    uuid representative_finding_id FK
    text method
    text rule
    numeric similarity
    uuid llm_call_id FK
    text reason
    timestamptz created_at
  }
  verdicts {
    uuid id PK
    uuid finding_id FK
    uuid group_id FK
  }
  reviews {
    uuid id PK
    uuid finding_id FK
  }
  reports {
    uuid id PK
  }
  llm_calls {
    uuid id PK
  }
  jobs {
    uuid id PK
    text kind
    text status
    jsonb payload
    text error
    timestamptz created_at
    timestamptz started_at
    timestamptz finished_at
  }
```

`text_array` stands for PostgreSQL's `text[]`, and `bool` for `boolean`, because Mermaid can't show those names.

## Conventions

- Primary keys are UUIDs made by PostgreSQL with `gen_random_uuid()`, except `locations`, which has many small rows and uses a `bigint` identity.
- Values from a fixed list, such as statuses, are `text` with a `CHECK` constraint. Adding a value then needs only a new constraint, not a new PostgreSQL enum type.
- Times are `timestamptz`, stored in UTC.
- Deleting a finding deletes its locations. Every other foreign key blocks the delete, because reviews and verdicts must never lose the finding they refer to (requirement N3). We don't delete scans in normal use.

## Scan side

### scans

One row per scan of one commit of one repository.

| Column | Type | Can be empty | Meaning |
|---|---|---|---|
| `id` | uuid | no | primary key |
| `repo_url` | text | no | the repository URL, normalized as in the scope file check (requirement F2) |
| `commit_sha` | text | no | the full 40-character commit hash that was scanned |
| `requested_ref` | text | yes | the branch or tag the researcher asked for, if they didn't give a commit |
| `status` | text | no | `queued`, `running`, `completed`, `partial` or `failed`, as defined in docs/interfaces.md |
| `error` | text | yes | why the scan failed, for example a clone error |
| `languages` | text[] | no | the languages found in the checkout, which decide the plug-ins to run. Empty until the checkout is done. |
| `created_at` | timestamptz | no | when the scan was requested |
| `started_at` | timestamptz | yes | when the worker started it |
| `finished_at` | timestamptz | yes | when its last plug-in run ended |

A scan that the scope check refuses is never created, so every row here is a repository from the scope file.

### analyzer_runs

One row per plug-in run in a scan. This table is not one of the eight in the proposal, but the plug-in contract needs it: it records the tool and rules versions of every scan (requirement F1) and why a run failed. The `PluginRun` class in docs/class-diagrams.md maps to it.

| Column | Type | Can be empty | Meaning |
|---|---|---|---|
| `id` | uuid | no | primary key, the `run_id` of findings |
| `scan_id` | uuid | no | the scan, references `scans` |
| `plugin` | text | no | the plug-in's name from its manifest, such as `semgrep` |
| `image` | text | no | the image name and tag from the manifest |
| `image_digest` | text | yes | the digest of the image that ran. Empty only if the image couldn't be found. |
| `tool_version` | text | no | from the manifest |
| `rules_version` | text | no | from the manifest |
| `status` | text | no | `pending`, `building`, `running`, `succeeded`, `skipped`, `failed` or `timed_out` |
| `reason` | text | yes | for failed runs: `exit_code`, `missing_sarif`, `nothing_scanned`, `invalid_sarif`, `out_of_memory` or `build_failed` |
| `exit_code` | integer | yes | the container's exit code, empty while running and after a timeout |
| `files_scanned` | integer | yes | the number of files the tool scanned, from `scan-info.json`. A run with 0 here fails when the checkout has files in the plug-in's languages. |
| `result_count` | integer | yes | the number of results in the SARIF file |
| `dropped_count` | integer | no | results the adapter didn't turn into findings, for the reasons in docs/finding-format.md. Default 0. |
| `sarif_path` | text | yes | where the SARIF file is in the `sieve-data` volume |
| `log_path` | text | yes | where the run's log is in the `sieve-data` volume |
| `started_at` | timestamptz | yes | |
| `finished_at` | timestamptz | yes | |

Each plug-in runs at most once per scan: `(scan_id, plugin)` is unique.

### findings

One row per finding, in the format of docs/finding-format.md. Each field of that format has a column here with the same name, except for these:

- `finding_id` is `id`.
- The primary location is stored in the columns `file`, `start_line`, `end_line`, `start_column`, `end_column` and `snippet`, because almost every query filters or sorts by it. Related locations and data-flow steps are in `locations`.
- `group_id` and `matched_finding_id` are added by deduplication.

| Column | Type | Can be empty | Meaning |
|---|---|---|---|
| `id` | uuid | no | primary key |
| `scan_id` | uuid | no | the scan, references `scans` |
| `run_id` | uuid | no | the plug-in run that produced it, references `analyzer_runs` |
| `group_id` | uuid | yes | its duplicate group, references `duplicate_groups`. Empty when the finding has no duplicates, so it is a triage item on its own. |
| `matched_finding_id` | uuid | yes | the finding with the same fingerprint in the latest earlier scan of the same repository, references `findings`. Set by deduplication. A finding whose match was already reviewed is not shown in the review queue again (requirement F3), unless either of the two is ambiguous. |
| `tool` | text | no | the plug-in's name |
| `tool_version` | text | no | |
| `rule_id` | text | no | |
| `rule_description` | text | yes | |
| `rule_help_uri` | text | yes | |
| `cwe` | text[] | no | CWE IDs such as `CWE-89`, sorted. Can be an empty array. |
| `message` | text | no | |
| `tool_severity` | text | no | `error`, `warning`, `note` or `none` |
| `tool_score` | numeric(3,1) | yes | from 0.0 to 10.0 |
| `tool_confidence` | text | yes | `high`, `medium` or `low` |
| `file` | text | no | path relative to the repository root |
| `start_line` | integer | no | starts at 1 |
| `end_line` | integer | no | at least `start_line` |
| `start_column` | integer | yes | starts at 1 |
| `end_column` | integer | yes | |
| `snippet` | text | yes | the flagged code |
| `fingerprint` | text | no | computed as in docs/finding-format.md, such as `v1:4aef0ff3eeeaa51051da86d7be561fee` |
| `fingerprint_ambiguous` | boolean | no | true when another finding in the same run has the same rule, file and flagged code. Such a finding is shown again instead of hidden when it matches an earlier one. |
| `tool_fingerprint` | text | yes | the tool's own fingerprint, when it is stable |
| `language` | text | yes | `python`, `java`, `javascript` or `typescript` |
| `raw` | jsonb | no | the SARIF result the finding came from |
| `created_at` | timestamptz | no | |

`(scan_id, fingerprint)` is unique: the occurrence number in the fingerprint keeps two identical results apart.

### locations

The related locations and the data-flow steps of a finding. The primary location is in `findings`.

| Column | Type | Can be empty | Meaning |
|---|---|---|---|
| `id` | bigint | no | primary key |
| `finding_id` | uuid | no | the finding, references `findings`. Deleted with the finding. |
| `kind` | text | no | `related` or `flow_step` |
| `position` | integer | no | the order within its kind, starting at 1. For a data-flow step, this is its `step`. |
| `file` | text | no | path relative to the repository root |
| `start_line` | integer | no | |
| `end_line` | integer | no | |
| `start_column` | integer | yes | |
| `end_column` | integer | yes | |
| `snippet` | text | yes | |
| `message` | text | yes | what the tool says about this step or location |

`(finding_id, kind, position)` is unique.

### duplicate_groups

One row per group of findings in one scan that describe the same issue. Each group records how it was formed (requirement F3, test 2). A finding is in at most one group, and a group has at least two findings.

| Column | Type | Can be empty | Meaning |
|---|---|---|---|
| `id` | uuid | no | primary key, the triage item's `item_id` for a group (docs/interfaces.md) |
| `scan_id` | uuid | no | the scan, references `scans` |
| `representative_finding_id` | uuid | yes | the finding the review screen shows first, references `findings`. Set after the group's findings get their `group_id`. |
| `method` | text | no | `rule`, `similarity` or `llm` |
| `rule` | text | yes | for `rule`: the rule that matched, such as `same_function_related_cwe` |
| `similarity` | numeric(4,3) | yes | for `similarity`: the score that put the findings together, from 0 to 1 |
| `llm_call_id` | uuid | yes | for `llm`: the call that decided, references `llm_calls` |
| `reason` | text | no | one sentence a reviewer can read, such as "Same function and related CWEs (CWE-77 and CWE-78)" |
| `created_at` | timestamptz | no | |

A check constraint makes sure that `rule`, `similarity` or `llm_call_id` is filled to match `method`.

Repeated scans are not handled with groups. A finding from a later scan points to its earlier version through `findings.matched_finding_id`.

### jobs

The queue of background jobs (docs/architecture.md, deployment view). Like `analyzer_runs`, it is not one of the eight tables in the proposal.

| Column | Type | Can be empty | Meaning |
|---|---|---|---|
| `id` | uuid | no | primary key, returned by the API when it starts a job |
| `kind` | text | no | `scan`, `triage` or `report_draft` |
| `status` | text | no | `queued`, `running`, `succeeded` or `failed` |
| `payload` | jsonb | no | only IDs, such as `{"scan_id": "..."}`. Never image names, paths or flags (docs/architecture.md). |
| `error` | text | yes | why the job failed |
| `created_at` | timestamptz | no | |
| `started_at` | timestamptz | yes | |
| `finished_at` | timestamptz | yes | |

## Review side

To be written by Furkan: the columns of `verdicts`, `reviews`, `reports` and `llm_calls`, and the tables that link them, such as the findings each report covers and the LLM calls behind each verdict. The diagram above shows the links to the scan side that these tables need:

- A verdict is for one triage item: either a finding (`finding_id`) or a duplicate group (`group_id`), never both.
- A review is about one finding. Requirement F5 counts a finding as approved when its latest review approves it.
- A report covers one approved finding, or every finding of an approved group.
- A duplicate group decided by the LLM points to its call in `llm_calls`.

## Indexes

Besides the primary keys and the unique constraints above:

| Table | Index | For |
|---|---|---|
| `findings` | `(scan_id)` | listing a scan's findings |
| `findings` | `(scan_id, file, start_line)` | findings in one file, and the deduplication rules that compare nearby lines |
| `findings` | `(group_id)` | the findings of a duplicate group |
| `findings` | `(fingerprint)` | matching findings across scans of the same repository |
| `analyzer_runs` | `(scan_id)` | a scan's plug-in runs |
| `locations` | `(finding_id)` | a finding's locations and data-flow steps |
| `duplicate_groups` | `(scan_id)` | a scan's groups |
| `scans` | `(repo_url, created_at)` | the latest earlier scan of a repository, for fingerprint matching |
| `jobs` | `(created_at)` where `status = 'queued'` | the worker taking the oldest waiting job |
