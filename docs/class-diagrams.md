# Class diagrams

Four interfaces let us add an analyzer, a model provider or a report format without changing the core (requirement N5). Each diagram shows the interface and at least one implementation.

## Plug-in and SARIF adapter

Two interfaces keep the analyzers out of the core. A plug-in is a Docker image described by its manifest (`PluginManifest`), and `PluginRunner` runs any plug-in the same way, through the plug-in contract in docs/interfaces.md. A `SarifAdapter` turns one tool's SARIF file into findings in the format of docs/finding-format.md. Adding an analyzer means adding a plug-in directory and one adapter class. The Semgrep plug-in and its adapter are the examples.

### Plug-in

```mermaid
classDiagram
  direction LR
  class ScanService {
    +start_scan(repo_url: str, commit: str) Scan
    +run_scan(scan_id: str) Scan
  }
  class ScopeFile {
    +load(path: Path)$ ScopeFile
    +allows(repo_url: str) ScopeEntry
  }
  class CheckoutExporter {
    +export(entry: ScopeEntry, commit: str, dest: Path) str
  }
  class CheckoutReader {
    +read_lines(scan_id: str, file: str) list~str~
  }
  class PluginRegistry {
    +load(plugins_dir: Path)$ PluginRegistry
    +get(name: str) PluginManifest
    +for_languages(languages: set~str~) list~PluginManifest~
  }
  class PluginManifest {
    +name: str
    +image: str
    +languages: list~str~
    +adapter: str
    +timeout_seconds: int
    +tool_version: str
    +rules_version: str
    +build: BuildStep
    +load(path: Path)$ PluginManifest
  }
  class BuildStep {
    +image: str
  }
  class PluginRunner {
    +run(scan: Scan, plugin: PluginManifest, run: PluginRun) PluginRun
    +remove_leftovers(scan_id: str)
    -prepare_dirs(run: PluginRun)
    -read_scan_info(out_dir: Path) int
    -files_in_languages(scan: Scan, plugin: PluginManifest) int
  }
  class RunStore {
    +create_run(scan_id: str, plugin: PluginManifest) PluginRun
    +update(run: PluginRun)
    +save_findings(run: PluginRun, findings: list~Finding~)
  }
  class RunLog {
    +append(run_id: str, text: str)
  }
  class ContainerEngine {
    <<interface>>
    +run(spec: ContainerSpec, timeout_seconds: int) ContainerResult
    +image_digest(image: str) str
    +remove_labeled(label: str, value: str)
  }
  class DockerEngine {
    +run(spec: ContainerSpec, timeout_seconds: int) ContainerResult
    +image_digest(image: str) str
    +remove_labeled(label: str, value: str)
  }
  class ContainerSpec {
    +image: str
    +mounts: list~Mount~
    +network: str
    +env: dict
    +labels: dict
    +user: str
    +read_only: bool
    +tmpfs: list~str~
    +cap_drop: list~str~
    +no_new_privileges: bool
    +memory: str
    +cpus: float
    +pids_limit: int
  }
  class Mount {
    +volume: str
    +subpath: str
    +target: str
    +read_only: bool
  }
  class ContainerResult {
    +exit_code: int
    +timed_out: bool
    +out_of_memory: bool
    +start_failed: bool
    +log: str
  }
  class SarifValidator {
    +validate(path: Path) dict
  }
  class InvalidSarif {
    <<exception>>
    +reason: str
  }
  class PluginRun {
    +run_id: str
    +scan_id: str
    +plugin: str
    +image: str
    +image_digest: str
    +tool_version: str
    +rules_version: str
    +status: RunStatus
    +reason: str
    +exit_code: int
    +started_at: datetime
    +finished_at: datetime
    +files_scanned: int
    +result_count: int
    +dropped_count: int
    +sarif_path: str
    +log_path: str
  }
  class RunStatus {
    <<enumeration>>
    pending
    building
    running
    succeeded
    skipped
    failed
    timed_out
  }

  ScanService --> ScopeFile
  ScanService --> CheckoutExporter
  ScanService --> PluginRegistry
  ScanService --> PluginRunner
  ScanService --> RunStore
  ScanService --> AdapterRegistry
  PluginRegistry o-- PluginManifest
  PluginManifest *-- BuildStep
  PluginRunner --> ContainerEngine
  PluginRunner --> SarifValidator
  PluginRunner --> RunStore
  PluginRunner --> RunLog
  ContainerEngine <|.. DockerEngine
  ContainerEngine ..> ContainerSpec
  ContainerEngine ..> ContainerResult
  ContainerSpec *-- Mount
  RunStore ..> PluginRun : stores
  PluginRun --> RunStatus
  SarifValidator ..> InvalidSarif : raises
  note for PluginManifest "Example: the Semgrep plug-in<br>name = semgrep, adapter = semgrep<br>image = sieve-plugin-semgrep:1.183.0-16b9e6d<br>languages = python, java, javascript, typescript<br>timeout_seconds = 600, no build step"
```

How `ScanService` works:

1. `start_scan()` runs in the API. It checks the repository with `ScopeFile.allows()`, which returns the matching scope entry or refuses the scan before anything else (requirement F2). It then creates the scan and puts a job in the queue, and the worker calls `run_scan()`.
2. `run_scan()` calls `CheckoutExporter.export()`. The exporter clones the URL from the scope entry without credentials, redirects or submodules, refuses a commit that isn't on a branch or tag of that repository, and exports the files into `sieve-data` without the .git folder, symbolic links or the tools' ignore files. It returns the full commit hash, which the scan stores. `run_scan()` then finds the languages in the checkout and asks `PluginRegistry.for_languages()` for the plug-ins to run.
3. For each plug-in, `RunStore.create_run()` stores a `PluginRun` as `pending`, so the run's ID exists before any container starts: the containers' labels and folders use it. `PluginRunner.run()` creates the run's folders and gives them to user 10001, and updates the status through `RunStore.update()` at every change: `building`, `running`, and the end status.
4. The runner builds a `ContainerSpec` with every flag from docs/interfaces.md as a field, for the build container and then the scan container, within one time limit. Because the flags are fields, the runner's tests can check them with a fake engine. `ContainerEngine.run()` waits until the container exits or the limit passes, and removes the container in every case, including when it was created but failed to start. `RunLog` keeps both steps' output in the run's log, up to 5 MB.
5. The runner turns the result into a status and reason. It uses the exit code, `timed_out`, `out_of_memory` and `start_failed` from `ContainerResult`; `SarifValidator.validate()`, whose `InvalidSarif` carries the reason `missing_sarif` or `invalid_sarif`; and `read_scan_info()` with `files_in_languages()` for `nothing_scanned`. It records the image digest and the versions in the `PluginRun`.
6. For each succeeded run, `ScanService` passes the SARIF file to the plug-in's adapter (below), and `RunStore.save_findings()` stores all of the run's findings in one transaction, together with the run's result and dropped counts. The adapter's warnings go to `RunLog`. A failed run doesn't stop the others.

`ContainerEngine` is an interface so that the runner's tests can use a fake engine without Docker, and so that Podman could be added later. `DockerEngine` uses the Docker SDK for Python, version 7.2.0 or later. `remove_leftovers()` removes containers labeled with a scan's ID, for scans that were running when the worker stopped.

`CheckoutReader` is the one way to read a checkout. It resolves every path and refuses any that leaves the checkout. The adapters use it, and so can the triage agent's context collector and tools, so that no read can follow a path out of the checkout.

### SARIF adapter

```mermaid
classDiagram
  direction LR
  class SarifAdapter {
    <<interface>>
    +tool: str
    +to_findings(sarif: dict, run: PluginRun, reader: CheckoutReader) AdapterResult
  }
  class BaseSarifAdapter {
    <<abstract>>
    +to_findings(sarif: dict, run: PluginRun, reader: CheckoutReader) AdapterResult
    #find_rule(run: dict, result: dict) dict
    #normalize_path(uri: str, base_ids: dict) str
    #cwes(rule: dict, result: dict) list~str~
    #tool_severity(rule: dict, result: dict) str
    #tool_score(rule: dict) float
    #confidence(rule: dict, result: dict) str
    #tool_fingerprint(result: dict) str
    #keep(result: dict) bool
    #mask(lines: list~str~, location: Location) list~str~
  }
  class SemgrepAdapter {
    +tool: str
    #confidence(rule: dict, result: dict) str
    #tool_fingerprint(result: dict) str
  }
  class SpotBugsAdapter {
    +tool: str
    #normalize_path(uri: str, base_ids: dict) str
  }
  class EslintAdapter {
    +tool: str
    #cwes(rule: dict, result: dict) list~str~
  }
  class GitleaksAdapter {
    +tool: str
    #cwes(rule: dict, result: dict) list~str~
    #mask(lines: list~str~, location: Location) list~str~
  }
  class AdapterRegistry {
    +get(name: str) SarifAdapter
  }
  class AdapterResult {
    +findings: list~Finding~
    +dropped: dict
    +warnings: list~str~
  }
  class Fingerprinter {
    +assign(findings: list~Finding~, file_lines: dict)
    +fingerprint(tool: str, rule_id: str, file: str, lines: list~str~, occurrence: int)$ str
    +context_hash(file_lines: list~str~, start_line: int, end_line: int)$ str
  }
  class Finding {
    +finding_id: str
    +scan_id: str
    +run_id: str
    +tool: str
    +tool_version: str
    +rule_id: str
    +rule_description: str
    +rule_help_uri: str
    +cwe: list~str~
    +message: str
    +tool_severity: str
    +tool_score: float
    +tool_confidence: str
    +location: Location
    +related_locations: list~Location~
    +data_flow: list~FlowStep~
    +fingerprint: str
    +fingerprint_ambiguous: bool
    +context_hash: str
    +suppressed: bool
    +tool_fingerprint: str
    +language: str
    +raw: dict
  }
  class Location {
    +file: str
    +start_line: int
    +end_line: int
    +start_column: int
    +end_column: int
    +snippet: str
  }
  class FlowStep {
    +step: int
    +message: str
  }

  SarifAdapter <|.. BaseSarifAdapter
  BaseSarifAdapter <|-- SemgrepAdapter
  BaseSarifAdapter <|-- SpotBugsAdapter
  BaseSarifAdapter <|-- EslintAdapter
  BaseSarifAdapter <|-- GitleaksAdapter
  AdapterRegistry o-- SarifAdapter
  BaseSarifAdapter --> Fingerprinter
  SarifAdapter ..> AdapterResult : returns
  AdapterResult *-- Finding
  Finding *-- Location
  Finding *-- FlowStep
  Location <|-- FlowStep
```

`BaseSarifAdapter` does the mapping that is the same for every tool, as described in docs/finding-format.md: it finds each result's rule, keeps only results that `keep()` accepts, normalizes paths, reads CWEs from tags, relationships and taxa, applies the default level, marks suppressed results, maps locations and code flows, and takes `tool_version` from the plug-in run. It reads each flagged file once through `CheckoutReader`, applies `mask()`, and passes the masked lines of all files to `Fingerprinter.assign()`. The fingerprinter computes the fingerprints, the context hashes and the `fingerprint_ambiguous` flags for all findings of the run at once, since the occurrence numbers depend on the other findings. Because it only gets lines that `mask()` has already handled, no secret that an adapter masks can reach a hash.

`to_findings()` returns an `AdapterResult` with the findings, the number of results dropped for each reason, and the warnings for the run's log. It fills `finding_id` only when the findings store saves the finding.

A tool's adapter overrides only what its tool does differently:

- `SemgrepAdapter.confidence()` reads the `HIGH CONFIDENCE`, `MEDIUM CONFIDENCE` and `LOW CONFIDENCE` rule tags, and `tool_fingerprint()` returns nothing, because Semgrep without a login writes `requires login` instead of a fingerprint.
- `SpotBugsAdapter.normalize_path()` also tries the source folders the Java build step listed, because SpotBugs writes paths relative to a source folder when it doesn't know the folder.
- `EslintAdapter.cwes()` maps the rules of eslint-plugin-security to CWEs with the table in docs/finding-format.md, because the plug-in gives none.
- `GitleaksAdapter.cwes()` returns `CWE-798`, and `mask()` replaces every flagged line with `REDACTED`. In other adapters `mask()` returns the lines unchanged.

The Bandit adapter (T2.2) follows the same pattern. Each adapter is tested against a saved SARIF file from a real run of its tool (requirement F1).

## LLM provider

Every LLM call goes through `LLMClient`. It renders the prompt template, answers a repeated request from the cache, checks the run's budget, calls the provider, prices the answer and logs the call. A provider only knows how to send one request to one API, so adding a provider means writing one class and adding its models to `backend/app/llm/models.json`. docs/llm-provider.md has the details.

### Client

```mermaid
classDiagram
  direction LR
  class LLMClient {
    +providers: dict
    +job_id: str
    +build_request(template: PromptTemplate, values: dict, code: list~CodeBlock~, model: str, max_tokens: int, effort: str, history: list~Message~) LLMRequest
    +ask(template: PromptTemplate, values: dict, code: list~CodeBlock~, model: str, max_tokens: int, effort: str, history: list~Message~) LLMResponse
  }
  class PromptTemplate {
    +name: str
    +version: str
    +text: str
    +system_message() Message
    +render(values: dict, code: list~CodeBlock~) tuple~Message~
  }
  class CodeBlock {
    +path: str
    +start_line: int
    +end_line: int
    +text: str
  }
  class Message {
    +role: str
    +content: str
  }
  class Catalog {
    +checked_on: str
    +providers: dict
    +default_model: str
    +get(model: str) ModelInfo
    +worst_case_cost(info: ModelInfo, request: LLMRequest) Decimal
    +cost(provider: str, attempts: list~Attempt~, during: tuple) Decimal
    +ceiling_price(provider: str) Price
  }
  class ModelInfo {
    +name: str
    +provider: str
    +price: Price
    +long_context_price: Price
    +long_context_above: int
    +off_peak: OffPeak
    +temperature: bool
    +server_fallbacks: bool
    +cost(usage: Usage, during: tuple) Decimal
  }
  class Price {
    +input: Decimal
    +output: Decimal
    +cache_read: Decimal
    +cache_write: Decimal
    +cost(usage: Usage) Decimal
  }
  class OffPeak {
    +price_factor: Decimal
    +peak_hours: list
    +peak_days: set
    +is_peak(moment: datetime) bool
  }
  class Budget {
    +limit_usd: Decimal
    +spent_usd: Decimal
    +remaining_usd: Decimal
    +reserve(amount_usd: Decimal) Reservation
  }
  class Reservation {
    +amount_usd: Decimal
    +charge(cost_usd: Decimal)
    +release()
  }
  class BudgetExceeded {
    <<exception>>
  }
  class ResponseCache {
    <<interface>>
    +get(key: str) LLMResponse
    +put(key: str, response: LLMResponse)
  }
  class CallLog {
    <<interface>>
    +record(record: CallRecord)
  }
  class PostgresCallStore {
    +create_table()
    +record(record: CallRecord)
    +get(key: str) LLMResponse
    +put(key: str, response: LLMResponse)
  }
  class CallRecord {
    +id: str
    +job_id: str
    +provider: str
    +model: str
    +model_version: str
    +template_name: str
    +template_version: str
    +messages: list~Message~
    +response_text: str
    +stop_reason: str
    +attempts: list~Attempt~
    +cost_usd: Decimal
    +duration_ms: int
    +cached: bool
    +cache_key: str
    +request_id: str
    +error: str
    +created_at: datetime
  }
  class LLMProvider {
    <<abstract>>
    +complete(request: LLMRequest) LLMResponse
  }

  LLMClient --> Catalog
  LLMClient --> Budget
  LLMClient --> ResponseCache
  LLMClient --> CallLog
  LLMClient --> LLMProvider
  LLMClient ..> PromptTemplate
  PromptTemplate ..> CodeBlock
  PromptTemplate ..> Message
  Catalog o-- ModelInfo
  ModelInfo *-- Price
  ModelInfo *-- OffPeak
  Budget ..> Reservation : returns
  Budget ..> BudgetExceeded : raises
  ResponseCache <|.. PostgresCallStore
  CallLog <|.. PostgresCallStore
  CallLog ..> CallRecord : stores
```

How `ask()` works:

1. `build_request()` takes the model from the `Catalog`, or its `default_model` when the call names none. `PromptTemplate.render()` gives a system message with the template text and the rules for data, and a user message made by `data_block()`: one JSON object with the values and each `CodeBlock`'s path, lines and text, between markers whose id is a hash of the content. Code never goes into the instructions (requirement N4). Earlier turns in `history` have to be the model's answers or blocks made by `data_block()`.
2. The cache key is a hash of the model, the messages, `max_tokens`, the effort, the temperature and the fallback setting. On a hit, `ask()` returns the cached response with `cached` set, and logs it at no cost.
3. Before the call, `Budget.reserve()` sets aside `Catalog.worst_case_cost()`: every byte of the prompt counted as a token at the model's highest input price, and `max_tokens` at its output price, with a second attempt added when Claude's refusal fallbacks are on. If that doesn't fit in what is left, it raises `BudgetExceeded` and nothing is sent (requirement N1).
4. The provider sends the request. `Catalog.cost()` prices each `Attempt` at its own model's price, with the long-context or off-peak price where models.json has one, and `Reservation.charge()` replaces the reservation with that cost. A failed call releases its reservation.
5. `CallLog.record()` stores a `CallRecord` with the prompt, the response, the exact model version, the attempts with their tokens, the cost and the duration in the llm_calls table. Its id comes back as `call_id`, which verdicts link to (requirement N3). If the write fails, the record goes to the error log, and the answer is still returned.

`PostgresCallStore` is both the call log and the cache: `get()` returns the latest complete answer with the same key from llm_calls. The tests use `InMemoryCallLog` and `InMemoryResponseCache` instead.

### Providers

```mermaid
classDiagram
  direction LR
  class LLMProvider {
    <<abstract>>
    +name: str
    +api_key_variable: str
    +refused_variables: list~str~
    +complete(request: LLMRequest)* LLMResponse
  }
  class AnthropicProvider {
    +base_url: str
    +complete(request: LLMRequest) LLMResponse
  }
  class OpenAIProvider {
    +base_url: str
    +complete(request: LLMRequest) LLMResponse
  }
  class ChatCompletionsProvider {
    +label: str
    +base_url: str
    +base_url_variable: str
    +base_url_host: str
    +max_tokens_field: str
    +resolved_base_url()$ str
    +body_fields(request: LLMRequest) dict
    +effort_fields(effort: str) dict
    +sampling_fields(temperature: float) dict
    +complete(request: LLMRequest) LLMResponse
  }
  class DeepSeekProvider
  class QwenProvider {
    +body_fields(request: LLMRequest) dict
    +effort_fields(effort: str) dict
  }
  class GLMProvider {
    +effort_fields(effort: str) dict
    +sampling_fields(temperature: float) dict
  }
  class KimiProvider {
    +effort_fields(effort: str) dict
  }
  class LLMRequest {
    +model: str
    +messages: list~Message~
    +max_tokens: int
    +effort: str
    +temperature: float
    +server_fallbacks: bool
  }
  class LLMResponse {
    +text: str
    +model_version: str
    +stop_reason: StopReason
    +raw_stop_reason: str
    +attempts: list~Attempt~
    +usage: Usage
    +request_id: str
    +cost_usd: Decimal
    +duration_ms: int
    +cached: bool
    +call_id: str
  }
  class Attempt {
    +model: str
    +usage: Usage
  }
  class Usage {
    +input_tokens: int
    +output_tokens: int
    +cache_read_tokens: int
    +cache_write_tokens: int
  }
  class StopReason {
    <<enumeration>>
    complete
    max_tokens
    refusal
    other
  }
  class ProviderError {
    <<exception>>
    +retryable: bool
  }
  class MissingAPIKey {
    <<exception>>
    +variable: str
  }

  LLMProvider <|-- AnthropicProvider
  LLMProvider <|-- OpenAIProvider
  LLMProvider <|-- ChatCompletionsProvider
  ChatCompletionsProvider <|-- DeepSeekProvider
  ChatCompletionsProvider <|-- QwenProvider
  ChatCompletionsProvider <|-- GLMProvider
  ChatCompletionsProvider <|-- KimiProvider
  LLMProvider ..> LLMRequest
  LLMProvider ..> LLMResponse : returns
  LLMProvider ..> ProviderError : raises
  ProviderError <|-- MissingAPIKey
  LLMResponse *-- Attempt
  LLMResponse --> StopReason
  Attempt *-- Usage
```

`providers_from_env()` imports each class listed under `providers` in models.json and sets it up when its key variable is set. A provider reads its key only from the environment, passes its API's base URL to the SDK, and refuses to start while one of its `refused_variables` is set, because the SDK would add that to every request. It turns the SDK's errors into `ProviderError`, whose `retryable` says whether trying again later can help.

DeepSeek, Qwen, GLM and Kimi serve OpenAI's Chat Completions format, so they extend `ChatCompletionsProvider` and override only how their API takes the output limit, the effort and the temperature. `QwenProvider.body_fields()` splits `max_tokens` between thinking and answer, because Qwen's own `max_tokens` leaves out the thinking. `GLMProvider.sampling_fields()` sends `do_sample: false` instead of a temperature of 0, and `KimiProvider` sends `max_completion_tokens`. Each `Attempt` in a response is one model run with its own tokens: a Claude refusal fallback adds a second one, charged at its own model's price.

Temperature 0 goes only to models that accept it, as marked in models.json. `LLMClient` doesn't choose between models: a call that names none goes to `default_model`, deepseek-flash, and the triage agent asks the cheaper model first and the stronger one only when the first is unsure.

## Report format

A report format turns a `Report` into the text of one exported file. Markdown is the core format, and the platform formats are stretch goals (T4.2). The fields of `Report` follow the report schema in docs/interfaces.md.

```mermaid
classDiagram
  class ReportFormat {
    <<interface>>
    +name: str
    +file_extension: str
    +render(report: Report) str
  }
  class MarkdownFormat {
    +render(report: Report) str
  }
  class HackerOneFormat {
    <<stretch>>
    +render(report: Report) str
  }
  class BugcrowdFormat {
    <<stretch>>
    +render(report: Report) str
  }
  class Report {
    +report_id: str
    +finding_ids: list~str~
    +title: str
    +summary: str
    +impact: str
    +steps_to_reproduce: list~str~
    +fix: str
    +references: list~str~
    +severity: CvssScore
    +locations: list~Location~
    +status: str
  }
  class CvssScore {
    +vector: str
    +score: float
    +level: str
  }
  class ReportService {
    +draft(finding_ids: list~str~) Report
    +export(report_id: str, format: str) str
  }
  class NotApproved {
    <<exception>>
  }

  ReportFormat <|.. MarkdownFormat
  ReportFormat <|.. HackerOneFormat
  ReportFormat <|.. BugcrowdFormat
  ReportFormat ..> Report
  Report --> CvssScore
  ReportService --> ReportFormat
  ReportService ..> Report
  ReportService ..> NotApproved : raises
```

`ReportService.export()` checks that every finding in the report is approved and raises `NotApproved` otherwise, so nothing leaves Sieve without a person's approval (requirement F5). `draft()` writes the text through `LLMClient`, and the reviewer can edit any field before export. HackerOne's format maps the severity to its CVSS-based rating, and Bugcrowd's maps it to a VRT priority.
