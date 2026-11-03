# Class diagrams

Four interfaces let us add an analyzer, a model provider or a report format without changing the core (requirement N5). Each diagram shows the interface and at least one implementation.

## Plug-in and SARIF adapter

To be written by Ali.

## LLM provider

Every LLM call goes through `LLMClient`. It renders the prompt template, answers a repeated request from the cache, checks the run's budget, calls the provider and logs the call. A provider only knows how to send one request to one API, so adding a provider means writing one class.

```mermaid
classDiagram
  direction LR
  class LLMProvider {
    <<interface>>
    +name: str
    +complete(request: LLMRequest) LLMResponse
    +price(model: str) Price
  }
  class AnthropicProvider {
    +complete(request: LLMRequest) LLMResponse
    +price(model: str) Price
  }
  class OpenAIProvider {
    +complete(request: LLMRequest) LLMResponse
    +price(model: str) Price
  }
  class LLMClient {
    +ask(template: PromptTemplate, values: dict, code: list~CodeBlock~, model: str) LLMResponse
  }
  class PromptTemplate {
    +name: str
    +version: str
    +text: str
    +render(values: dict, code: list~CodeBlock~) list~Message~
  }
  class CodeBlock {
    +path: str
    +start_line: int
    +end_line: int
    +text: str
  }
  class LLMRequest {
    +model: str
    +messages: list~Message~
    +temperature: float
    +max_tokens: int
  }
  class LLMResponse {
    +text: str
    +model_version: str
    +input_tokens: int
    +output_tokens: int
    +cost_usd: float
    +duration_ms: int
    +cached: bool
  }
  class Price {
    +input_usd_per_million: float
    +output_usd_per_million: float
  }
  class ResponseCache {
    +get(key: str) LLMResponse
    +put(key: str, response: LLMResponse)
  }
  class Budget {
    +limit_usd: float
    +spent_usd: float
    +reserve(estimate_usd: float)
    +charge(cost_usd: float)
  }
  class CallLog {
    +record(run_id: str, request: LLMRequest, response: LLMResponse) str
  }
  class BudgetExceeded {
    <<exception>>
  }

  LLMProvider <|.. AnthropicProvider
  LLMProvider <|.. OpenAIProvider
  LLMClient --> LLMProvider
  LLMClient --> ResponseCache
  LLMClient --> Budget
  LLMClient --> CallLog
  LLMClient ..> PromptTemplate
  PromptTemplate ..> CodeBlock
  LLMClient ..> LLMRequest
  LLMProvider ..> LLMResponse
  LLMProvider ..> Price
  Budget ..> BudgetExceeded : raises
```

How `ask()` works:

1. `PromptTemplate.render()` builds the messages. Code goes only into the template's marked data block, never into the instructions (requirement N4).
2. The cache key is a hash of the model, the rendered messages, the temperature, `max_tokens` and the template version. On a hit, `ask()` returns the cached response with `cached` set, and nothing is charged.
3. Before the call, `Budget.reserve()` checks the worst case: the input tokens at the input price plus `max_tokens` at the output price. If that doesn't fit in what is left, it raises `BudgetExceeded` and no request is sent. So a run never goes over its limit (requirement N1).
4. After the call, `Budget.charge()` records the actual cost, and `CallLog.record()` stores the request, the response, the exact model version, the tokens and the cost in the LLM calls table, and returns the call ID that verdicts link to (requirement N3).

Temperature is 0 wherever the API allows it. API keys are read from environment variables by each provider. `LLMClient` doesn't choose between models: the triage agent asks the cheaper model first and the stronger one only when the first is unsure.

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
