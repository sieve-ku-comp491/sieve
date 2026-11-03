# Sequence diagrams

Three diagrams show the main interactions step by step: scanning a repository and importing its findings, triaging one finding, and approving and exporting a report. Each one shows its main error path.

## Scan and import

To be written by Daniyal.

## Triage of one finding

Grouping runs once per scan before this, so the item can be a single finding or a duplicate group. The triage agent checks the item with the cheaper model first, and asks the stronger model only when the cheaper one is unsure. It then has the LLM choose the CVSS v4.0 metrics and computes the score itself.

```mermaid
sequenceDiagram
  autonumber
  participant TA as Triage agent
  participant DB as Findings store
  participant CC as Context collector
  participant FS as Scanned checkout
  participant LC as LLMClient
  participant API as Hosted LLM API
  participant CV as CVSS calculator

  TA->>DB: load the triage item and its findings
  TA->>CC: get the code context
  CC->>FS: read the file
  CC-->>TA: enclosing function, data-flow path, injection flag
  TA->>LC: ask false-positive template, code as marked data, cheaper model
  LC->>LC: look up the cache
  alt cached
    LC-->>TA: cached response
  else not cached
    LC->>LC: reserve the worst-case cost in the run's budget
    break budget would be exceeded
      LC-->>TA: BudgetExceeded
      TA->>DB: mark the run stopped_at_budget and leave the item untriaged
    end
    LC->>API: request
    API-->>LC: response
    LC->>LC: charge the actual cost and log the call
    LC-->>TA: response
  end
  loop while the model asks for a tool, at most 5 times
    TA->>FS: read_file or find_definition
    FS-->>TA: code
    TA->>LC: ask again with the tool result as marked data
    LC-->>TA: response
  end
  opt verdict is unsure
    TA->>LC: ask false-positive template, stronger model
    LC-->>TA: verdict, reasoning, cited lines
  end
  TA->>LC: ask severity template
  LC-->>TA: CVSS v4.0 metrics, each with a justification
  TA->>CV: compute the score from the vector
  CV-->>TA: score and level
  TA->>DB: save the verdict, the severity and the IDs of the logged calls
```

Notes on the steps:

- Every `ask` goes through the same cache and budget steps shown for the first one. If the budget runs out at any call, the run stops there. Items that were already saved keep their results, and the next run picks up the rest.
- The context collector extracts the enclosing function with tree-sitter, which has grammars for Python, Java and JavaScript/TypeScript, so the same steps work for all three languages. It also flags comments and strings that look like instructions to an AI. The flag is saved with the verdict, and the review screen shows it.
- The agent's tools read only from the scanned checkout.
- The model chooses the metrics, and the calculator computes the score with FIRST's CVSS v4.0 algorithm. In evaluation runs on CVEs that only have a v3.1 vector, the agent also asks for v3.1 metrics.
- The saved call IDs link every verdict and every metric choice to its prompt and response in the LLM calls table (requirement N3).

## Approval and export

To be written by Daniyal.
