# Design documents

These documents turn the design in the proposal (Section 2.1, Tables 1 to 3) into the requirements and the design that the implementation tasks build on (T1.1, issue #1). Each came in its own pull request, and our advisor went through them in the design review (M1.1, issue #12).

| Document | What it covers | Issue |
|---|---|---|
| [requirements.md](requirements.md) | the functional and non-functional requirements, each with acceptance tests, and the pinned analyzers, datasets and target applications | #2 |
| [use-cases.md](use-cases.md) | the use cases of the researcher, with the PlantUML diagram | #4 |
| [architecture.md](architecture.md) | the component view and the deployment view: services, networks and background jobs | #5 |
| [data-flow.md](data-flow.md) | how a finding moves from SARIF to an exported report, and what leaves the researcher's machine | #6 |
| [finding-format.md](finding-format.md) | the finding format every adapter produces, the fingerprint and when a finding is hidden | #3 |
| [interfaces.md](interfaces.md) | the plug-in contract, the triage API and the report schema | #3 |
| [class-diagrams.md](class-diagrams.md) | the plug-in and SARIF adapter, the LLM provider and the report format | #8 |
| [llm-provider.md](llm-provider.md) | how every LLM call goes through LLMClient: prompt templates, the response cache, the budget, the providers and the call log, and how to add a provider | #21 |
| [sequences.md](sequences.md) | scan and import, triage of one finding, and approval and export | #9 |
| [database.md](database.md) | the PostgreSQL tables of the findings store, with the ER diagram | #7 |
| [finding-states.md](finding-states.md) | the states of a finding, the export check of F5, and repeated scans | #10 |
| [ui-mockups.md](ui-mockups.md) | the review queue, the finding detail and the report preview | #11 |
| [ci.md](ci.md) | the CI workflow that runs on every pull request | #16 |

The REST API specification is not written by hand: FastAPI generates it from the code in T2.3, and it is served at http://localhost:8000/docs.

How we write commits, issues and pull requests is in [CONTRIBUTING.md](../CONTRIBUTING.md), and how to set up and start the environment is in [README.md](../README.md).
