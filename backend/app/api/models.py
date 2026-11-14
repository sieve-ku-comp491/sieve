"""The response bodies of the scan and finding endpoints. Field names are the column names of
docs/database.md and the field names of docs/finding-format.md."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

State = Literal["new", "grouped", "triaged", "edited", "approved", "rejected", "reported"]
Verdict = Literal["true_positive", "false_positive", "unsure"]
Level = Literal["none", "low", "medium", "high", "critical"]
ToolSeverity = Literal["error", "warning", "note", "none"]


class Health(BaseModel):
    status: str


class AnalyzerRun(BaseModel):
    id: UUID
    plugin: str
    image: str
    image_digest: str | None
    tool_version: str
    rules_version: str
    status: str
    reason: str | None
    exit_code: int | None
    files_scanned: int | None
    result_count: int | None
    dropped_count: int
    started_at: datetime | None
    finished_at: datetime | None


class TriageRun(BaseModel):
    id: UUID
    cheap_model: str
    strong_model: str
    budget_usd: float
    cost_usd: float
    status: str
    grouped_at: datetime | None
    created_at: datetime
    finished_at: datetime | None


class Scan(BaseModel):
    id: UUID
    repo_url: str
    commit_sha: str | None
    requested_ref: str | None
    status: str
    error: str | None
    languages: list[str]
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    finding_count: int


class ScanDetail(Scan):
    runs: list[AnalyzerRun]
    triage_run: TriageRun | None = Field(description="the scan's latest triage run")
    state_counts: dict[State, int] = Field(
        description="the number of findings in each state, without the hidden ones"
    )
    hidden_count: int = Field(
        description="findings hidden because an earlier review applies to them"
    )


class FindingItem(BaseModel):
    """One row of the review queue."""

    id: UUID
    scan_id: UUID
    run_id: UUID
    group_id: UUID | None
    tool: str
    tool_version: str
    rule_id: str
    cwe: list[str]
    message: str
    tool_severity: ToolSeverity
    tool_confidence: str | None
    file: str
    start_line: int
    end_line: int
    language: str | None
    suppressed: bool
    hidden: bool
    carried_review_id: UUID | None
    state: State
    verdict: Verdict | None = Field(
        description="the latest verdict of its triage item, or the reviewer's edit of it. "
        "Empty before triage."
    )
    severity: Level | None = Field(description="the CVSS v4.0 level, from the same place")
    score: float | None = Field(description="the CVSS v4.0 score, from the same place")
    injection_suspected: bool


class FindingPage(BaseModel):
    total: int = Field(description="the number of findings that match the filters")
    limit: int
    offset: int
    items: list[FindingItem]


class Location(BaseModel):
    file: str
    start_line: int
    end_line: int
    start_column: int | None
    end_column: int | None
    snippet: str | None
    message: str | None = None


class FlowStep(Location):
    step: int


class Code(BaseModel):
    """Lines of the scanned file around the finding, read from the scan's checkout."""

    file: str
    start_line: int = Field(description="the line number of the first line in lines")
    end_line: int
    lines: list[str]


class VerdictOut(BaseModel):
    id: UUID
    triage_run_id: UUID
    finding_id: UUID | None
    group_id: UUID | None
    verdict: Verdict
    reasoning: str
    cited_lines: list[dict[str, Any]]
    injection_suspected: bool
    injection_lines: list[dict[str, Any]]
    model_version: str
    cvss_v4_vector: str
    cvss_v4_score: float
    cvss_v4_level: Level
    cvss_v4_justifications: dict[str, str]
    cvss_v31_vector: str | None
    cvss_v31_score: float | None
    cvss_v31_level: Level | None
    cvss_v31_justifications: dict[str, str] | None
    created_at: datetime
    call_count: int = Field(description="the LLM calls behind the verdict")
    cost_usd: float = Field(description="what those calls cost")


class FindingEdit(BaseModel):
    id: UUID
    verdict_id: UUID
    editor: str
    verdict: Verdict | None
    reasoning: str | None
    cvss_v4_vector: str | None
    cvss_v4_score: float | None
    cvss_v4_level: Level | None
    note: str | None
    created_at: datetime


class Review(BaseModel):
    id: UUID
    decision: Literal["approve", "reject"]
    reviewer: str
    comment: str | None
    verdict_id: UUID | None
    finding_edit_id: UUID | None
    created_at: datetime


class GroupMember(BaseModel):
    id: UUID
    tool: str
    rule_id: str
    message: str
    file: str
    start_line: int
    end_line: int
    cwe: list[str]
    tool_severity: ToolSeverity
    state: State


class Group(BaseModel):
    id: UUID
    method: Literal["rule", "similarity", "llm"]
    rule: str | None
    similarity: float | None
    reason: str
    representative_finding_id: UUID | None
    created_at: datetime
    members: list[GroupMember]


class FindingDetail(BaseModel):
    """One finding in the format of docs/finding-format.md, with what the finding detail
    screen shows next to it."""

    id: UUID
    scan_id: UUID
    run_id: UUID
    group_id: UUID | None
    matched_finding_id: UUID | None
    carried_review_id: UUID | None
    hidden: bool
    tool: str
    tool_version: str
    rule_id: str
    rule_description: str | None
    rule_help_uri: str | None
    cwe: list[str]
    message: str
    tool_severity: ToolSeverity
    tool_score: float | None
    tool_confidence: str | None
    location: Location
    related_locations: list[Location]
    data_flow: list[FlowStep]
    fingerprint: str
    fingerprint_ambiguous: bool
    context_hash: str
    suppressed: bool
    tool_fingerprint: str | None
    language: str | None
    raw: dict[str, Any]
    created_at: datetime
    state: State
    code: Code | None = Field(
        description="the flagged lines with up to 10 lines before and after. Empty when the "
        "checkout can't be read."
    )
    verdict: VerdictOut | None = Field(description="the latest verdict of its triage item")
    latest_edit: FindingEdit | None
    reviews: list[Review] = Field(description="newest first")
    carried_review: Review | None = Field(
        description="the earlier review that applies to it from an earlier scan. It decides "
        "the finding when hidden is true, and is a suggestion otherwise."
    )
    group: Group | None
