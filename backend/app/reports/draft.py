"""What the model is asked for a report, and what its answer must look like.

The prompt template is app/llm/prompts/report_draft.md. Everything about the finding goes to the
model as data (docs/llm-provider.md, "Prompt templates and data blocks"), and the severity and the
locations of a report always come from the finding, never from the model's answer.
"""

import json
import re

from app.reports.models import (
    URL,
    FindingContext,
    Location,
    ReportDraftError,
    ReportText,
    cwe_references,
    problems,
)

TEMPLATE = "report_draft"
FENCE = re.compile(r"^\s*```(?:json)?\s*\n(.*?)\n\s*```\s*$", re.DOTALL | re.IGNORECASE)
STEP_NUMBER = re.compile(r"^\s*(?:step\s*)?\d+\s*[.):]\s+", re.IGNORECASE)


def prompt_values(
    context: FindingContext,
    attempt: int = 1,
    previous: ReportText | None = None,
    retry: int = 0,
) -> dict:
    """The values of the data block. A new draft carries the earlier text and its number, so
    asking again is a different request and the cache doesn't answer it with the same text. A
    retry after an answer that wasn't a report carries its own number for the same reason."""
    values: dict = {
        "rules": [
            {"tool": rule.tool, "rule": rule.rule_id, "message": rule.message}
            for rule in context.rules
        ],
        "cwes": list(context.cwes),
        "locations": [_where(location) for location in context.locations],
        "verdict_reasoning": context.reasoning,
        "cited_lines": [_where(location) for location in context.cited_lines],
        "severity": {
            "vector": context.severity.vector,
            "score": context.severity.score,
            "level": context.severity.level,
            "justifications": dict(context.justifications),
        },
        "injection_suspected": context.injection_suspected,
        "attempt": attempt,
    }
    if retry:
        values["retry"] = retry
    if previous is not None:
        values["previous_draft"] = {
            "title": previous.title,
            "summary": previous.summary,
            "impact": previous.impact,
            "steps_to_reproduce": list(previous.steps_to_reproduce),
            "fix": previous.fix,
            "references": list(previous.references),
        }
    return values


def parse_draft(answer: str, context: FindingContext, llm_call_id: str) -> ReportText:
    """The model's JSON answer as an unsaved text (version 0). Raises ReportDraftError when it
    isn't a complete report, so that no half-finished draft is saved."""
    try:
        data = json.loads(_unfenced(answer))
    except ValueError:
        raise ReportDraftError("the answer is not a JSON object") from None
    if not isinstance(data, dict):
        raise ReportDraftError("the answer is not a JSON object")
    missing = [key for key in _KEYS if key not in data]
    if missing:
        raise ReportDraftError(f"the answer has no {', '.join(missing)}")
    wrong = [
        key
        for key in _KEYS
        if not (_is_text_list(data[key]) if key in _LISTS else isinstance(data[key], str))
    ]
    if wrong:
        raise ReportDraftError(f"the answer has the wrong type for {', '.join(wrong)}")

    steps = tuple(STEP_NUMBER.sub("", step).strip() for step in data["steps_to_reproduce"])
    text = ReportText(
        version=0,
        source="llm_draft",
        title=data["title"].strip(),
        summary=data["summary"].strip(),
        impact=data["impact"].strip(),
        steps_to_reproduce=steps,
        fix=data["fix"].strip(),
        references=_references(context, data["references"]),
        severity=context.severity,
        locations=context.locations,
        llm_call_id=llm_call_id,
    )
    found = problems(text, context.cwes)
    if found:
        raise ReportDraftError("the answer is not a complete report: " + "; ".join(found))
    return text


_KEYS = ("title", "summary", "impact", "steps_to_reproduce", "fix", "references")
_LISTS = {"steps_to_reproduce", "references"}


def _is_text_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _unfenced(answer: str) -> str:
    """Some models wrap JSON in a Markdown fence although the prompt says not to."""
    match = FENCE.match(answer)
    return (match.group(1) if match else answer).strip()


def _references(context: FindingContext, given: list[str]) -> tuple[str, ...]:
    """The CWE entries first, then the model's URLs, without repeats. A reference that is not a
    URL is left out."""
    references: list[str] = []
    for url in [*cwe_references(context.cwes), *(ref.strip() for ref in given)]:
        if URL.match(url) and url not in references:
            references.append(url)
    return tuple(references)


def _where(location: Location) -> dict:
    return {"file": location.file, "lines": location.as_text()}
