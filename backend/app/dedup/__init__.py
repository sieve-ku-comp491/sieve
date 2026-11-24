"""Deduplication (T3.2): duplicate groups within a scan, and matching repeated scans."""

from app.dedup.functions import FunctionLookup, FunctionSpan, NoFunctionLookup
from app.dedup.groups import Group, GroupingError, GroupingStep, ScanFinding, group_findings
from app.dedup.llm import LLMStep
from app.dedup.matching import Matched, match_earlier_findings
from app.dedup.rules import NEARBY, NEARBY_LINES, SAME_FUNCTION, RuleStep, close
from app.dedup.similarity import ASK_FROM, GROUP_AT, SimilarityStep, TextScorer
from app.dedup.store import group_scan, save_groups, scan_findings, write_groups_csv

__all__ = [
    "ASK_FROM",
    "GROUP_AT",
    "NEARBY",
    "NEARBY_LINES",
    "SAME_FUNCTION",
    "FunctionLookup",
    "FunctionSpan",
    "Group",
    "GroupingError",
    "GroupingStep",
    "LLMStep",
    "Matched",
    "NoFunctionLookup",
    "RuleStep",
    "ScanFinding",
    "SimilarityStep",
    "TextScorer",
    "close",
    "group_findings",
    "group_scan",
    "match_earlier_findings",
    "save_groups",
    "scan_findings",
    "write_groups_csv",
]
