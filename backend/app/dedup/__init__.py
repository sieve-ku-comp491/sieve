"""Deduplication (T3.2): duplicate groups within a scan, and matching repeated scans."""

from app.dedup.functions import FunctionLookup, FunctionSpan, NoFunctionLookup
from app.dedup.groups import Group, GroupingError, GroupingStep, ScanFinding, group_findings
from app.dedup.rules import NEARBY, NEARBY_LINES, SAME_FUNCTION, RuleStep

__all__ = [
    "NEARBY",
    "NEARBY_LINES",
    "SAME_FUNCTION",
    "FunctionLookup",
    "FunctionSpan",
    "Group",
    "GroupingError",
    "GroupingStep",
    "NoFunctionLookup",
    "RuleStep",
    "ScanFinding",
    "group_findings",
]
