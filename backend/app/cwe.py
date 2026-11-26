"""CWEs that name the same weakness at different levels, for the evaluation (app.eval.metrics)
and the grouping rules (app.dedup.rules)."""

# CWEs that describe the same weakness at different levels. A finding tagged with one of them
# counts for a test case that expects another. Weak hashing (328) and broken crypto (327) are one
# group: Bandit and Semgrep tag MD5 and SHA-1 as CWE-327, while the Benchmark files those cases
# under 328. Each Benchmark case is its own file, so a hash finding can't count for a cipher case.
RELATED_CWES = [
    frozenset(group)
    for group in (
        {"CWE-22", "CWE-23", "CWE-36", "CWE-73"},
        {"CWE-77", "CWE-78", "CWE-88"},
        {"CWE-79", "CWE-80", "CWE-83", "CWE-87"},
        {"CWE-89", "CWE-564", "CWE-943"},
        {"CWE-94", "CWE-95"},
        {"CWE-326", "CWE-327", "CWE-328", "CWE-916"},
        {"CWE-330", "CWE-338"},
        {"CWE-611", "CWE-776"},
    )
]


def related(a: str, b: str) -> bool:
    return a == b or any(a in group and b in group for group in RELATED_CWES)
