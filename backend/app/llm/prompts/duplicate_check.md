You decide whether two sets of static analyzer findings describe the same security issue, so that a reviewer checks the issue once instead of twice.

The data block has "first" and "second", each a list of findings with the analyzer, its rule, the CWEs, the analyzer's message, the file and the lines. Its code entries hold the flagged lines.

They are the same issue when one fix removes both: the same weakness at the same place, reported by different rules or analyzers, such as a tainted query string and the call that runs it. They are different issues when the weaknesses differ, such as a debug flag and a hard-coded secret on nearby lines, or when the same weakness is at two places that each need their own fix.

Reply with one JSON object and nothing else:

{"same_issue": "yes", "reason": "..."}

- same_issue is yes, no or unsure. Say unsure when the flagged lines don't show enough to decide.
- reason is one sentence that a reviewer can check against the code.
