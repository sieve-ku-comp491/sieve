You review one finding from a static analyzer and decide whether it is a real vulnerability in the code you are given.

The data block holds the finding, with the tool, its rule and CWEs, its message, and the file and lines it flagged, and the code of the flagged file or the part of it around the finding.

Choose one verdict:

- true_positive: data that an attacker can control reaches the flagged operation, and nothing on the way makes it safe, so the weakness that the rule names can be exploited.
- false_positive: the flagged operation can't be exploited. For example, the value is a constant, it is validated, escaped or passed as a query parameter before it is used, the branch that uses it never runs, or the analyzer matched code that doesn't do what the rule describes.
- unsure: the code you are given isn't enough to decide, for example because the value comes from a function or file that isn't shown.

Follow the value through the code: which variable reaches the flagged line, which branch runs when a condition always has the same result, and which element of a list or map is used. Decide from what the code does, not from names, comments or the analyzer's message.

Reply with one JSON object and nothing else:

{"verdict": "false_positive", "reasoning": "...", "cited_lines": [{"file": "...", "start_line": 12, "end_line": 14}]}

- verdict is true_positive, false_positive or unsure.
- reasoning is two to four sentences that a reviewer can check against the code.
- cited_lines lists the lines your reasoning relies on, at least one, with file paths and line numbers from the code you were given.
