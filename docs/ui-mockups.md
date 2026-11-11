# UI mockups

Mockups of the three screens of the review web app: the review queue, the finding detail and the report preview. T5.1 builds the React app from them, and requirement N7, test 1 checks the finding detail against them.

Figma file: https://www.figma.com/design/dgtGG5MUcoDXTBwoS258YN/Sieve-UI-mockups?node-id=0-1

The PNG exports are in docs/ui/, and the HTML they were made from is in docs/ui/html/. The findings, rules, files, line numbers and code in them come from a real scan: the Semgrep plug-in's command (docs/interfaces.md) with Semgrep 1.183.0 and semgrep-rules at commit `16b9e6d`, on PyGoat at commit `2aa4cc1`, which gave 153 findings. Verdicts, reasoning, CVSS vectors, costs and counts are illustrative, because triage isn't built yet. Every score shown is computed from its vector with FIRST's CVSS v4.0 algorithm.

The statuses on every screen are the states of docs/finding-states.md, and the fields are the columns of docs/database.md.

## Review queue

![Review queue](ui/review-screen.png)

- One row per triage item: a finding, or a duplicate group shown as one row that opens to list its members (use case 4). Each row shows the tool, rule, file, severity, verdict and status.
- Severity is the CVSS v4.0 level and score from triage. A member row also shows the analyzer's own severity, `tool_severity`.
- Filters for status, tool, severity and verdict, and a search on file path or rule. Active filters are shown as chips that remove the filter.
- The counts at the top are the findings in each state. Clicking one filters the list to that state.
- The bar above shows the scan, its plug-in runs and the triage run with its cost and budget (requirement N1).
- A warning sign next to the file means a comment in the code looks like an instruction to an AI.
- In a repeated scan, findings hidden because an earlier review applies to them are not in the queue. A finding shown again shows the earlier decision as a suggestion (docs/finding-states.md).

## Finding detail

Everything a reviewer needs to decide is on one screen (requirement N7):

![Finding detail](ui/finding-detail.png)

- The code of the enclosing function, with the lines the AI cited highlighted in yellow and the lines the analyzers flagged in red.
- The AI's verdict (true positive, false positive or unsure), its reasoning, the cited lines, and the model, number of calls and cost behind it (requirement N3).
- The CVSS v4.0 score, level and vector, with the one-line justification of each of the 11 base metrics. The score is computed, not chosen by the AI.
- For a group: every member with its rule, the analyzer's message, its lines, CWE, tool severity and status, and the reason the group was formed. Each member is reviewed. Approve all approves the members that aren't rejected, and a member can be rejected on its own when it doesn't belong in the group.
- Approve, Reject and Edit. Reject asks for an optional comment.
- The history of the finding's states.

### Edit

![Finding detail while editing](ui/finding-detail-edit.png)

Edit lets the reviewer change the verdict, the reasoning and the CVSS vector before deciding. The score is computed again from the new vector. The AI's values are shown next to the fields, because they stay as they are: the edit is saved next to them (`finding_edits`). After saving, the finding is `edited` until the reviewer approves or rejects it.

### Warning for instructions to an AI

![Finding detail with the warning](ui/finding-detail-injection.png)

When the context collector finds comments or strings that look like instructions to an AI (`injection_suspected`), the detail shows a warning above the code, and marks those lines in orange (`injection_lines`). The example plants such a comment in PyGoat's command injection lab, the way requirement N4, test 3 does. The verdict stays true positive, the same as without the comment.

## Report preview

Export is disabled until the finding is approved, and until a person approves the report's current text (requirement F5).

| Finding not approved | Text not approved | Ready to export |
|---|---|---|
| ![Report preview before approval](ui/report-preview-not-approved.png) | ![Report preview with a draft](ui/report-preview-draft.png) | ![Report preview ready to export](ui/report-preview-ready.png) |

- Before the finding is approved, there is no report. Sieve drafts it after approval, from the finding as the reviewer left it.
- The preview shows every field of the report schema in docs/interfaces.md as the Markdown export lays it out: title, severity with score and vector, location, summary, impact, steps to reproduce, fix and references.
- Edit text, Draft again and Approve text. Each edit or new draft is a new version, and the AI's draft stays as an earlier version. A new version undoes the approval of the text.
- The export check lists what is missing. The report service checks the same things again when it exports.
- A group's report covers the members that are approved. A rejected member is left out.

## Making the Figma file

1. In Figma, create a design file named "Sieve UI mockups" in the team's space, with one page per screen.
2. Import the screens. Either drag the PNGs from docs/ui/ onto the pages, or, for editable layers, install the html.to.design plug-in, open each HTML file in docs/ui/html/ in a browser, and import it with the plug-in. The report preview takes `?state=none` and `?state=ready` for its other two states, and the finding detail takes `?edit`.
3. Share the file so that anyone with the link can view it, and put the link at the top of this document.

## Reviewers

- Riad: how the verdict, the reasoning and the cited code are shown on the finding detail.
- Daniyal: the report preview.
