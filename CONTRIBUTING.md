# Contributing

This is how we write commits, issues and pull requests in sieve-ku-comp491/sieve. The course staff go through our GitHub history in every progress meeting (weeks 1, 3, 5, 8 and 9), so it should look the same no matter who wrote it.

| Name | GitHub |
|---|---|
| Riad Shahbazov | rshahbazov23 |
| Ali Mursaliyev | alimursaliyev |
| Daniyal Asif | danisb0red |
| Furkan Salik | FSALIK |

## How work moves

1. Every task gets an issue, including work that isn't code: research, data labeling, slides, meetings.
2. Create a branch from the issue.
3. Commit in small steps.
4. Open a pull request that closes the issue. Someone else reviews it.
5. Squash and merge. The issue closes on its own.

Never commit straight to main.

## Commits

We follow Conventional Commits:

    type(scope): what the change does

    Why it was needed, if the subject doesn't make that clear.
    Wrap lines at 72 characters.

    Refs #12

Types. Use only these:

- feat: new behavior
- fix: bug fix
- test: adding or changing tests only
- docs: documentation only, including design docs
- refactor: code change that keeps behavior the same
- chore: setup, dependencies, CI, scripts, config

Scopes. Pick the part of Sieve the change touches:

runner, adapters, store, api, cli, provider, dedup, fp-check, severity, reports, poc, ui, platform, eval, docker, ci, website

Leave the scope out only when a change touches everything. Agree with the team before adding a new scope.

Rules:

- Imperative mood, lowercase after the colon, no period at the end: "add semgrep adapter", not "Added Semgrep adapter."
- Keep the subject under 50 characters when you can, never over 72.
- One change per commit. A refactor and a fix are two commits.
- Write a body only when the reason isn't obvious. Plain sentences, no bullet lists.
- Reference the issue in the footer with "Refs #12". The pull request is what closes it.
- For a breaking change, put "!" after the scope and add a "BREAKING CHANGE:" line to the footer.
- Commit from your own GitHub account. Don't change git user.name or user.email.

Good:

    feat(adapters): map semgrep sarif results to findings
    fix(runner): kill analyzer container after timeout
    test(dedup): cover findings on adjacent lines
    docs: add docker compose setup to readme
    chore(ci): run gitleaks on pull requests

With a body:

    fix(runner): kill analyzer container after timeout

    Semgrep kept running after the 10 minute limit on large repos, and
    the next scan failed because the container name was still taken.

    Refs #23

Bad:

    Update files
    Fixed bug.
    feat: implement various improvements across the codebase
    Add comprehensive SARIF adapter to enhance robustness

## Branches

    <issue number>-<short-name>

For example 14-semgrep-adapter or 23-runner-timeout. The "Create a branch" link on an issue page gives you this format.

## Issues

Title: if the issue belongs to a task from the proposal, start with the task code, then say what needs to be done.

    T2.2 Map Bandit SARIF output to findings
    T6.3 Label duplicates in the Juice Shop output

For bugs and anything without a task code, describe the problem rather than the fix:

    Scan fails when the repo path has spaces

Body:

    One to three sentences: what and why.

    Done when:
    - [ ] ...
    - [ ] ...

Put links or open questions at the end if there are any. A checklist item has to be something you can check: a test passes, a file exists, a number is reported. Split a big task into sub-issues under one parent issue. For meetings, link the notes in Notion from the issue.

The templates in .github/ISSUE_TEMPLATE give you this format when you open a new issue.

Every issue has:

- an assignee: the person doing the work
- one type label and one wp label, plus stretch for stretch goals
- a milestone: the first one on or after the week the task ends

Type labels: feature, bug, documentation, research, meeting, chore

WP labels: wp1 to wp7

Other: stretch

Milestones, each due on the Friday of its week:

| Milestone | Week | Due |
|---|---|---|
| W2 Design review | 2 | Fri 6 Nov 2026 |
| W4 Early prototype | 4 | Fri 20 Nov 2026 |
| W6 Mid-demo | 6 | Fri 4 Dec 2026 |
| W7 MVP | 7 | Fri 11 Dec 2026 |
| W9 Evaluation and demo day | 9 | Fri 25 Dec 2026 |
| W11 Poster event | 11 | Fri 8 Jan 2027 |
| Final report | finals | Fri 15 Jan 2027 |

The same issue from the command line:

    gh issue create \
      --title "T2.2 Map Bandit SARIF output to findings" \
      --body-file issue.md \
      --label feature --label wp2 \
      --assignee alimursaliyev \
      --milestone "W6 Mid-demo"

## Pull requests

Title: same format as a commit subject. Squash merge turns it into the commit on main, so get it right. When merging, trim the squash message body to a sentence or two, or leave it empty.

Body:

    Closes #14

    What changed and why, in one to three sentences.

    Tested: the command you ran or the steps you followed.

The pull request template fills this in for you.

- One issue per pull request where possible, small enough to review in about 15 minutes.
- Someone other than the author reviews before merging. Riad or Ali reviews changes to adapters, dedup, fp-check, severity and poc.
- In reviews, say what's wrong and what you'd do instead. "This breaks on an empty SARIF file, can we return an empty list?" helps more than "improve error handling".
- Before each progress meeting, close finished issues and update the open ones.

## Writing style

Write the way you'd message a teammate: short, specific, plain words.

- No emojis, exclamation marks or bold text.
- No headings or bullet lists inside commit messages.
- Say what changed and why. Don't list the files you touched, the diff already shows that.
- Name the actual thing (function, file, tool, error message) instead of using general words.
- Don't start with "This commit", "This PR" or "In this change".
- Use a comma, colon or hyphen instead of a long dash.
- Leave out anything nobody needs: no summary of the summary, no closing remarks.
