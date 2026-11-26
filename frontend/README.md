# Front end

The review web app (T5.1): React, built with Vite and served by nginx in the `web` service of `docker-compose.yml`, as in docs/architecture.md. nginx forwards every request under `/api/` to the back end, without the `/api` prefix, so the app calls `/api/health` and the back end serves `/health`.

## With Docker Compose

From the repository root:

    docker compose up --build

The app is at http://localhost:8080. The header shows "API up" when the back end answers. To see findings before scans run end to end, load a saved Semgrep run as "Load a saved Semgrep run of PyGoat" in the main README describes.

## Screens

The screens follow the mockups in docs/ui-mockups.md:

- Review queue (`#/`, or `#/scans/<scan ID>` for another scan): the scan with its plug-in runs and triage run, the findings per state, the filters for status, tool, severity and verdict, a search on file or rule, and one row per triage item. Members of a duplicate group on the same page are shown under one row. The filters are kept in the address, so a filtered queue can be bookmarked.
- Finding detail (`#/findings/<finding ID>`): the code around the finding with the analyzer's lines in red, the lines the AI cited in yellow and lines that look like instructions to an AI in orange, the analyzer's message, the AI's verdict and reasoning, the CVSS v4.0 score with the reason for each metric, the group's members and the history. Before triage, the verdict and the severity show a placeholder.
- Approve, Reject and Edit save through the API (docs/finding-states.md, "Saving decisions and edits through the API"). They stay disabled until the finding has a verdict, and after it is reported. Type your name next to "researcher" in the header first: it is saved with each decision and edit, and kept in this browser.

## For development

You need Node.js 22. In this folder:

    npm ci
    npm run dev

The app is at http://localhost:5173 and reloads when you save a file. The development server forwards `/api` to the back end at http://localhost:8000, so start the back end too, with Docker Compose or with uvicorn. Set `API_URL` to use another address.

## Lint

    npm run lint

CI runs the same command on every pull request.
