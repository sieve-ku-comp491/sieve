# Front end

The review web app (T5.1): React, built with Vite and served by nginx in the `web` service of `docker-compose.yml`, as in docs/architecture.md. nginx forwards every request under `/api/` to the back end, without the `/api` prefix, so the app calls `/api/health` and the back end serves `/health`.

## With Docker Compose

From the repository root:

    docker compose up --build

The app is at http://localhost:8080. The header shows "API up" when the back end answers.

## For development

You need Node.js 22. In this folder:

    npm ci
    npm run dev

The app is at http://localhost:5173 and reloads when you save a file. The development server forwards `/api` to the back end at http://localhost:8000, so start the back end too, with Docker Compose or with uvicorn. Set `API_URL` to use another address.

## Lint

    npm run lint

CI runs the same command on every pull request.
