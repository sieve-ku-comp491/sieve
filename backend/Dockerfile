FROM python:3.14-slim

# The worker clones the scanned repositories with Git. Debian 13's Git 2.47.3 is the maintenance
# release that fixes the clone-time attacks of CVE-2024-32002 and CVE-2025-48384, like 2.50.1
# (docs/architecture.md). Changing the base image's Debian release means checking this again.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git=1:2.47.3-0+deb13u1 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

EXPOSE 8000
# The tables are brought up to date before the API starts (app/store/migrate.py). The worker
# service in docker-compose.yml runs the same image with python -m app.worker.
CMD ["sh", "-c", "python -m app.store migrate && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
