FROM python:3.14-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

EXPOSE 8000
# The tables are brought up to date before the API starts (app/store/migrate.py).
CMD ["sh", "-c", "python -m app.store migrate && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
