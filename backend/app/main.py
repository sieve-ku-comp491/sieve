from fastapi import FastAPI

app = FastAPI(title="Sieve")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
