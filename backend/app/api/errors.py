"""The 422 answer for a request that fails validation.

FastAPI's own answer repeats the input it refused. When that input holds a lone surrogate,
which JSON can carry as an escape but UTF-8 can't encode, writing the answer fails and the
client gets a 500 instead of the 422. Here every string in the answer is made encodable first.
"""

from fastapi import Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


def encodable(value):
    """value with each lone surrogate in its strings written as a backslash escape."""
    if isinstance(value, str):
        return value.encode("utf-8", "backslashreplace").decode("utf-8")
    if isinstance(value, dict):
        return {encodable(key): encodable(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [encodable(item) for item in value]
    return value


async def validation_failed(request: Request, error: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422, content={"detail": encodable(jsonable_encoder(error.errors()))}
    )
