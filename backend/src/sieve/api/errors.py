"""Maps exceptions to the single API error shape:

``{"error": {"code": str, "message": str, "correlation_id": str, ...}}``

Internal error messages never reach the response body; they go to logs with the correlation id.
"""

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from sieve.core.correlation import get_correlation_id
from sieve.core.errors import ErrorCategory, SieveError
from sieve.core.logging import get_logger

log = get_logger(__name__)


def error_body(code: str, message: str, **extra: Any) -> dict[str, Any]:
    return {
        "error": {"code": code, "message": message, "correlation_id": get_correlation_id(), **extra}
    }


async def _sieve_error(_request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, SieveError)  # noqa: S101 - registered for SieveError only
    level = "warning" if exc.category in (ErrorCategory.USER, ErrorCategory.SECURITY) else "error"
    getattr(log, level)(
        "request.failed",
        code=exc.code,
        category=str(exc.category),
        internal_message=exc.message,
        detail=dict(exc.detail),
    )
    return JSONResponse(
        status_code=exc.http_status, content=error_body(exc.code, exc.public_message)
    )


async def _validation_error(_request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)  # noqa: S101
    # Echo field locations and messages, never the submitted values.
    fields = [{"loc": list(err["loc"]), "msg": err["msg"]} for err in exc.errors()]
    return JSONResponse(
        status_code=422,
        content=error_body("validation_error", "The request is invalid.", fields=fields),
    )


async def _http_error(_request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, HTTPException)  # noqa: S101
    code = "not_found" if exc.status_code == 404 else "http_error"
    return JSONResponse(
        status_code=exc.status_code,
        content=error_body(code, str(exc.detail)),
        headers=exc.headers,
    )


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(SieveError, _sieve_error)
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.add_exception_handler(HTTPException, _http_error)
