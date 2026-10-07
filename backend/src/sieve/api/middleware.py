"""ASGI middleware.

Written as plain ASGI (not ``BaseHTTPMiddleware``) so it does not buffer streaming responses,
which Server-Sent Events depend on.
"""

import time

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sieve.core.correlation import accept_inbound, correlation_scope
from sieve.core.errors import SieveError
from sieve.core.logging import get_logger

CORRELATION_HEADER = "X-Correlation-Id"

log = get_logger(__name__)


class CorrelationIdMiddleware:
    """Assigns a correlation id, echoes it in the response, logs the request, and turns any
    unhandled exception into the standard error body (so even crashes carry the id)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        correlation_id = accept_inbound(Headers(scope=scope).get(CORRELATION_HEADER))
        status_code = 500
        response_started = False
        started = time.perf_counter()

        async def send_with_header(message: Message) -> None:
            nonlocal status_code, response_started
            if message["type"] == "http.response.start":
                response_started = True
                status_code = message["status"]
                MutableHeaders(scope=message).append(CORRELATION_HEADER, correlation_id)
            await send(message)

        with correlation_scope(correlation_id):
            try:
                await self.app(scope, receive, send_with_header)
            except Exception:
                log.exception("request.unhandled_exception", path=scope["path"])
                if response_started:
                    raise
                response = JSONResponse(
                    status_code=500,
                    content={
                        "error": {
                            "code": SieveError.code,
                            "message": SieveError.default_public_message,
                            "correlation_id": correlation_id,
                        }
                    },
                    headers={CORRELATION_HEADER: correlation_id},
                )
                await response(scope, receive, send)
            finally:
                log.info(
                    "request.completed",
                    method=scope["method"],
                    path=scope["path"],
                    status=status_code,
                    duration_ms=round((time.perf_counter() - started) * 1000, 1),
                )
