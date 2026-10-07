"""Application factory. Run with ``uvicorn sieve.api.app:create_app --factory``."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from importlib.metadata import version

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sieve.api.errors import register_error_handlers
from sieve.api.middleware import CORRELATION_HEADER, CorrelationIdMiddleware
from sieve.api.ratelimit import build_rate_limiter
from sieve.api.routers import (
    auth,
    demo,
    findings,
    health,
    organizations,
    repositories,
    scans,
    system,
    webhooks,
)
from sieve.core.config import Settings, get_settings
from sieve.core.http import build_client
from sieve.core.logging import configure_logging
from sieve.core.telemetry import configure_telemetry, instrument_app, instrument_engine
from sieve.db.session import create_db_engine, create_session_factory
from sieve.runtime import build_artifact_store


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(level=settings.log_level, json=settings.log_json)
    configure_telemetry(settings, service="sieve-api")
    engine = create_db_engine(settings)
    instrument_engine(engine)
    http = build_client(timeout=30)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield
        http.close()
        engine.dispose()

    expose_docs = settings.environment != "production"
    app = FastAPI(
        title="Sieve API",
        version=version("sieve"),
        summary="Evidence-backed dependency vulnerability triage.",
        lifespan=lifespan,
        docs_url="/docs" if expose_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if expose_docs else None,
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = create_session_factory(engine)
    app.state.http = http
    app.state.artifacts = build_artifact_store(settings)
    app.state.rate_limiter = build_rate_limiter(settings)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "X-Sieve-CSRF", CORRELATION_HEADER],
        expose_headers=[CORRELATION_HEADER],
    )
    # Added last, so it is the outermost middleware and wraps everything, including CORS.
    app.add_middleware(CorrelationIdMiddleware)
    register_error_handlers(app)
    instrument_app(app)

    for module in (
        health,
        auth,
        organizations,
        repositories,
        scans,
        findings,
        demo,
        system,
        webhooks,
    ):
        app.include_router(module.router)
    return app
