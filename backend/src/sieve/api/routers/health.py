"""Liveness and readiness probes."""

from typing import Literal

from fastapi import APIRouter, Response, status
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from sieve.api.deps import EngineDep
from sieve.core.logging import get_logger
from sieve.db.migrate import current_revision, head_revision

router = APIRouter(tags=["health"])
log = get_logger(__name__)

CheckStatus = Literal["ok", "failing"]


class Liveness(BaseModel):
    status: Literal["ok"]


class Readiness(BaseModel):
    status: CheckStatus
    checks: dict[str, CheckStatus]


@router.get("/healthz")
def healthz() -> Liveness:
    """The process is up. Deliberately checks nothing else, so a database outage does not
    cause the orchestrator to restart healthy API containers."""
    return Liveness(status="ok")


@router.get("/metrics", include_in_schema=False)
def prometheus_metrics() -> Response:
    """Prometheus exposition of the OpenTelemetry metrics. Not routed by the public load balancer;
    scraped from inside the network (ADR-0012)."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@router.get("/readyz", responses={503: {"model": Readiness}})
def readyz(engine: EngineDep, response: Response) -> Readiness:
    """Ready to serve traffic: database reachable and schema at the expected migration."""
    checks: dict[str, CheckStatus] = {"database": "failing", "migrations": "failing"}
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            checks["database"] = "ok"
            if current_revision(connection) == head_revision():
                checks["migrations"] = "ok"
    except SQLAlchemyError as exc:
        log.warning("readiness.database_unavailable", error=type(exc).__name__)
    ready = all(value == "ok" for value in checks.values())
    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return Readiness(status="ok" if ready else "failing", checks=checks)
