import re
from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import Engine
from sqlalchemy.engine import URL

from sieve.api.app import create_app
from sieve.core.config import Settings
from sieve.core.errors import ConflictError
from sieve.core.telemetry import JOBS


def make_settings(database_url: str) -> Settings:
    return Settings(environment="test", database_url=SecretStr(database_url), log_json=False)


def add_failing_routes(app: FastAPI) -> None:
    @app.get("/_test/conflict")
    def conflict() -> None:
        raise ConflictError("finding 42 is at version 7, client sent 6")

    @app.get("/_test/crash")
    def crash() -> None:
        raise RuntimeError("database password is hunter2")


@pytest.fixture
def client(engine: Engine, database_url: URL) -> Iterator[TestClient]:
    app = create_app(make_settings(database_url.render_as_string(hide_password=False)))
    add_failing_routes(app)
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


def test_healthz(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_metrics_exposes_request_and_domain_metrics(client: TestClient) -> None:
    client.get("/api/v1/demo")
    JOBS.add(1, {"kind": "test.kind", "outcome": "succeeded"})
    response = client.get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert re.search(r'sieve_jobs_total\{kind="test\.kind",[^}]*outcome="succeeded"', response.text)
    assert "http_server_" in response.text
    assert "/metrics" not in client.get("/openapi.json").json()["paths"]


def test_readyz_when_database_is_migrated(client: TestClient) -> None:
    response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "checks": {"database": "ok", "migrations": "ok"}}


def test_readyz_reports_unreachable_database() -> None:
    # Port 1 on localhost refuses connections immediately.
    app = create_app(make_settings("postgresql+psycopg://sieve:sieve@127.0.0.1:1/sieve_test"))
    with TestClient(app) as client:
        response = client.get("/readyz")
    assert response.status_code == 503
    assert response.json()["checks"] == {"database": "failing", "migrations": "failing"}


def test_every_response_carries_a_correlation_id(client: TestClient) -> None:
    response = client.get("/healthz", headers={"X-Correlation-Id": "client-req-0001"})
    assert response.headers["X-Correlation-Id"] == "client-req-0001"


def test_unsafe_inbound_correlation_id_is_replaced(client: TestClient) -> None:
    response = client.get("/healthz", headers={"X-Correlation-Id": "<script>alert(1)</script>"})
    assert "<" not in response.headers["X-Correlation-Id"]


def test_domain_error_uses_public_message_only(client: TestClient) -> None:
    response = client.get("/_test/conflict")
    assert response.status_code == 409
    error = response.json()["error"]
    assert error["code"] == "conflict"
    assert "42" not in error["message"]
    assert error["correlation_id"] == response.headers["X-Correlation-Id"]


def test_unhandled_exception_returns_generic_500_without_internals(client: TestClient) -> None:
    response = client.get("/_test/crash")
    assert response.status_code == 500
    body = response.json()
    assert body["error"]["code"] == "internal_error"
    assert "hunter2" not in response.text
    assert body["error"]["correlation_id"] == response.headers["X-Correlation-Id"]


def test_unknown_route_uses_error_shape(client: TestClient) -> None:
    response = client.get("/does-not-exist")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"
