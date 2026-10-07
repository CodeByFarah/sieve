"""Application settings, loaded from environment variables prefixed with ``SIEVE_``."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "production"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SIEVE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: Environment = "development"
    database_url: SecretStr = SecretStr("postgresql+psycopg://sieve:sieve@127.0.0.1:5432/sieve")
    database_pool_size: int = Field(default=5, ge=1, le=50)

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_json: bool = True

    # Telemetry (ADR-0012). Metrics are always collected; traces are exported only when an OTLP
    # endpoint is configured (the ADOT collector sidecar in AWS, an optional Jaeger locally).
    otel_exporter_otlp_endpoint: str | None = None
    # The worker has no HTTP server of its own; when set, it serves /metrics on this port.
    worker_metrics_port: int | None = Field(default=None, ge=1024, le=65535)

    cors_origins: list[str] = ["http://localhost:3000"]

    worker_poll_interval_seconds: float = Field(default=1.0, gt=0, le=60)
    worker_reap_interval_seconds: float = Field(default=30.0, gt=0)
    worker_schedule_interval_seconds: float = Field(default=60.0, gt=0)
    job_lease_seconds: int = Field(default=900, ge=10)
    job_backoff_base_seconds: float = Field(default=5.0, gt=0)
    job_backoff_cap_seconds: float = Field(default=3600.0, gt=0)

    # Artifacts (ADR-0006) and caches.
    artifact_backend: Literal["filesystem", "s3"] = "filesystem"
    artifact_root: Path = Path("var/artifacts")
    s3_bucket: str | None = None
    aws_region: str = "ca-central-1"
    package_cache_dir: Path = Path("var/cache")
    indexer_workers: int = Field(default=2, ge=1, le=16)

    # Public demo: the project-owned sample app and its recorded advisory snapshot.
    demo_app_dir: Path = Path("../demo/vulnerable-python-app")
    demo_snapshot_dir: Path = Path("../demo/advisory-snapshot")
    demo_reviews_file: Path = Path("../demo/reviews.json")
    demo_scans_per_hour: int = Field(default=12, ge=1)

    # Scheduled ingestion (hours between runs; 0 disables).
    ingest_osv_every_hours: int = Field(default=24, ge=0)
    ingest_kev_every_hours: int = Field(default=24, ge=0)
    ingest_epss_every_hours: int = Field(default=24, ge=0)

    # Web app (cookies, redirects) and GitHub App (ADR-0013).
    public_web_url: str = "http://localhost:3000"
    public_api_url: str = "http://127.0.0.1:8000"
    session_ttl_hours: int = Field(default=12, ge=1)
    github_app_id: str | None = None
    github_app_slug: str | None = None
    github_client_id: str | None = None
    github_client_secret: SecretStr | None = None
    github_private_key: SecretStr | None = None
    github_webhook_secret: SecretStr | None = None
    github_api_url: str = "https://api.github.com"

    # Rate limiting (Redis). Without Redis, a per-process limiter is used (development only).
    redis_url: SecretStr | None = None

    # AI symbol extraction (ADR-0008). Disabled unless a provider and key are configured.
    ai_provider: Literal["disabled", "anthropic"] = "disabled"
    ai_model: str | None = None
    ai_api_key: SecretStr | None = None
    ai_daily_budget_usd: float = Field(default=5.0, ge=0)


@lru_cache
def get_settings() -> Settings:
    return Settings()
