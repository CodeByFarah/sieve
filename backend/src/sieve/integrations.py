"""Optional integrations (GitHub App, AI symbol extraction), enabled only when configured.

Sieve runs fully without either: demo scans need neither, and findings without known symbols are
reported as ``needs_review`` rather than guessed.
"""

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from decimal import Decimal

import httpx
from sqlalchemy.orm import Session, sessionmaker

from sieve.advisories.fanout import rescan_affected
from sieve.ai.extraction import ExtractionService
from sieve.ai.guardrails import PROMPT_VERSION
from sieve.ai.providers import AnthropicProvider
from sieve.analysis.sandbox import InProcessIndexer
from sieve.core.config import Settings
from sieve.db.enums import AIExtractionStatus
from sieve.db.models import Finding, Repository
from sieve.db.session import transaction
from sieve.github import checks
from sieve.github.app import GitHubApp, GitHubWorkspaces
from sieve.github.sync import sync_installation
from sieve.packages.pypi import PypiSourceCache
from sieve.scans.workspaces import WorkspaceProvider
from sieve.worker import queue
from sieve.worker.runner import Handler, JobContext


@dataclass
class Integrations:
    handlers: dict[str, Handler] = field(default_factory=dict)
    github_workspaces: Callable[[Repository], WorkspaceProvider] | None = None
    on_symbols_missing: Callable[[Session, Finding], None] | None = None


def _github(
    settings: Settings, factory: sessionmaker[Session], http: httpx.Client, into: Integrations
) -> None:
    app = GitHubApp.from_settings(settings, http)
    if app is None:
        return
    workspaces = GitHubWorkspaces(app, factory)
    into.github_workspaces = lambda _repository: workspaces

    def sync(context: JobContext) -> None:
        with transaction(factory) as session:
            sync_installation(session, app, int(context.job.payload["installation_id"]))

    def publish(context: JobContext) -> None:
        with transaction(factory) as session:
            checks.publish(session, app, settings, uuid.UUID(str(context.job.payload["check_id"])))

    into.handlers["github.sync_installation"] = sync
    into.handlers["checks.publish"] = publish


def _ai(
    settings: Settings, factory: sessionmaker[Session], http: httpx.Client, into: Integrations
) -> None:
    if settings.ai_provider != "anthropic" or settings.ai_api_key is None:
        return
    provider = AnthropicProvider(
        settings.ai_api_key.get_secret_value(), settings.ai_model or "claude-opus-5-5"
    )
    service = ExtractionService(
        provider=provider,
        sources=PypiSourceCache(settings.package_cache_dir / "packages", http),
        indexer=InProcessIndexer(),
        http=http,
        daily_budget_usd=Decimal(str(settings.ai_daily_budget_usd)),
    )

    def request_extraction(session: Session, finding: Finding) -> None:
        queue.enqueue(
            session,
            kind="symbols.extract",
            idempotency_key=f"symbols.extract:{finding.advisory_id}:{finding.package_id}:{PROMPT_VERSION}",
            payload={
                "advisory_id": str(finding.advisory_id),
                "package_id": str(finding.package_id),
                "version": finding.installed_version,
            },
            priority=120,
        )

    def extract(context: JobContext) -> None:
        payload = context.job.payload
        with transaction(factory) as session:
            record = service.extract(
                session,
                uuid.UUID(str(payload["advisory_id"])),
                uuid.UUID(str(payload["package_id"])),
                payload.get("version"),
            )
            if record.status is AIExtractionStatus.SUCCEEDED:
                rescan_affected(session, record.advisory_id, f"symbols:{record.id}")

    into.on_symbols_missing = request_extraction
    into.handlers["symbols.extract"] = extract


def build_integrations(
    settings: Settings, factory: sessionmaker[Session], http: httpx.Client
) -> Integrations:
    integrations = Integrations()
    _github(settings, factory, http, integrations)
    _ai(settings, factory, http, integrations)
    return integrations
