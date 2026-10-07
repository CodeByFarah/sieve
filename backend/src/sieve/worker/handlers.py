"""Job-kind → handler registry, and the periodic schedule.

A job whose kind has no handler goes straight to the dead-letter queue.
"""

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx
from sqlalchemy.orm import Session, sessionmaker

from sieve.advisories.fanout import fan_out
from sieve.advisories.ingest import ingest_epss, ingest_kev, ingest_osv_export
from sieve.core.config import Settings
from sieve.db.session import transaction
from sieve.demo.seed import apply_demo_reviews
from sieve.scans.pipeline import ScanPipeline
from sieve.worker import queue
from sieve.worker.runner import Handler, JobContext


@dataclass
class HandlerDeps:
    settings: Settings
    session_factory: sessionmaker[Session]
    http: httpx.Client
    pipeline: ScanPipeline
    extra: dict[str, Handler] = field(default_factory=dict)  # contributed by optional integrations


def registered_handlers(deps: HandlerDeps) -> dict[str, Handler]:
    factory = deps.session_factory

    def run_scan(context: JobContext) -> None:
        deps.pipeline.run(uuid.UUID(str(context.job.payload["scan_id"])))

    def fanout(context: JobContext) -> None:
        with transaction(factory) as session:
            fan_out(session, uuid.UUID(str(context.job.payload["run_id"])))

    def osv(_context: JobContext) -> None:
        ingest_osv_export(factory, deps.http)

    def kev(_context: JobContext) -> None:
        ingest_kev(factory, deps.http)

    def epss(_context: JobContext) -> None:
        ingest_epss(factory, deps.http)

    def demo_reviews(_context: JobContext) -> None:
        with transaction(factory) as session:
            apply_demo_reviews(session, deps.settings.demo_reviews_file)

    handlers: dict[str, Handler] = {
        "demo.apply_reviews": demo_reviews,
        "scan.run": run_scan,
        "advisories.fanout": fanout,
        "advisories.ingest_osv": osv,
        "advisories.ingest_kev": kev,
        "advisories.ingest_epss": epss,
    }
    handlers.update(deps.extra)
    return handlers


def scheduled_jobs(settings: Settings) -> list[tuple[str, int]]:
    return [
        (kind, hours)
        for kind, hours in (
            ("advisories.ingest_osv", settings.ingest_osv_every_hours),
            ("advisories.ingest_kev", settings.ingest_kev_every_hours),
            ("advisories.ingest_epss", settings.ingest_epss_every_hours),
        )
        if hours > 0
    ]


def make_scheduler(settings: Settings) -> Callable[[Session], int]:
    """Enqueue each periodic job once per period. The idempotency key is the period number, so
    any number of workers running this concurrently enqueue each run exactly once."""

    def schedule(session: Session) -> int:
        now = datetime.now(UTC).timestamp()
        created = 0
        for kind, hours in scheduled_jobs(settings):
            period = int(now // (hours * 3600))
            job = queue.enqueue(
                session, kind=kind, idempotency_key=f"{kind}:period:{hours}h:{period}", priority=200
            )
            created += job is not None
        return created

    return schedule
