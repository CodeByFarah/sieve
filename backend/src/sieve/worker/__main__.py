"""Entry point: ``python -m sieve.worker`` (or the ``sieve-worker`` script)."""

import signal
from types import FrameType

from sieve.analysis.sandbox import ProcessIndexer
from sieve.core.config import get_settings
from sieve.core.http import build_client
from sieve.core.logging import configure_logging
from sieve.core.telemetry import configure_telemetry, instrument_engine, serve_worker_metrics
from sieve.db.session import create_db_engine, create_session_factory
from sieve.integrations import build_integrations
from sieve.runtime import build_artifact_store, build_engine, build_workspaces, tool_version
from sieve.scans.pipeline import PipelineDeps, ScanPipeline
from sieve.worker.handlers import HandlerDeps, make_scheduler, registered_handlers
from sieve.worker.queue import BackoffPolicy
from sieve.worker.runner import Worker, WorkerConfig


def main() -> None:
    settings = get_settings()
    configure_logging(level=settings.log_level, json=settings.log_json)
    configure_telemetry(settings, service="sieve-worker")
    serve_worker_metrics(settings)
    engine = create_db_engine(settings)
    instrument_engine(engine)
    factory = create_session_factory(engine)
    http = build_client(timeout=60)
    indexer = ProcessIndexer(workers=settings.indexer_workers)
    artifacts = build_artifact_store(settings)
    integrations = build_integrations(settings, factory, http)
    pipeline = ScanPipeline(
        PipelineDeps(
            session_factory=factory,
            workspaces=build_workspaces(settings, integrations.github_workspaces),
            engine=build_engine(settings, http, indexer),
            artifacts=artifacts,
            tool_version=tool_version(),
            on_symbols_missing=integrations.on_symbols_missing,
        )
    )
    worker = Worker(
        session_factory=factory,
        handlers=registered_handlers(
            HandlerDeps(settings, factory, http, pipeline, integrations.handlers)
        ),
        config=WorkerConfig(
            lease_seconds=settings.job_lease_seconds,
            poll_interval_seconds=settings.worker_poll_interval_seconds,
            reap_interval_seconds=settings.worker_reap_interval_seconds,
            schedule_interval_seconds=settings.worker_schedule_interval_seconds,
            backoff=BackoffPolicy(
                base_seconds=settings.job_backoff_base_seconds,
                cap_seconds=settings.job_backoff_cap_seconds,
            ),
        ),
        scheduler=make_scheduler(settings),
    )

    def _shutdown(_signum: int, _frame: FrameType | None) -> None:
        worker.stop()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    try:
        worker.run_forever()
    finally:
        indexer.close()
        http.close()
        engine.dispose()


if __name__ == "__main__":
    main()
