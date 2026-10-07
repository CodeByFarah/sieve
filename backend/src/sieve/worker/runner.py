"""The worker loop: claim a job, run its handler, record the outcome."""

import os
import socket
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from sqlalchemy.orm import Session, sessionmaker

from sieve.core.correlation import correlation_scope, new_correlation_id
from sieve.core.errors import SieveError
from sieve.core.logging import get_logger
from sieve.core.telemetry import JOB_DURATION, JOBS
from sieve.db.session import transaction
from sieve.worker import queue
from sieve.worker.queue import BackoffPolicy, ClaimedJob

log = get_logger(__name__)


@dataclass(frozen=True)
class JobContext:
    job: ClaimedJob
    session_factory: sessionmaker[Session]


Handler = Callable[[JobContext], None]


class UnknownJobKind(SieveError):
    code = "unknown_job_kind"


@dataclass(frozen=True)
class WorkerConfig:
    lease_seconds: int
    poll_interval_seconds: float
    reap_interval_seconds: float
    backoff: BackoffPolicy
    schedule_interval_seconds: float = 60.0


def default_worker_id() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"


class Worker:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        handlers: Mapping[str, Handler],
        config: WorkerConfig,
        worker_id: str | None = None,
        scheduler: Callable[[Session], int] | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._handlers = dict(handlers)
        self._config = config
        self.worker_id = worker_id or default_worker_id()
        self._scheduler = scheduler
        self._stop = threading.Event()
        self._last_reap = 0.0
        self._last_schedule = 0.0

    def stop(self) -> None:
        self._stop.set()

    def run_forever(self) -> None:
        log.info("worker.started", worker_id=self.worker_id, kinds=sorted(self._handlers))
        while not self._stop.is_set():
            self._maybe_reap()
            self._maybe_schedule()
            if not self.run_once():
                self._stop.wait(self._config.poll_interval_seconds)
        log.info("worker.stopped", worker_id=self.worker_id)

    def run_once(self) -> bool:
        """Process at most one job. Returns whether a job was found."""
        with transaction(self._session_factory) as session:
            job = queue.claim(
                session, worker_id=self.worker_id, lease_seconds=self._config.lease_seconds
            )
        if job is None:
            return False
        with correlation_scope(job.correlation_id or new_correlation_id()):
            self._execute(job)
        return True

    def _execute(self, job: ClaimedJob) -> None:
        bound = log.bind(job_id=str(job.id), kind=job.kind, attempt=job.attempts)
        started = time.monotonic()
        try:
            handler = self._handlers.get(job.kind)
            if handler is None:
                raise UnknownJobKind(f"no handler registered for job kind {job.kind!r}")
            handler(JobContext(job=job, session_factory=self._session_factory))
        except Exception as exc:  # noqa: BLE001 - every failure is recorded, then classified
            self._record_failure(job, exc)
            JOB_DURATION.record(time.monotonic() - started, {"kind": job.kind})
            return
        with transaction(self._session_factory) as session:
            owned = queue.complete(session, job_id=job.id, worker_id=self.worker_id)
        duration = round(time.monotonic() - started, 3)
        JOB_DURATION.record(duration, {"kind": job.kind})
        JOBS.add(1, {"kind": job.kind, "outcome": "succeeded" if owned else "lease_lost"})
        if owned:
            bound.info("job.succeeded", duration_seconds=duration)
        else:
            bound.warning("job.lease_lost", duration_seconds=duration)

    def _record_failure(self, job: ClaimedJob, exc: Exception) -> None:
        retryable = exc.retryable if isinstance(exc, SieveError) else False
        with transaction(self._session_factory) as session:
            status = queue.fail(
                session,
                job=job,
                worker_id=self.worker_id,
                error=f"{type(exc).__name__}: {exc}",
                retryable=retryable,
                backoff=self._config.backoff,
            )
        outcome = "lease_lost" if status is None else str(status)
        JOBS.add(1, {"kind": job.kind, "outcome": "retrying" if outcome == "pending" else outcome})
        log.error(
            "job.failed",
            job_id=str(job.id),
            kind=job.kind,
            attempt=job.attempts,
            retryable=retryable,
            new_status=str(status) if status else "lease_lost",
            exc_info=exc,
        )

    def _maybe_schedule(self) -> None:
        now = time.monotonic()
        if (
            self._scheduler is None
            or now - self._last_schedule < self._config.schedule_interval_seconds
        ):
            return
        self._last_schedule = now
        with transaction(self._session_factory) as session:
            created = self._scheduler(session)
        if created:
            log.info("worker.scheduled_jobs", count=created)

    def _maybe_reap(self) -> None:
        now = time.monotonic()
        if now - self._last_reap < self._config.reap_interval_seconds:
            return
        self._last_reap = now
        with transaction(self._session_factory) as session:
            reaped = queue.reap_expired_leases(session)
        if reaped:
            log.warning("worker.reaped_expired_leases", count=reaped)
