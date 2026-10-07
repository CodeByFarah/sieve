"""PostgreSQL-backed job queue.

* ``enqueue`` runs in the caller's transaction and is idempotent on ``idempotency_key``.
* ``claim`` leases one job with ``FOR UPDATE SKIP LOCKED`` so concurrent workers never collide.
* ``complete`` / ``fail`` only succeed for the worker that still holds the lease; a worker whose
  lease expired (and whose job was reclaimed) cannot overwrite the new owner's outcome.
* Failed attempts are retried with exponential backoff and jitter until ``max_attempts``; then the
  job is ``dead`` — the dead-letter queue — with its last error preserved.
"""

import random
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from sieve.core.correlation import get_correlation_id
from sieve.core.ids import uuid7
from sieve.db.enums import JobStatus
from sieve.db.models import Job

MAX_ERROR_LENGTH = 4000


@dataclass(frozen=True)
class ClaimedJob:
    id: uuid.UUID
    kind: str
    payload: Mapping[str, Any]
    attempts: int
    max_attempts: int
    correlation_id: str | None
    organization_id: uuid.UUID | None


@dataclass(frozen=True)
class BackoffPolicy:
    base_seconds: float
    cap_seconds: float

    def delay(self, attempt: int, rng: random.Random | None = None) -> timedelta:
        """Full-jitter exponential backoff: uniform in [base·2^(attempt-1) / 2, base·2^(attempt-1)].

        Half of the delay is fixed so retries are never immediate; the other half is random so a
        burst of jobs that failed together does not retry together.
        """
        if attempt < 1:
            raise ValueError("attempt numbers start at 1")
        ceiling = min(self.cap_seconds, self.base_seconds * 2 ** (attempt - 1))
        jitter = (rng or random).uniform(0.5, 1.0)
        return timedelta(seconds=ceiling * jitter)


def enqueue(
    session: Session,
    *,
    kind: str,
    idempotency_key: str,
    payload: Mapping[str, Any] | None = None,
    organization_id: uuid.UUID | None = None,
    priority: int = 100,
    max_attempts: int = 5,
    run_after: datetime | None = None,
) -> uuid.UUID | None:
    """Insert a job unless one with the same idempotency key exists.

    Returns the new job's id, or ``None`` if the key was already used (duplicate event).
    """
    values: dict[str, Any] = {
        "id": uuid7(),
        "kind": kind,
        "idempotency_key": idempotency_key,
        "payload": dict(payload or {}),
        "organization_id": organization_id,
        "priority": priority,
        "max_attempts": max_attempts,
        "correlation_id": get_correlation_id(),
    }
    if run_after is not None:
        values["run_after"] = run_after
    statement = (
        insert(Job)
        .values(**values)
        .on_conflict_do_nothing(index_elements=[Job.idempotency_key])
        .returning(Job.id)
    )
    return session.scalar(statement)


def claim(session: Session, *, worker_id: str, lease_seconds: int) -> ClaimedJob | None:
    next_job = (
        select(Job.id)
        .where(Job.status == JobStatus.PENDING, Job.run_after <= func.now())
        .order_by(Job.priority, Job.run_after)
        .limit(1)
        .with_for_update(skip_locked=True)
        .scalar_subquery()
    )
    row = session.execute(
        update(Job)
        .where(Job.id == next_job)
        .values(
            status=JobStatus.RUNNING,
            locked_by=worker_id,
            lease_expires_at=func.now() + timedelta(seconds=lease_seconds),
            attempts=Job.attempts + 1,
        )
        .returning(
            Job.id,
            Job.kind,
            Job.payload,
            Job.attempts,
            Job.max_attempts,
            Job.correlation_id,
            Job.organization_id,
        )
    ).one_or_none()
    if row is None:
        return None
    return ClaimedJob(
        id=row.id,
        kind=row.kind,
        payload=row.payload,
        attempts=row.attempts,
        max_attempts=row.max_attempts,
        correlation_id=row.correlation_id,
        organization_id=row.organization_id,
    )


def _owned_by(job_id: uuid.UUID, worker_id: str) -> Any:
    return (Job.id == job_id) & (Job.status == JobStatus.RUNNING) & (Job.locked_by == worker_id)


def heartbeat(session: Session, *, job_id: uuid.UUID, worker_id: str, lease_seconds: int) -> bool:
    result = session.execute(
        update(Job)
        .where(_owned_by(job_id, worker_id))
        .values(lease_expires_at=func.now() + timedelta(seconds=lease_seconds))
        .returning(Job.id)
    )
    return result.one_or_none() is not None


def complete(session: Session, *, job_id: uuid.UUID, worker_id: str) -> bool:
    result = session.execute(
        update(Job)
        .where(_owned_by(job_id, worker_id))
        .values(
            status=JobStatus.SUCCEEDED,
            locked_by=None,
            lease_expires_at=None,
            finished_at=func.now(),
        )
        .returning(Job.id)
    )
    return result.one_or_none() is not None


def fail(
    session: Session,
    *,
    job: ClaimedJob,
    worker_id: str,
    error: str,
    retryable: bool,
    backoff: BackoffPolicy,
) -> JobStatus | None:
    """Record a failed attempt. Returns the job's new status, or ``None`` if the lease was lost."""
    give_up = not retryable or job.attempts >= job.max_attempts
    values: dict[str, Any] = {
        "locked_by": None,
        "lease_expires_at": None,
        "last_error": error[:MAX_ERROR_LENGTH],
    }
    if give_up:
        values |= {"status": JobStatus.DEAD, "finished_at": func.now()}
    else:
        values |= {
            "status": JobStatus.PENDING,
            "run_after": func.now() + backoff.delay(job.attempts),
        }
    result = session.execute(
        update(Job).where(_owned_by(job.id, worker_id)).values(**values).returning(Job.status)
    )
    return result.scalar_one_or_none()


def reap_expired_leases(session: Session) -> int:
    """Return jobs whose worker vanished to the queue (or to the DLQ if out of attempts)."""
    expired = (Job.status == JobStatus.RUNNING) & (Job.lease_expires_at < func.now())
    lease_lost = "lease expired: worker stopped heartbeating"
    dead = session.execute(
        update(Job)
        .where(expired & (Job.attempts >= Job.max_attempts))
        .values(
            status=JobStatus.DEAD,
            locked_by=None,
            lease_expires_at=None,
            last_error=lease_lost,
            finished_at=func.now(),
        )
        .returning(Job.id)
    ).all()
    requeued = session.execute(
        update(Job)
        .where(expired)
        .values(
            status=JobStatus.PENDING, locked_by=None, lease_expires_at=None, last_error=lease_lost
        )
        .returning(Job.id)
    ).all()
    return len(dead) + len(requeued)


def retry_dead(session: Session, *, job_id: uuid.UUID) -> bool:
    """Operator action: give a dead job a fresh set of attempts."""
    result = session.execute(
        update(Job)
        .where(Job.id == job_id, Job.status == JobStatus.DEAD)
        .values(status=JobStatus.PENDING, attempts=0, run_after=func.now(), finished_at=None)
        .returning(Job.id)
    )
    return result.one_or_none() is not None
