from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import Engine, delete, func, select, update
from sqlalchemy.orm import Session

from sieve.db.enums import JobStatus
from sieve.db.models import Job
from sieve.worker import queue
from sieve.worker.queue import BackoffPolicy

BACKOFF = BackoffPolicy(base_seconds=30, cap_seconds=3600)
LEASE = 60


def get_job(session: Session, job_id: object) -> Job:
    session.expire_all()
    job = session.get(Job, job_id)
    assert job is not None
    return job


def test_enqueue_is_idempotent(session: Session) -> None:
    first = queue.enqueue(session, kind="scan.run", idempotency_key="scan:r1:abc")
    second = queue.enqueue(session, kind="scan.run", idempotency_key="scan:r1:abc")
    assert first is not None
    assert second is None
    count = session.scalar(
        select(func.count()).select_from(Job).where(Job.idempotency_key == "scan:r1:abc")
    )
    assert count == 1


def test_claim_leases_the_highest_priority_due_job(session: Session) -> None:
    low = queue.enqueue(session, kind="k", idempotency_key="low", priority=200)
    high = queue.enqueue(session, kind="k", idempotency_key="high", priority=10)
    queue.enqueue(
        session,
        kind="k",
        idempotency_key="future",
        priority=0,
        run_after=datetime.now(UTC) + timedelta(hours=1),
    )

    claimed = queue.claim(session, worker_id="w1", lease_seconds=LEASE)

    assert claimed is not None
    assert claimed.id == high
    assert claimed.attempts == 1
    job = get_job(session, high)
    assert job.status is JobStatus.RUNNING
    assert job.locked_by == "w1"
    assert job.lease_expires_at is not None
    assert get_job(session, low).status is JobStatus.PENDING


def test_claim_returns_none_when_nothing_is_due(session: Session) -> None:
    assert queue.claim(session, worker_id="w1", lease_seconds=LEASE) is None


def test_complete_marks_success(session: Session) -> None:
    job_id = queue.enqueue(session, kind="k", idempotency_key="c1")
    claimed = queue.claim(session, worker_id="w1", lease_seconds=LEASE)
    assert claimed is not None

    assert queue.complete(session, job_id=claimed.id, worker_id="w1") is True

    job = get_job(session, job_id)
    assert job.status is JobStatus.SUCCEEDED
    assert job.finished_at is not None
    assert job.locked_by is None


def test_only_the_lease_holder_can_record_an_outcome(session: Session) -> None:
    queue.enqueue(session, kind="k", idempotency_key="owned")
    claimed = queue.claim(session, worker_id="w1", lease_seconds=LEASE)
    assert claimed is not None

    assert queue.complete(session, job_id=claimed.id, worker_id="impostor") is False
    assert (
        queue.heartbeat(session, job_id=claimed.id, worker_id="impostor", lease_seconds=LEASE)
        is False
    )
    assert (
        queue.fail(
            session, job=claimed, worker_id="impostor", error="x", retryable=True, backoff=BACKOFF
        )
        is None
    )
    assert get_job(session, claimed.id).status is JobStatus.RUNNING


def test_retryable_failure_is_rescheduled_with_backoff(session: Session) -> None:
    job_id = queue.enqueue(session, kind="k", idempotency_key="retry", max_attempts=3)
    claimed = queue.claim(session, worker_id="w1", lease_seconds=LEASE)
    assert claimed is not None

    status = queue.fail(
        session, job=claimed, worker_id="w1", error="GitHub 502", retryable=True, backoff=BACKOFF
    )

    assert status is JobStatus.PENDING
    job = get_job(session, job_id)
    db_now = session.scalar(select(func.now()))
    assert db_now is not None
    assert job.run_after >= db_now + timedelta(seconds=BACKOFF.base_seconds / 2)
    assert job.last_error == "GitHub 502"
    assert job.attempts == 1
    # Not claimable until the backoff elapses.
    assert queue.claim(session, worker_id="w1", lease_seconds=LEASE) is None


def test_job_goes_to_dead_letter_after_max_attempts(session: Session) -> None:
    job_id = queue.enqueue(session, kind="k", idempotency_key="dies", max_attempts=2)
    for attempt in (1, 2):
        session.execute(update(Job).where(Job.id == job_id).values(run_after=func.now()))
        claimed = queue.claim(session, worker_id="w1", lease_seconds=LEASE)
        assert claimed is not None
        assert claimed.attempts == attempt
        status = queue.fail(
            session,
            job=claimed,
            worker_id="w1",
            error=f"boom {attempt}",
            retryable=True,
            backoff=BACKOFF,
        )
    assert status is JobStatus.DEAD
    job = get_job(session, job_id)
    assert job.last_error == "boom 2"
    assert job.finished_at is not None


def test_permanent_failure_goes_straight_to_dead_letter(session: Session) -> None:
    job_id = queue.enqueue(session, kind="k", idempotency_key="perm", max_attempts=5)
    claimed = queue.claim(session, worker_id="w1", lease_seconds=LEASE)
    assert claimed is not None

    status = queue.fail(
        session, job=claimed, worker_id="w1", error="bad lockfile", retryable=False, backoff=BACKOFF
    )

    assert status is JobStatus.DEAD
    assert get_job(session, job_id).attempts == 1


def test_dead_job_can_be_retried_by_an_operator(session: Session) -> None:
    job_id = queue.enqueue(session, kind="k", idempotency_key="revive", max_attempts=1)
    claimed = queue.claim(session, worker_id="w1", lease_seconds=LEASE)
    assert claimed is not None
    queue.fail(session, job=claimed, worker_id="w1", error="x", retryable=True, backoff=BACKOFF)
    assert job_id is not None

    assert queue.retry_dead(session, job_id=job_id) is True

    job = get_job(session, job_id)
    assert job.status is JobStatus.PENDING
    assert job.attempts == 0


def test_expired_leases_are_requeued_or_dead_lettered(session: Session) -> None:
    requeue_id = queue.enqueue(session, kind="k", idempotency_key="crashed", max_attempts=3)
    dead_id = queue.enqueue(session, kind="k", idempotency_key="crashed-last", max_attempts=1)
    for _ in range(2):
        assert queue.claim(session, worker_id="w1", lease_seconds=LEASE) is not None
    session.execute(update(Job).values(lease_expires_at=func.now() - timedelta(seconds=1)))

    assert queue.reap_expired_leases(session) == 2

    assert get_job(session, requeue_id).status is JobStatus.PENDING
    assert get_job(session, dead_id).status is JobStatus.DEAD


@pytest.fixture
def committed_engine(engine: Engine) -> Iterator[Engine]:
    """For tests that need two real concurrent transactions; cleans up after itself."""
    yield engine
    with engine.begin() as connection:
        connection.execute(delete(Job).where(Job.idempotency_key.like("concurrent:%")))


def test_concurrent_workers_never_claim_the_same_job(committed_engine: Engine) -> None:
    with Session(committed_engine) as setup, setup.begin():
        for n in range(2):
            queue.enqueue(setup, kind="k", idempotency_key=f"concurrent:{n}")

    with (
        Session(committed_engine) as first,
        Session(committed_engine) as second,
        first.begin(),
        second.begin(),
    ):
        # `first` holds a row lock on its job until it commits; `second` must skip it.
        job_a = queue.claim(first, worker_id="a", lease_seconds=LEASE)
        job_b = queue.claim(second, worker_id="b", lease_seconds=LEASE)
        assert job_a is not None
        assert job_b is not None
        assert job_a.id != job_b.id
