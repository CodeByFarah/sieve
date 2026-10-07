from sqlalchemy.orm import Session, sessionmaker

from sieve.core.correlation import get_correlation_id
from sieve.core.errors import ExternalServiceError, UserError
from sieve.db.enums import JobStatus
from sieve.db.models import Job
from sieve.db.session import transaction
from sieve.worker import queue
from sieve.worker.queue import BackoffPolicy
from sieve.worker.runner import JobContext, Worker, WorkerConfig

CONFIG = WorkerConfig(
    lease_seconds=60,
    poll_interval_seconds=0.01,
    reap_interval_seconds=60,
    backoff=BackoffPolicy(base_seconds=30, cap_seconds=60),
)


def make_worker(factory: sessionmaker[Session], **handlers: object) -> Worker:
    return Worker(factory, handlers=handlers, config=CONFIG, worker_id="test-worker")  # type: ignore[arg-type]


def enqueue(factory: sessionmaker[Session], kind: str, key: str) -> object:
    with transaction(factory) as session:
        return queue.enqueue(session, kind=kind, idempotency_key=key, payload={"n": 1})


def status_of(session: Session, job_id: object) -> JobStatus:
    session.expire_all()
    job = session.get(Job, job_id)
    assert job is not None
    return job.status


def test_successful_handler_completes_job(
    session_factory: sessionmaker[Session], session: Session
) -> None:
    seen: list[dict[str, object]] = []

    def handler(context: JobContext) -> None:
        seen.append({"payload": dict(context.job.payload), "correlation": get_correlation_id()})

    job_id = enqueue(session_factory, "test.echo", "w-ok")
    worker = make_worker(session_factory, **{"test.echo": handler})

    assert worker.run_once() is True
    assert worker.run_once() is False
    assert seen[0]["payload"] == {"n": 1}
    assert seen[0]["correlation"] is not None
    assert status_of(session, job_id) is JobStatus.SUCCEEDED


def test_transient_failure_is_retried_later(
    session_factory: sessionmaker[Session], session: Session
) -> None:
    def handler(_context: JobContext) -> None:
        raise ExternalServiceError("OSV returned 503")

    job_id = enqueue(session_factory, "test.flaky", "w-flaky")
    make_worker(session_factory, **{"test.flaky": handler}).run_once()

    assert status_of(session, job_id) is JobStatus.PENDING


def test_permanent_failure_is_dead_lettered(
    session_factory: sessionmaker[Session], session: Session
) -> None:
    def handler(_context: JobContext) -> None:
        raise UserError("unsupported lockfile")

    job_id = enqueue(session_factory, "test.bad", "w-bad")
    make_worker(session_factory, **{"test.bad": handler}).run_once()

    assert status_of(session, job_id) is JobStatus.DEAD


def test_unexpected_exception_is_not_retried(
    session_factory: sessionmaker[Session], session: Session
) -> None:
    """A bug is not transient: retrying it would only repeat the failure."""

    def handler(_context: JobContext) -> None:
        raise KeyError("missing")

    job_id = enqueue(session_factory, "test.bug", "w-bug")
    make_worker(session_factory, **{"test.bug": handler}).run_once()

    session.expire_all()
    job = session.get(Job, job_id)
    assert job is not None
    assert job.status is JobStatus.DEAD
    assert job.last_error is not None
    assert "KeyError" in job.last_error


def test_unknown_job_kind_is_dead_lettered(
    session_factory: sessionmaker[Session], session: Session
) -> None:
    job_id = enqueue(session_factory, "test.nobody-handles-this", "w-unknown")
    make_worker(session_factory).run_once()

    session.expire_all()
    job = session.get(Job, job_id)
    assert job is not None
    assert job.status is JobStatus.DEAD
    assert job.last_error is not None
    assert "no handler registered" in job.last_error
