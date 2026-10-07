"""Requesting scans. Idempotent: the same request twice yields one scan and one job."""

import uuid

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from sieve.audit.log import record_event
from sieve.core.correlation import get_correlation_id
from sieve.db.enums import ActorType, ScanStatus, ScanTrigger
from sieve.db.models import Repository, Scan
from sieve.worker import queue

ANALYZER_VERSION = "0.1.0"


def request_scan(
    session: Session,
    repository: Repository,
    *,
    commit_sha: str,
    trigger: ScanTrigger,
    ref: str | None = None,
    idempotency_key: str | None = None,
    actor_type: ActorType = ActorType.SYSTEM,
    actor_id: str | None = None,
    priority: int = 100,
) -> tuple[Scan, bool]:
    key = idempotency_key or f"scan:{repository.id}:{commit_sha}:{ANALYZER_VERSION}"
    scan_id = session.scalar(
        insert(Scan)
        .values(
            id=uuid.uuid4(),
            organization_id=repository.organization_id,
            repository_id=repository.id,
            commit_sha=commit_sha,
            ref=ref,
            trigger=trigger,
            status=ScanStatus.QUEUED,
            idempotency_key=key,
            analyzer_version=ANALYZER_VERSION,
            correlation_id=get_correlation_id(),
            progress={},
            stats={},
        )
        .on_conflict_do_nothing(index_elements=[Scan.idempotency_key])
        .returning(Scan.id)
    )
    if scan_id is None:
        existing = session.scalar(select(Scan).where(Scan.idempotency_key == key))
        assert existing is not None  # noqa: S101
        return existing, False
    queue.enqueue(
        session,
        kind="scan.run",
        idempotency_key=f"scan.run:{scan_id}",
        payload={"scan_id": str(scan_id)},
        organization_id=repository.organization_id,
        priority=priority,
    )
    record_event(
        session,
        action="scan.requested",
        actor_type=actor_type,
        actor_id=actor_id,
        organization_id=repository.organization_id,
        target_type="scan",
        target_id=str(scan_id),
        data={"repository": repository.full_name, "commit": commit_sha, "trigger": str(trigger)},
    )
    scan = session.get(Scan, scan_id)
    assert scan is not None  # noqa: S101
    return scan, True
