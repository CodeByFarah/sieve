"""New or changed advisories → rescans of the repositories they could affect (spec §30).

One fan-out job per ingestion run, and at most one rescan per repository per run: a bulk
ingestion that changes 300 advisories rescans each affected repository once, and a duplicate
fan-out job (redelivery, retry) creates nothing new because every scan key includes the run id.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from sieve.db.enums import ScanTrigger
from sieve.db.models import (
    Advisory,
    AdvisoryPackage,
    Dependency,
    Finding,
    IngestionRun,
    Repository,
    Scan,
)
from sieve.scans.service import ANALYZER_VERSION, request_scan

FANOUT_PRIORITY = 150  # behind user-requested scans


def changed_advisory_ids(session: Session, run: IngestionRun) -> list[uuid.UUID]:
    statement = select(Advisory.id).where(Advisory.ingested_at >= run.started_at)
    if run.finished_at is not None:
        statement = statement.where(Advisory.ingested_at <= run.finished_at)
    return list(session.scalars(statement))


def affected_repositories(
    session: Session, run: IngestionRun, advisory_ids: list[uuid.UUID]
) -> list[tuple[Repository, Scan]]:
    package_ids = select(AdvisoryPackage.package_id).where(
        AdvisoryPackage.advisory_id.in_(advisory_ids)
    )
    statement = (
        select(Repository, Scan)
        .join(Scan, Scan.id == Repository.latest_scan_id)
        .join(Dependency, Dependency.scan_id == Scan.id)
        .where(Repository.is_active.is_(True), Dependency.package_id.in_(package_ids))
        .distinct()
    )
    if run.finished_at is not None:
        # A scan requested after the run finished already matched against its advisories.
        statement = statement.where(Scan.created_at < run.finished_at)
    return [(repository, scan) for repository, scan in session.execute(statement).all()]


def fan_out(session: Session, run_id: uuid.UUID) -> list[uuid.UUID]:
    run = session.get(IngestionRun, run_id)
    if run is None:
        return []
    advisory_ids = changed_advisory_ids(session, run)
    if not advisory_ids:
        return []
    created = []
    for repository, latest in affected_repositories(session, run, advisory_ids):
        scan, is_new = request_scan(
            session,
            repository,
            commit_sha=latest.commit_sha,
            ref=latest.ref,
            trigger=ScanTrigger.ADVISORY,
            idempotency_key=f"scan:{repository.id}:{latest.commit_sha}:{ANALYZER_VERSION}:ingest:{run_id}",
            priority=FANOUT_PRIORITY,
        )
        if is_new:
            created.append(scan.id)
    return created


def rescan_affected(session: Session, advisory_id: uuid.UUID, reason: str) -> list[uuid.UUID]:
    """Re-analyse every repository whose latest scan has a finding for this advisory, e.g. after
    new symbols were verified for it."""
    rows = session.execute(
        select(Repository, Scan)
        .join(Scan, Scan.id == Repository.latest_scan_id)
        .join(Finding, Finding.repository_id == Repository.id)
        .where(Finding.advisory_id == advisory_id, Repository.is_active.is_(True))
        .distinct()
    ).all()
    created = []
    for repository, latest in rows:
        scan, is_new = request_scan(
            session,
            repository,
            commit_sha=latest.commit_sha,
            ref=latest.ref,
            trigger=ScanTrigger.ADVISORY,
            idempotency_key=f"scan:{repository.id}:{latest.commit_sha}:{ANALYZER_VERSION}:{reason}",
            priority=FANOUT_PRIORITY,
        )
        if is_new:
            created.append(scan.id)
    return created
