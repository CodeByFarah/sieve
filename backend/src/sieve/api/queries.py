"""Read-side queries for the API: findings with their effective verdict and exploitation signals,
repository summaries, activity. Kept out of the routers so each can be tested and tuned alone."""

import base64
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import ColumnElement, Select, any_, case, exists, func, or_, select
from sqlalchemy.orm import Session

from sieve.api.schemas import (
    AuditEventOut,
    FindingItemOut,
    RepositoryOut,
    ScanOut,
    VerdictCounts,
)
from sieve.db.enums import ActorType, Presence, ReviewState, ScanStatus, Severity, Verdict
from sieve.db.models import (
    Advisory,
    AuditEvent,
    EpssScore,
    Finding,
    KevEntry,
    Package,
    Repository,
    Scan,
    User,
)

SEVERITY_ORDER = case(
    {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 2}, value=Advisory.severity
)


def effective_verdict() -> ColumnElement[Any]:
    reviewed = Finding.review_state.in_(
        [ReviewState.ACCEPTED, ReviewState.OVERRIDDEN]
    ) & Finding.decided_verdict.is_not(None)
    return case((reviewed, Finding.decided_verdict), else_=Finding.verdict)


def kev_flag() -> ColumnElement[bool]:
    return exists().where(
        or_(KevEntry.cve_id == any_(Advisory.aliases), KevEntry.cve_id == Advisory.source_id)
    )


def epss_percentile() -> Any:
    return (
        select(func.max(EpssScore.percentile))
        .where(
            or_(EpssScore.cve_id == any_(Advisory.aliases), EpssScore.cve_id == Advisory.source_id)
        )
        .scalar_subquery()
    )


@dataclass
class FindingFilters:
    verdicts: list[Verdict] = field(default_factory=list)
    severities: list[Severity] = field(default_factory=list)
    kev: bool | None = None
    package: str | None = None
    repository_id: uuid.UUID | None = None
    query: str | None = None
    presence: Presence = Presence.PRESENT


def finding_select() -> Select[Any]:  # wide row: Finding, Advisory, labels
    return (
        select(
            Finding,
            Advisory,
            Package.name.label("package"),
            Repository.full_name.label("repository"),
            effective_verdict().label("effective"),
            kev_flag().label("kev"),
            epss_percentile().label("epss"),
        )
        .join(Advisory, Advisory.id == Finding.advisory_id)
        .join(Package, Package.id == Finding.package_id)
        .join(Repository, Repository.id == Finding.repository_id)
    )


def finding_item(row: Any) -> FindingItemOut:
    finding: Finding = row.Finding
    advisory: Advisory = row.Advisory
    return FindingItemOut(
        id=finding.id,
        advisory_id=advisory.source_id,
        aliases=advisory.aliases,
        summary=advisory.summary,
        package=row.package,
        installed_version=finding.installed_version,
        severity=advisory.severity,
        cvss_score=advisory.cvss_score,
        verdict=finding.verdict,
        effective_verdict=row.effective,
        confidence=finding.confidence,
        review_state=finding.review_state,
        risk_score=finding.risk_score,
        kev=bool(row.kev),
        epss_percentile=row.epss,
        presence=finding.presence,
        repository_id=finding.repository_id,
        repository_full_name=row.repository,
        first_seen_at=finding.created_at,
    )


def encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(f"o:{offset}".encode()).decode()


def decode_cursor(cursor: str | None) -> int:
    if not cursor:
        return 0
    try:
        kind, _, value = base64.urlsafe_b64decode(cursor.encode()).decode().partition(":")
        offset = int(value)
    except (ValueError, UnicodeDecodeError):
        return 0
    return offset if kind == "o" and 0 <= offset < 1_000_000 else 0


def list_findings(
    session: Session,
    organization_ids: list[uuid.UUID],
    filters: FindingFilters,
    *,
    sort: str = "risk",
    offset: int = 0,
    limit: int = 50,
) -> tuple[list[FindingItemOut], int]:
    statement = finding_select().where(
        Finding.organization_id.in_(organization_ids), Finding.presence == filters.presence
    )
    if filters.verdicts:
        statement = statement.where(effective_verdict().in_(filters.verdicts))
    if filters.severities:
        statement = statement.where(Advisory.severity.in_(filters.severities))
    if filters.kev is not None:
        statement = statement.where(kev_flag() if filters.kev else ~kev_flag())
    if filters.package:
        statement = statement.where(Package.name == filters.package.lower())
    if filters.repository_id:
        statement = statement.where(Finding.repository_id == filters.repository_id)
    if filters.query:
        pattern = f"%{filters.query.strip()[:100]}%"
        statement = statement.where(
            or_(
                Advisory.source_id.ilike(pattern),
                Package.name.ilike(pattern),
                Advisory.summary.ilike(pattern),
                func.array_to_string(Advisory.aliases, " ").ilike(pattern),
            )
        )
    total = (
        session.scalar(select(func.count()).select_from(statement.order_by(None).subquery())) or 0
    )
    order = {
        "risk": [Finding.risk_score.desc().nulls_last(), Finding.id],
        "severity": [SEVERITY_ORDER.desc(), Finding.risk_score.desc().nulls_last(), Finding.id],
        "discovered": [Finding.created_at.desc(), Finding.id],
    }.get(sort, [Finding.risk_score.desc().nulls_last(), Finding.id])
    rows = session.execute(statement.order_by(*order).offset(offset).limit(limit)).all()
    return [finding_item(row) for row in rows], total


def verdict_counts(
    session: Session, repository_ids: list[uuid.UUID]
) -> dict[uuid.UUID, VerdictCounts]:
    effective = effective_verdict()
    rows = session.execute(
        select(Finding.repository_id, effective, kev_flag(), func.count())
        .join(Advisory, Advisory.id == Finding.advisory_id)
        .where(Finding.repository_id.in_(repository_ids), Finding.presence == Presence.PRESENT)
        .group_by(Finding.repository_id, effective, kev_flag())
    ).all()
    counts: dict[uuid.UUID, VerdictCounts] = {rid: VerdictCounts() for rid in repository_ids}
    for repository_id, verdict, kev, count in rows:
        bucket = counts[repository_id]
        bucket.total += count
        if kev:
            bucket.kev += count
        key = str(verdict) if verdict else "pending"
        setattr(bucket, key, getattr(bucket, key) + count)
    return counts


def scan_out(scan: Scan) -> ScanOut:
    return ScanOut.model_validate(scan)


def _health(scan: Scan | None, counts: VerdictCounts) -> str:
    if scan is None:
        return "pending"
    if scan.status is ScanStatus.FAILED:
        return "failing"
    if counts.reachable or counts.kev:
        return "attention"
    return "healthy"


def repository_summaries(
    session: Session, organization_ids: list[uuid.UUID]
) -> list[RepositoryOut]:
    repositories = session.scalars(
        select(Repository)
        .where(Repository.organization_id.in_(organization_ids), Repository.is_active.is_(True))
        .order_by(Repository.full_name)
    ).all()
    counts = verdict_counts(session, [r.id for r in repositories])
    scans = {
        scan.id: scan
        for scan in session.scalars(
            select(Scan).where(
                Scan.id.in_([r.latest_scan_id for r in repositories if r.latest_scan_id])
            )
        )
    }
    active = {
        scan.repository_id: scan
        for scan in session.scalars(
            select(Scan)
            .where(
                Scan.repository_id.in_([r.id for r in repositories]),
                Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING]),
            )
            .order_by(Scan.created_at)
        )
    }
    summaries = []
    for repository in repositories:
        latest = active.get(repository.id) or scans.get(repository.latest_scan_id)  # type: ignore[arg-type]
        bucket = counts[repository.id]
        summaries.append(
            RepositoryOut(
                id=repository.id,
                full_name=repository.full_name,
                source=str(repository.source),
                default_branch=repository.default_branch,
                is_private=repository.is_private,
                latest_scan=scan_out(latest) if latest else None,
                counts=bucket,
                health=_health(
                    scans.get(repository.latest_scan_id) if repository.latest_scan_id else None,
                    bucket,
                ),
            )
        )
    order = {"failing": 0, "attention": 1, "pending": 2, "healthy": 3}
    return sorted(summaries, key=lambda r: (order[r.health], -r.counts.reachable, r.full_name))


def audit_events(
    session: Session,
    organization_id: uuid.UUID,
    *,
    target: tuple[str, str] | None = None,
    limit: int = 50,
) -> list[AuditEventOut]:
    statement = select(AuditEvent).where(AuditEvent.organization_id == organization_id)
    if target is not None:
        statement = statement.where(
            AuditEvent.target_type == target[0], AuditEvent.target_id == target[1]
        )
        statement = statement.order_by(AuditEvent.seq.asc())
    else:
        statement = statement.order_by(AuditEvent.seq.desc())
    events = session.scalars(statement.limit(limit)).all()
    user_ids = {
        uuid.UUID(e.actor_id) for e in events if e.actor_type is ActorType.USER and e.actor_id
    }
    logins = (
        dict(session.execute(select(User.id, User.login).where(User.id.in_(user_ids))).all())
        if user_ids
        else {}
    )
    return [
        AuditEventOut(
            seq=event.seq,
            action=event.action,
            actor_type=str(event.actor_type),
            actor_login=logins.get(uuid.UUID(event.actor_id))
            if event.actor_type is ActorType.USER and event.actor_id
            else None,
            target_type=event.target_type,
            target_id=event.target_id,
            data=event.data,
            correlation_id=event.correlation_id,
            occurred_at=event.occurred_at,
        )
        for event in events
    ]
