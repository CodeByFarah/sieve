"""Organization-scoped views: overview, repositories, findings, activity, VEX history, policy,
search."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select

from sieve.api.access import ADMINS, ViewerDep, csrf_protect, organization_for, require_role
from sieve.api.deps import SessionDep
from sieve.api.queries import (
    FindingFilters,
    audit_events,
    decode_cursor,
    effective_verdict,
    encode_cursor,
    list_findings,
    repository_summaries,
)
from sieve.api.schemas import (
    AuditEventOut,
    FindingPage,
    OrganizationOut,
    OverviewOut,
    PolicyIn,
    PolicyOut,
    RepositoryOut,
    SearchOut,
    SeverityBreakdown,
    VerdictCounts,
    VexDocumentOut,
)
from sieve.audit.log import verify_chain
from sieve.db.enums import Presence, Severity, Verdict
from sieve.db.models import Advisory, Finding, Package, PolicyVersion, Repository, VexDocument
from sieve.policy.service import ensure_default_policy, update_policy

router = APIRouter(prefix="/api/v1/orgs/{login}", tags=["organizations"])


@router.get("/overview")
def overview(login: str, session: SessionDep, viewer: ViewerDep) -> OverviewOut:
    organization, role = organization_for(session, viewer, login)
    effective = effective_verdict()
    rows = session.execute(
        select(Advisory.severity, effective, func.count())
        .join(Finding, Finding.advisory_id == Advisory.id)
        .where(Finding.organization_id == organization.id, Finding.presence == Presence.PRESENT)
        .group_by(Advisory.severity, effective)
    ).all()
    totals = VerdictCounts()
    by_severity: dict[Severity, SeverityBreakdown] = {
        s: SeverityBreakdown(severity=s, reachable=0, needs_review=0, not_reached=0)
        for s in Severity
    }
    for severity, verdict, count in rows:
        totals.total += count
        key = str(verdict) if verdict else "pending"
        setattr(totals, key, getattr(totals, key) + count)
        if verdict is not None:
            setattr(
                by_severity[severity],
                str(verdict),
                getattr(by_severity[severity], str(verdict)) + count,
            )
    kev, kev_total = list_findings(session, [organization.id], FindingFilters(kev=True), limit=10)
    totals.kev = kev_total
    top, _ = list_findings(
        session, [organization.id], FindingFilters(verdicts=[Verdict.REACHABLE]), limit=5
    )
    return OverviewOut(
        organization=OrganizationOut(
            id=organization.id,
            login=organization.login,
            account_type=str(organization.account_type),
            role=role,
        ),
        totals=totals,
        severity=[
            by_severity[s]
            for s in (
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
                Severity.LOW,
                Severity.UNKNOWN,
            )
        ],
        kev_findings=kev,
        top_findings=top,
        repositories=repository_summaries(session, [organization.id]),
        activity=audit_events(session, organization.id, limit=15),
    )


@router.get("/repositories")
def repositories(login: str, session: SessionDep, viewer: ViewerDep) -> list[RepositoryOut]:
    organization, _ = organization_for(session, viewer, login)
    return repository_summaries(session, [organization.id])


@router.get("/findings")
def findings(
    login: str,
    session: SessionDep,
    viewer: ViewerDep,
    verdict: Annotated[list[Verdict] | None, Query()] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    kev: bool | None = None,
    package: Annotated[str | None, Query(max_length=100)] = None,
    repository_id: uuid.UUID | None = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
    presence: Presence = Presence.PRESENT,
    sort: Annotated[str, Query(pattern="^(risk|severity|discovered)$")] = "risk",
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> FindingPage:
    organization, _ = organization_for(session, viewer, login)
    offset = decode_cursor(cursor)
    filters = FindingFilters(
        verdicts=verdict or [],
        severities=severity or [],
        kev=kev,
        package=package,
        repository_id=repository_id,
        query=q,
        presence=presence,
    )
    items, total = list_findings(
        session, [organization.id], filters, sort=sort, offset=offset, limit=limit
    )
    next_cursor = encode_cursor(offset + limit) if offset + limit < total else None
    return FindingPage(items=items, total=total, next_cursor=next_cursor)


@router.get("/activity")
def activity(
    login: str,
    session: SessionDep,
    viewer: ViewerDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> dict[str, object]:
    organization, _ = organization_for(session, viewer, login)
    chain = verify_chain(session, organization.id)
    events: list[AuditEventOut] = audit_events(session, organization.id, limit=limit)
    return {
        "events": events,
        "chain": {"valid": chain.valid, "events_checked": chain.events_checked},
    }


@router.get("/vex")
def vex_documents(login: str, session: SessionDep, viewer: ViewerDep) -> list[VexDocumentOut]:
    organization, _ = organization_for(session, viewer, login)
    rows = session.execute(
        select(VexDocument, Repository.full_name)
        .outerjoin(Repository, Repository.id == VexDocument.repository_id)
        .where(VexDocument.organization_id == organization.id)
        .order_by(VexDocument.created_at.desc())
        .limit(100)
    ).all()
    return [
        VexDocumentOut(
            id=doc.id,
            format=doc.format,
            repository_id=doc.repository_id,
            repository_full_name=name,
            statement_count=doc.statement_count,
            sha256=doc.artifact_sha256.hex(),
            created_at=doc.created_at,
        )
        for doc, name in rows
    ]


def _policy_out(session: SessionDep, organization_id: object, can_edit: bool) -> PolicyOut:
    policy, version = ensure_default_policy(session, organization_id)  # type: ignore[arg-type]
    history = session.scalars(
        select(PolicyVersion)
        .where(PolicyVersion.policy_id == policy.id)
        .order_by(PolicyVersion.version.desc())
    ).all()
    return PolicyOut(
        version=version.version,
        rules=version.rules,
        created_at=version.created_at,
        can_edit=can_edit,
        history=[{"version": v.version, "created_at": v.created_at.isoformat()} for v in history],
    )


@router.get("/policy")
def get_policy(login: str, session: SessionDep, viewer: ViewerDep) -> PolicyOut:
    organization, role = organization_for(session, viewer, login)
    out = _policy_out(session, organization.id, role in ADMINS)
    session.commit()  # the default policy may have just been created
    return out


@router.put("/policy", dependencies=[Depends(csrf_protect)])
def put_policy(login: str, body: PolicyIn, session: SessionDep, viewer: ViewerDep) -> PolicyOut:
    user = viewer.require_user()
    organization, role = organization_for(session, viewer, login)
    require_role(role, ADMINS)
    update_policy(session, organization.id, body.rules, user.id)
    session.commit()
    return _policy_out(session, organization.id, True)


@router.get("/search")
def search(
    login: str,
    session: SessionDep,
    viewer: ViewerDep,
    q: Annotated[str, Query(min_length=1, max_length=100)],
) -> SearchOut:
    organization, _ = organization_for(session, viewer, login)
    needle = q.strip().lower()
    repos = [
        r for r in repository_summaries(session, [organization.id]) if needle in r.full_name.lower()
    ][:5]
    items, _ = list_findings(session, [organization.id], FindingFilters(query=q), limit=8)
    packages = session.execute(
        select(Package.name, func.count(Finding.id))
        .join(Finding, Finding.package_id == Package.id)
        .where(
            Finding.organization_id == organization.id,
            Finding.presence == Presence.PRESENT,
            Package.name.ilike(f"%{needle}%"),
        )
        .group_by(Package.name)
        .limit(5)
    ).all()
    return SearchOut(
        repositories=repos,
        findings=items,
        packages=[{"name": n, "findings": c} for n, c in packages],
    )
