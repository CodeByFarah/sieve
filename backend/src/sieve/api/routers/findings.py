"""Finding detail — the evidence page — and review decisions."""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from sieve.api.access import WRITERS, ViewerDep, csrf_protect, finding_for, require_role
from sieve.api.deps import SessionDep
from sieve.api.queries import audit_events, finding_item, finding_select
from sieve.api.ratelimit import enforce
from sieve.api.schemas import (
    AdvisoryOut,
    AIExtractionOut,
    AnalysisOut,
    ExploitationOut,
    FindingDetailOut,
    PathOut,
    ReviewIn,
    ReviewOut,
    SymbolOut,
)
from sieve.db.enums import AccountType
from sieve.db.models import (
    Advisory,
    AIExtraction,
    AnalysisResult,
    EpssScore,
    Finding,
    KevEntry,
    Organization,
    Package,
    ReachabilityPath,
    Repository,
    ReviewDecision,
    Scan,
    User,
    VulnerableSymbol,
)
from sieve.reviews.service import ReviewRequest, record_review
from sieve.runtime import tool_version
from sieve.symbols.registry import curated_provenance
from sieve.vex.documents import Subject, build_openvex
from sieve.vex.service import statement_for

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])


def _alias_group(session: Session, advisory: Advisory) -> list[uuid.UUID]:
    ids = [advisory.source_id, *advisory.aliases]
    return list(
        session.scalars(
            select(Advisory.id).where(
                or_(Advisory.source_id.in_(ids), Advisory.aliases.overlap(ids))
            )
        )
    )


def _symbols(session: Session, finding: Finding, advisory: Advisory) -> list[SymbolOut]:
    rows = session.execute(
        select(VulnerableSymbol, AIExtraction)
        .outerjoin(AIExtraction, AIExtraction.id == VulnerableSymbol.ai_extraction_id)
        .where(
            VulnerableSymbol.advisory_id.in_(_alias_group(session, advisory)),
            VulnerableSymbol.package_id == finding.package_id,
        )
        .order_by(VulnerableSymbol.origin, VulnerableSymbol.qualified_name)
    ).all()
    seen: set[str] = set()
    symbols = []
    for symbol, extraction in rows:
        if symbol.qualified_name in seen:
            continue
        seen.add(symbol.qualified_name)
        symbols.append(
            SymbolOut(
                qualified_name=symbol.qualified_name,
                kind=symbol.kind,
                origin=symbol.origin,
                verification=symbol.verification,
                verification_detail=symbol.verification_detail,
                ai_extraction=AIExtractionOut.model_validate(extraction) if extraction else None,
            )
        )
    return symbols


def _exploitation(session: Session, advisory: Advisory) -> ExploitationOut:
    cves = [i for i in [advisory.source_id, *advisory.aliases] if i.startswith("CVE-")]
    kev = session.scalar(select(KevEntry).where(KevEntry.cve_id.in_(cves))) if cves else None
    epss = (
        session.scalar(
            select(EpssScore)
            .where(EpssScore.cve_id.in_(cves))
            .order_by(EpssScore.percentile.desc())
        )
        if cves
        else None
    )
    return ExploitationOut(
        kev=None
        if kev is None
        else {
            "cve": kev.cve_id,
            "date_added": kev.date_added.isoformat(),
            "due_date": kev.due_date.isoformat() if kev.due_date else None,
            "known_ransomware_use": kev.known_ransomware_use,
            "vendor": kev.vendor,
            "product": kev.product,
        },
        epss=None
        if epss is None
        else {
            "cve": epss.cve_id,
            "score": str(epss.score),
            "percentile": str(epss.percentile),
            "date": epss.score_date.isoformat(),
        },
    )


def _analysis(session: Session, finding: Finding) -> AnalysisOut | None:
    if finding.latest_analysis_id is None:
        return None
    result = session.get(AnalysisResult, finding.latest_analysis_id)
    if result is None:
        return None
    paths = session.scalars(
        select(ReachabilityPath)
        .where(ReachabilityPath.analysis_result_id == result.id)
        .order_by(ReachabilityPath.rank)
    ).all()
    return AnalysisOut(
        id=result.id,
        verdict=result.verdict,
        confidence=result.confidence,
        reasons=result.reasons,
        symbols=result.symbols,
        analyzer_version=result.analyzer_version,
        created_at=result.created_at,
        scan_id=result.scan_id,
        paths=[
            PathOut(rank=p.rank, entrypoint_kind=p.entrypoint_kind, steps=p.steps) for p in paths
        ],
    )


def _reviews(session: Session, finding: Finding) -> list[ReviewOut]:
    rows = session.execute(
        select(ReviewDecision, User.login)
        .join(User, User.id == ReviewDecision.reviewer_id)
        .where(ReviewDecision.finding_id == finding.id)
        .order_by(ReviewDecision.created_at.desc())
    ).all()
    return [
        ReviewOut(
            id=d.id,
            reviewer_login=login,
            previous_verdict=d.previous_verdict,
            decided_verdict=d.decided_verdict,
            vex_status=d.vex_status,
            justification=d.justification,
            comment=d.comment,
            analysis_result_id=d.analysis_result_id,
            created_at=d.created_at,
        )
        for d, login in rows
    ]


def finding_detail(
    session: Session, finding: Finding, organization: Organization, can_review: bool
) -> FindingDetailOut:
    row = session.execute(finding_select().where(Finding.id == finding.id)).one()
    item = finding_item(row)
    advisory: Advisory = row.Advisory
    package = session.get(Package, finding.package_id)
    repository = session.get(Repository, finding.repository_id)
    assert package is not None and repository is not None  # noqa: S101
    scan = session.get(Scan, repository.latest_scan_id) if repository.latest_scan_id else None
    preview = build_openvex(
        Subject(repository.full_name, scan.commit_sha if scan else "0" * 40, "Sieve (preview)"),
        [statement_for(finding, advisory, package)],
        datetime.now(UTC),
        tool_version(),
    )
    return FindingDetailOut(
        **item.model_dump(),
        version=finding.version,
        analysis_state=str(finding.analysis_state),
        decided_verdict=finding.decided_verdict,
        vex_status=finding.vex_status,
        vex_justification=finding.vex_justification,
        advisory=AdvisoryOut(
            id=advisory.source_id,
            aliases=advisory.aliases,
            summary=advisory.summary,
            details=advisory.details,
            severity=advisory.severity,
            cvss_vector=advisory.cvss_vector,
            cvss_score=advisory.cvss_score,
            references=advisory.references,
            published_at=advisory.published_at,
            modified_at=advisory.modified_at,
            url=f"https://osv.dev/vulnerability/{advisory.source_id}",
        ),
        risk_breakdown=finding.risk_breakdown,
        exploitation=_exploitation(session, advisory),
        analysis=_analysis(session, finding),
        symbols=_symbols(session, finding, advisory),
        symbol_provenance=curated_provenance(),
        reviews=_reviews(session, finding),
        timeline=audit_events(
            session, organization.id, target=("finding", str(finding.id)), limit=200
        ),
        vex_preview=preview,
        can_review=can_review,
    )


@router.get("/{finding_id}")
def get_finding(finding_id: uuid.UUID, session: SessionDep, viewer: ViewerDep) -> FindingDetailOut:
    finding, organization, role = finding_for(session, viewer, finding_id)
    can_review = role in WRITERS and organization.account_type is not AccountType.DEMO
    return finding_detail(session, finding, organization, can_review)


@router.post("/{finding_id}/reviews", status_code=201, dependencies=[Depends(csrf_protect)])
def review(
    finding_id: uuid.UUID, body: ReviewIn, request: Request, session: SessionDep, viewer: ViewerDep
) -> FindingDetailOut:
    user = viewer.require_user()
    finding, organization, role = finding_for(session, viewer, finding_id)
    require_role(role, WRITERS)
    enforce(request, "review", limit=60, window_seconds=60, subject=str(user.id))
    record_review(
        session,
        ReviewRequest(
            finding_id=finding.id,
            organization_id=organization.id,
            reviewer_id=user.id,
            expected_version=body.expected_version,
            decided_verdict=body.decided_verdict,
            vex_status=body.vex_status,
            justification=body.justification,
            comment=body.comment,
        ),
    )
    session.commit()
    session.refresh(finding)
    return finding_detail(session, finding, organization, True)
