"""Finding lifecycle: creation from matches, resolution, analysis results, risk."""

import uuid
from decimal import Decimal
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from sieve.analysis.reachability import Outcome
from sieve.audit.log import record_event
from sieve.db.enums import ActorType, AnalysisState, Presence, ReviewState, Verdict
from sieve.db.models import (
    Advisory,
    AnalysisResult,
    EpssScore,
    Finding,
    KevEntry,
    ReachabilityPath,
    Scan,
)
from sieve.findings.matching import Match
from sieve.risk.scoring import RiskInputs, score

REVIEWED = (ReviewState.ACCEPTED, ReviewState.OVERRIDDEN)


def effective_verdict(finding: Finding) -> Verdict | None:
    """What the finding currently means: a human decision wins over analysis."""
    if finding.review_state in REVIEWED and finding.decided_verdict is not None:
        return finding.decided_verdict
    return finding.verdict


def upsert_findings(session: Session, scan: Scan, matches: list[Match]) -> list[uuid.UUID]:
    """Insert new findings, refresh existing ones, reopen resolved ones. Concurrent scans of the
    same repository cannot create duplicates (unique key + ON CONFLICT)."""
    ids: list[uuid.UUID] = []
    for match in matches:
        statement = insert(Finding).values(
            id=uuid.uuid4(),
            organization_id=scan.organization_id,
            repository_id=scan.repository_id,
            advisory_id=match.advisory.id,
            package_id=match.dependency.package_id,
            installed_version=match.dependency.version,
            first_seen_scan_id=scan.id,
            last_seen_scan_id=scan.id,
            presence=Presence.PRESENT,
            analysis_state=AnalysisState.PENDING,
            review_state=ReviewState.UNREVIEWED,
            version=1,
        )
        upsert = statement.on_conflict_do_update(
            index_elements=[Finding.repository_id, Finding.advisory_id, Finding.package_id],
            set_={
                "installed_version": statement.excluded.installed_version,
                "last_seen_scan_id": scan.id,
                "presence": Presence.PRESENT,
                "updated_at": func.now(),
                "version": Finding.version + 1,
            },
        ).returning(Finding.id, Finding.version)
        row = session.execute(upsert).one()
        if row.version == 1:
            record_event(
                session,
                action="finding.created",
                actor_type=ActorType.SYSTEM,
                organization_id=scan.organization_id,
                target_type="finding",
                target_id=str(row.id),
                data={"advisory": match.advisory.source_id, "scan_id": str(scan.id)},
            )
        ids.append(row.id)
    return ids


def resolve_missing(session: Session, scan: Scan, seen: list[uuid.UUID]) -> int:
    """Findings no longer present in this commit (dependency upgraded or removed)."""
    result = session.execute(
        update(Finding)
        .where(
            Finding.repository_id == scan.repository_id,
            Finding.presence == Presence.PRESENT,
            Finding.id.not_in(seen) if seen else Finding.id.is_not(None),
        )
        .values(presence=Presence.RESOLVED, version=Finding.version + 1, updated_at=func.now())
        .returning(Finding.id)
        .execution_options(synchronize_session=False)
    ).all()
    for (finding_id,) in result:
        record_event(
            session,
            action="finding.resolved",
            actor_type=ActorType.SYSTEM,
            organization_id=scan.organization_id,
            target_type="finding",
            target_id=str(finding_id),
            data={"scan_id": str(scan.id)},
        )
    return len(result)


def apply_outcome(
    session: Session,
    finding: Finding,
    scan: Scan,
    outcome: Outcome,
    *,
    analyzer_version: str,
    stats: dict[str, Any],
) -> AnalysisResult:
    result = AnalysisResult(
        finding_id=finding.id,
        scan_id=scan.id,
        analyzer_version=analyzer_version,
        verdict=outcome.verdict,
        confidence=outcome.confidence,
        reasons=outcome.reasons,
        symbols=outcome.symbols,
        stats=stats,
    )
    session.add(result)
    session.flush()
    for rank, path in enumerate(outcome.paths):
        session.add(
            ReachabilityPath(
                analysis_result_id=result.id,
                rank=rank,
                entrypoint_kind=str(path["entrypoint_kind"]),
                steps=path["steps"],
            )
        )

    previous = finding.verdict
    finding.verdict = outcome.verdict
    finding.confidence = outcome.confidence
    finding.analysis_state = AnalysisState.ANALYZED
    finding.latest_analysis_id = result.id
    if previous != outcome.verdict:
        if finding.review_state in REVIEWED:
            finding.review_state = ReviewState.STALE
        record_event(
            session,
            action="finding.verdict_changed",
            actor_type=ActorType.SYSTEM,
            organization_id=finding.organization_id,
            target_type="finding",
            target_id=str(finding.id),
            data={
                "from": str(previous) if previous else None,
                "to": str(outcome.verdict),
                "analysis_result_id": str(result.id),
            },
        )
    return result


def exploitation_signals(session: Session, advisory: Advisory) -> tuple[bool, Decimal | None]:
    cves = [i for i in [advisory.source_id, *advisory.aliases] if i.startswith("CVE-")]
    if not cves:
        return False, None
    in_kev = (
        session.scalar(select(func.count()).select_from(KevEntry).where(KevEntry.cve_id.in_(cves)))
        or 0
    )
    percentile = session.scalar(
        select(func.max(EpssScore.percentile)).where(EpssScore.cve_id.in_(cves))
    )
    return in_kev > 0, percentile


def rescore(session: Session, finding: Finding, advisory: Advisory) -> None:
    in_kev, percentile = exploitation_signals(session, advisory)
    risk = score(RiskInputs(advisory.severity, effective_verdict(finding), in_kev, percentile))
    finding.risk_score = risk.value
    finding.risk_breakdown = risk.breakdown
