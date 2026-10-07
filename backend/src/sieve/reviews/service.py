"""Recording a review decision: validated, optimistic-locked, append-only, audited."""

import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

from sieve.audit.log import record_event
from sieve.core.errors import ConflictError, NotFoundError, UserError
from sieve.db.enums import (
    ActorType,
    AnalysisState,
    ReviewState,
    Verdict,
    VexJustification,
    VexStatus,
)
from sieve.db.models import Advisory, Finding, ReviewDecision
from sieve.findings.service import rescore

# Which VEX statuses a verdict may be paired with. "fixed" is allowed with any verdict because
# it describes a remediation, not the analysis.
_ALLOWED_STATUS = {
    Verdict.REACHABLE: {VexStatus.AFFECTED, VexStatus.FIXED, VexStatus.UNDER_INVESTIGATION},
    Verdict.NOT_REACHED: {VexStatus.NOT_AFFECTED, VexStatus.FIXED},
    Verdict.NEEDS_REVIEW: {VexStatus.UNDER_INVESTIGATION, VexStatus.AFFECTED, VexStatus.FIXED},
}


@dataclass(frozen=True)
class ReviewRequest:
    finding_id: uuid.UUID
    organization_id: uuid.UUID
    reviewer_id: uuid.UUID
    expected_version: int
    decided_verdict: Verdict
    vex_status: VexStatus
    justification: VexJustification | None
    comment: str | None


class InvalidReview(UserError):
    code = "invalid_review"


def record_review(session: Session, request: ReviewRequest) -> ReviewDecision:
    finding = session.scalar(
        select(Finding).where(
            Finding.id == request.finding_id, Finding.organization_id == request.organization_id
        )
    )
    if finding is None:
        raise NotFoundError(f"finding {request.finding_id} not visible to organization")
    if finding.version != request.expected_version:
        raise ConflictError(
            f"finding {finding.id} is at version {finding.version}, "
            f"client sent {request.expected_version}"
        )
    if finding.analysis_state is not AnalysisState.ANALYZED or finding.verdict is None:
        raise InvalidReview(
            "finding has not been analysed yet",
            public_message="This finding has not been analysed yet.",
        )
    if request.vex_status not in _ALLOWED_STATUS[request.decided_verdict]:
        raise InvalidReview(
            f"{request.vex_status} is inconsistent with {request.decided_verdict}",
            public_message=(
                f"A '{request.decided_verdict}' decision cannot be "
                f"published as '{request.vex_status}'."
            ),
        )
    if request.vex_status is VexStatus.NOT_AFFECTED and request.justification is None:
        raise InvalidReview(
            "not_affected requires a justification",
            public_message="A 'not affected' decision needs a justification.",
        )
    if request.vex_status is not VexStatus.NOT_AFFECTED and request.justification is not None:
        raise InvalidReview(
            "justification only applies to not_affected",
            public_message="A justification only applies to 'not affected'.",
        )

    decision = ReviewDecision(
        finding_id=finding.id,
        organization_id=finding.organization_id,
        reviewer_id=request.reviewer_id,
        analysis_result_id=finding.latest_analysis_id,
        finding_version=finding.version,
        previous_verdict=finding.verdict,
        decided_verdict=request.decided_verdict,
        vex_status=request.vex_status,
        justification=request.justification,
        comment=(request.comment or None) and request.comment[:4000],
    )
    session.add(decision)
    finding.review_state = (
        ReviewState.ACCEPTED
        if request.decided_verdict == finding.verdict
        else ReviewState.OVERRIDDEN
    )
    finding.decided_verdict = request.decided_verdict
    finding.vex_status = request.vex_status
    finding.vex_justification = request.justification
    advisory = session.get(Advisory, finding.advisory_id)
    assert advisory is not None  # noqa: S101 - foreign key
    rescore(session, finding, advisory)
    try:
        session.flush()  # the ORM adds "WHERE version = :expected": a concurrent edit fails here
    except StaleDataError as exc:
        raise ConflictError(f"finding {finding.id} changed concurrently") from exc
    record_event(
        session,
        action="review.decided",
        actor_type=ActorType.USER,
        actor_id=str(request.reviewer_id),
        organization_id=finding.organization_id,
        target_type="finding",
        target_id=str(finding.id),
        data={
            "decision_id": str(decision.id),
            "previous_verdict": str(decision.previous_verdict),
            "decided_verdict": str(decision.decided_verdict),
            "vex_status": str(decision.vex_status),
            "justification": str(decision.justification) if decision.justification else None,
            "analysis_result_id": str(decision.analysis_result_id)
            if decision.analysis_result_id
            else None,
        },
    )
    return decision
