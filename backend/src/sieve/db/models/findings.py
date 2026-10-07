import uuid
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    LargeBinary,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from sieve.db.base import Base, CreatedAt, Timestamps, UUIDPrimaryKey, enum_column
from sieve.db.enums import (
    AnalysisState,
    Confidence,
    Presence,
    ReviewState,
    Verdict,
    VexFormat,
    VexJustification,
    VexStatus,
)
from sieve.db.models.identity import SHA256_BYTES


class Finding(UUIDPrimaryKey, Timestamps, Base):
    """One advisory affecting one package in one repository.

    State is split into independent dimensions (ADR-0009). ``version`` provides optimistic
    locking: SQLAlchemy adds ``WHERE version = :old`` to every UPDATE.
    """

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("repository_id", "advisory_id", "package_id"),
        CheckConstraint(
            "analysis_state <> 'analyzed' OR verdict IS NOT NULL", name="analyzed_has_verdict"
        ),
        CheckConstraint("(verdict IS NULL) = (confidence IS NULL)", name="verdict_has_confidence"),
        Index(
            "ix_findings_org_verdict_risk",
            "organization_id",
            "verdict",
            text("risk_score DESC"),
        ),
        Index("ix_findings_repository_id_presence", "repository_id", "presence"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id"))
    advisory_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("advisories.id"))
    package_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("packages.id"))
    installed_version: Mapped[str | None] = mapped_column(String(128))
    first_seen_scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"))
    last_seen_scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"))
    presence: Mapped[Presence] = enum_column(Presence, "presence", default=Presence.PRESENT)
    analysis_state: Mapped[AnalysisState] = enum_column(
        AnalysisState, "analysis_state", default=AnalysisState.PENDING
    )
    verdict: Mapped[Verdict | None] = enum_column(Verdict, "verdict")
    confidence: Mapped[Confidence | None] = enum_column(Confidence, "confidence")
    latest_analysis_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("analysis_results.id", use_alter=True)
    )
    risk_score: Mapped[Decimal | None] = mapped_column(Numeric(5, 2))
    risk_breakdown: Mapped[dict[str, Any]] = mapped_column(default=dict, server_default="{}")
    review_state: Mapped[ReviewState] = enum_column(
        ReviewState, "review_state", default=ReviewState.UNREVIEWED
    )
    # Denormalised from the latest review decision (the append-only history stays in
    # review_decisions) so the effective verdict can be filtered and sorted without a join.
    decided_verdict: Mapped[Verdict | None] = enum_column(Verdict, "decided_verdict")
    vex_status: Mapped[VexStatus | None] = enum_column(VexStatus, "vex_status")
    vex_justification: Mapped[VexJustification | None] = enum_column(
        VexJustification, "vex_justification"
    )
    version: Mapped[int] = mapped_column(server_default="1")

    __mapper_args__ = {"version_id_col": version}  # noqa: RUF012 - SQLAlchemy convention


class AnalysisResult(UUIDPrimaryKey, CreatedAt, Base):
    """Immutable record of one reachability analysis of one finding."""

    __tablename__ = "analysis_results"
    __table_args__ = (
        Index("ix_analysis_results_finding_id_created_at", "finding_id", text("created_at DESC")),
    )

    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id"))
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"))
    analyzer_version: Mapped[str] = mapped_column(String(32))
    verdict: Mapped[Verdict] = enum_column(Verdict, "verdict")
    confidence: Mapped[Confidence] = enum_column(Confidence, "confidence")
    reasons: Mapped[list[dict[str, Any]]] = mapped_column(default=list, server_default="[]")
    symbols: Mapped[list[dict[str, Any]]] = mapped_column(default=list, server_default="[]")
    stats: Mapped[dict[str, Any]] = mapped_column(default=dict, server_default="{}")


class ReachabilityPath(UUIDPrimaryKey, Base):
    __tablename__ = "reachability_paths"
    __table_args__ = (UniqueConstraint("analysis_result_id", "rank"),)

    analysis_result_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("analysis_results.id"))
    rank: Mapped[int] = mapped_column(SmallInteger)
    entrypoint_kind: Mapped[str] = mapped_column(String(32))
    steps: Mapped[list[dict[str, Any]]]


class ReviewDecision(UUIDPrimaryKey, CreatedAt, Base):
    """Append-only (enforced by trigger). Records which evidence version the reviewer saw."""

    __tablename__ = "review_decisions"
    __table_args__ = (
        CheckConstraint(
            "vex_status <> 'not_affected' OR justification IS NOT NULL",
            name="not_affected_requires_justification",
        ),
        Index("ix_review_decisions_finding_id_created_at", "finding_id", "created_at"),
    )

    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id"))
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    reviewer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    analysis_result_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("analysis_results.id"))
    finding_version: Mapped[int]
    previous_verdict: Mapped[Verdict | None] = enum_column(Verdict, "previous_verdict")
    decided_verdict: Mapped[Verdict] = enum_column(Verdict, "decided_verdict")
    vex_status: Mapped[VexStatus] = enum_column(VexStatus, "vex_status")
    justification: Mapped[VexJustification | None] = enum_column(VexJustification, "justification")
    comment: Mapped[str | None] = mapped_column(Text)


class VexDocument(UUIDPrimaryKey, CreatedAt, Base):
    __tablename__ = "vex_documents"

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    repository_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("repositories.id"))
    format: Mapped[VexFormat] = enum_column(VexFormat, "format")
    artifact_key: Mapped[str] = mapped_column(String(512))
    artifact_sha256: Mapped[bytes] = mapped_column(LargeBinary(SHA256_BYTES))
    statement_count: Mapped[int]
    schema_valid: Mapped[bool]
    generated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
