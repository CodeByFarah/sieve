import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    LargeBinary,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from sieve.db.base import Base, CreatedAt, UUIDPrimaryKey, enum_column
from sieve.db.enums import IngestionStatus, Severity
from sieve.db.models.identity import SHA256_BYTES


class Advisory(UUIDPrimaryKey, Base):
    """Normalised advisory. Aliases (CVE/GHSA/PYSEC) join KEV and EPSS data, which are CVE-keyed."""

    __tablename__ = "advisories"
    __table_args__ = (
        UniqueConstraint("source", "source_id"),
        CheckConstraint("cvss_score >= 0 AND cvss_score <= 10", name="cvss_score_range"),
        Index("ix_advisories_aliases", "aliases", postgresql_using="gin"),
        Index("ix_advisories_modified_at", "modified_at"),
    )

    source: Mapped[str] = mapped_column(String(32))
    source_id: Mapped[str] = mapped_column(String(128))
    aliases: Mapped[list[str]] = mapped_column(
        ARRAY(String(128)), default=list, server_default="{}"
    )
    summary: Mapped[str | None] = mapped_column(Text)
    details: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[Severity] = enum_column(Severity, "severity")
    cvss_vector: Mapped[str | None] = mapped_column(String(256))
    cvss_score: Mapped[Decimal | None] = mapped_column(Numeric(3, 1))
    references: Mapped[list[dict[str, Any]]] = mapped_column(default=list, server_default="[]")
    published_at: Mapped[datetime | None]
    modified_at: Mapped[datetime]
    withdrawn_at: Mapped[datetime | None]
    content_hash: Mapped[bytes] = mapped_column(LargeBinary(SHA256_BYTES))
    raw: Mapped[dict[str, Any]]
    ingested_at: Mapped[datetime] = mapped_column(server_default=func.now())


class AdvisoryPackage(UUIDPrimaryKey, Base):
    __tablename__ = "advisory_packages"
    __table_args__ = (UniqueConstraint("advisory_id", "package_id"),)

    advisory_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("advisories.id"))
    package_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("packages.id"), index=True)
    ranges: Mapped[list[dict[str, Any]]] = mapped_column(default=list, server_default="[]")
    versions: Mapped[list[str]] = mapped_column(
        ARRAY(String(128)), default=list, server_default="{}"
    )


class KevEntry(Base):
    __tablename__ = "kev_entries"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    date_added: Mapped[date]
    due_date: Mapped[date | None]
    known_ransomware_use: Mapped[bool]
    vendor: Mapped[str] = mapped_column(String(255))
    product: Mapped[str] = mapped_column(String(255))
    ingested_at: Mapped[datetime] = mapped_column(server_default=func.now())


class EpssScore(Base):
    """Latest EPSS score per CVE. History is not kept: nothing consumes it."""

    __tablename__ = "epss_scores"
    __table_args__ = (
        CheckConstraint("score >= 0 AND score <= 1", name="score_range"),
        CheckConstraint("percentile >= 0 AND percentile <= 1", name="percentile_range"),
    )

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    score: Mapped[Decimal] = mapped_column(Numeric(6, 5))
    percentile: Mapped[Decimal] = mapped_column(Numeric(6, 5))
    score_date: Mapped[date]
    ingested_at: Mapped[datetime] = mapped_column(server_default=func.now())


class IngestionRun(UUIDPrimaryKey, Base):
    __tablename__ = "ingestion_runs"
    __table_args__ = (
        Index("ix_ingestion_runs_source_started_at", "source", text("started_at DESC")),
    )

    source: Mapped[str] = mapped_column(String(32))
    status: Mapped[IngestionStatus] = enum_column(IngestionStatus, "status")
    started_at: Mapped[datetime] = mapped_column(server_default=func.now())
    finished_at: Mapped[datetime | None]
    records_seen: Mapped[int] = mapped_column(default=0, server_default="0")
    records_changed: Mapped[int] = mapped_column(default=0, server_default="0")
    records_failed: Mapped[int] = mapped_column(default=0, server_default="0")
    cursor: Mapped[str | None] = mapped_column(String(255))
    error: Mapped[str | None] = mapped_column(Text)


class IngestionFailure(UUIDPrimaryKey, CreatedAt, Base):
    """Per-record dead letter: a record that could not be ingested is kept, never dropped."""

    __tablename__ = "ingestion_failures"

    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("ingestion_runs.id"), index=True)
    source: Mapped[str] = mapped_column(String(32))
    record_id: Mapped[str] = mapped_column(String(255))
    error: Mapped[str] = mapped_column(Text)
    payload_excerpt: Mapped[str | None] = mapped_column(Text)
    resolved_at: Mapped[datetime | None]
