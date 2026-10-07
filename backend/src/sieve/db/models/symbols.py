import uuid
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
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from sieve.db.base import Base, CreatedAt, Timestamps, UUIDPrimaryKey, enum_column
from sieve.db.enums import AIExtractionStatus, SymbolKind, SymbolOrigin, SymbolVerification
from sieve.db.models.identity import SHA256_BYTES


class AIExtraction(UUIDPrimaryKey, CreatedAt, Base):
    """Every model call, successful or not. Successful calls double as the extraction cache."""

    __tablename__ = "ai_extractions"
    __table_args__ = (
        # Failures are recorded but must never be served from cache.
        Index(
            "uq_ai_extractions_cache_key",
            "input_sha256",
            "provider",
            "model",
            "prompt_version",
            unique=True,
            postgresql_where=text("status = 'succeeded'"),
        ),
        Index("ix_ai_extractions_advisory_id_package_id", "advisory_id", "package_id"),
    )

    advisory_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("advisories.id"))
    package_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("packages.id"))
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str] = mapped_column(String(128))
    prompt_version: Mapped[str] = mapped_column(String(32))
    input_sha256: Mapped[bytes] = mapped_column(LargeBinary(SHA256_BYTES))
    status: Mapped[AIExtractionStatus] = enum_column(AIExtractionStatus, "status")
    output: Mapped[dict[str, Any] | None]
    input_tokens: Mapped[int | None]
    output_tokens: Mapped[int | None]
    cost_usd: Mapped[Decimal | None] = mapped_column(Numeric(10, 6))
    latency_ms: Mapped[int | None]
    error: Mapped[str | None] = mapped_column(Text)


class VulnerableSymbol(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "vulnerable_symbols"
    __table_args__ = (
        UniqueConstraint("advisory_id", "package_id", "qualified_name"),
        CheckConstraint(
            "(origin = 'ai') = (ai_extraction_id IS NOT NULL)", name="ai_origin_has_extraction"
        ),
    )

    advisory_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("advisories.id"))
    package_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("packages.id"))
    qualified_name: Mapped[str] = mapped_column(String(512))
    kind: Mapped[SymbolKind] = enum_column(SymbolKind, "kind")
    origin: Mapped[SymbolOrigin] = enum_column(SymbolOrigin, "origin")
    ai_extraction_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("ai_extractions.id"))
    verification: Mapped[SymbolVerification] = enum_column(
        SymbolVerification, "verification", default=SymbolVerification.UNVERIFIED
    )
    verification_detail: Mapped[dict[str, Any]] = mapped_column(default=dict, server_default="{}")
