import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, ForeignKey, Identity, Index, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from sieve.core.ids import uuid7
from sieve.db.base import Base, enum_column
from sieve.db.enums import ActorType
from sieve.db.models.identity import SHA256_BYTES


class AuditEvent(Base):
    """Append-only, hash-chained per organization.

    A trigger rejects UPDATE/DELETE/TRUNCATE. ``hash`` covers the previous hash and the canonical
    event content, so a modification made by bypassing the trigger breaks the chain.
    """

    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_events_organization_id_seq", "organization_id", "seq"),
        Index("ix_audit_events_target", "target_type", "target_id"),
    )

    seq: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    id: Mapped[uuid.UUID] = mapped_column(unique=True, default=uuid7)
    organization_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("organizations.id"))
    actor_type: Mapped[ActorType] = enum_column(ActorType, "actor_type")
    actor_id: Mapped[str | None] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    target_type: Mapped[str | None] = mapped_column(String(64))
    target_id: Mapped[str | None] = mapped_column(String(64))
    data: Mapped[dict[str, Any]] = mapped_column(default=dict, server_default="{}")
    correlation_id: Mapped[str | None] = mapped_column(String(64))
    # Set by the application (not the database) because it is part of the hashed content.
    occurred_at: Mapped[datetime]
    prev_hash: Mapped[bytes | None] = mapped_column(LargeBinary(SHA256_BYTES))
    hash: Mapped[bytes] = mapped_column(LargeBinary(SHA256_BYTES))
