import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, ForeignKey, Index, SmallInteger, String, Text, func, text
from sqlalchemy.orm import Mapped, mapped_column

from sieve.db.base import Base, CreatedAt, UUIDPrimaryKey, enum_column
from sieve.db.enums import JobStatus


class Job(UUIDPrimaryKey, CreatedAt, Base):
    """A unit of asynchronous work. The table is the queue (ADR-0004)."""

    __tablename__ = "jobs"
    __table_args__ = (
        CheckConstraint("attempts >= 0 AND attempts <= max_attempts", name="attempts_bounded"),
        # Claim query: smallest (priority, run_after) among pending jobs.
        Index(
            "ix_jobs_claimable",
            "priority",
            "run_after",
            postgresql_where=text("status = 'pending'"),
        ),
        # Reaper: running jobs whose lease expired.
        Index(
            "ix_jobs_leases",
            "lease_expires_at",
            postgresql_where=text("status = 'running'"),
        ),
        # Dead-letter view.
        Index("ix_jobs_dead", "created_at", postgresql_where=text("status = 'dead'")),
    )

    kind: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(default=dict, server_default="{}")
    status: Mapped[JobStatus] = enum_column(JobStatus, "status", default=JobStatus.PENDING)
    priority: Mapped[int] = mapped_column(SmallInteger, default=100, server_default="100")
    idempotency_key: Mapped[str] = mapped_column(String(255), unique=True)
    attempts: Mapped[int] = mapped_column(default=0, server_default="0")
    max_attempts: Mapped[int] = mapped_column(default=5, server_default="5")
    run_after: Mapped[datetime] = mapped_column(server_default=func.now())
    locked_by: Mapped[str | None] = mapped_column(String(128))
    lease_expires_at: Mapped[datetime | None]
    last_error: Mapped[str | None] = mapped_column(Text)
    correlation_id: Mapped[str | None] = mapped_column(String(64))
    organization_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("organizations.id"))
    finished_at: Mapped[datetime | None]
