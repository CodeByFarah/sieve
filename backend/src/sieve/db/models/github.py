import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column

from sieve.db.base import Base, Timestamps, UUIDPrimaryKey


class GitHubInstallation(UUIDPrimaryKey, Timestamps, Base):
    """A GitHub App installation. No tokens are stored: they are minted per job."""

    __tablename__ = "github_installations"
    __table_args__ = (
        CheckConstraint("repository_selection IN ('all', 'selected')", name="repository_selection"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    github_installation_id: Mapped[int] = mapped_column(BigInteger, unique=True)
    account_login: Mapped[str] = mapped_column(String(100))
    repository_selection: Mapped[str] = mapped_column(String(16))
    permissions: Mapped[dict[str, Any]] = mapped_column(default=dict, server_default="{}")
    suspended_at: Mapped[datetime | None]


class WebhookDelivery(Base):
    """Delivery ids already accepted. Inserting first makes duplicate deliveries no-ops."""

    __tablename__ = "webhook_deliveries"

    github_delivery_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    event: Mapped[str] = mapped_column(String(64))
    action: Mapped[str | None] = mapped_column(String(64))
    github_installation_id: Mapped[int | None] = mapped_column(BigInteger)
    received_at: Mapped[datetime] = mapped_column(server_default=func.now())
