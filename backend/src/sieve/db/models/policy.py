import uuid
from typing import Any

from sqlalchemy import BigInteger, ForeignKey, String, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column

from sieve.db.base import Base, CreatedAt, Timestamps, UUIDPrimaryKey


class Policy(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "policies"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String(100))
    is_active: Mapped[bool] = mapped_column(default=True, server_default=text("true"))
    current_version: Mapped[int]


class PolicyVersion(UUIDPrimaryKey, CreatedAt, Base):
    """Immutable. Changing a policy creates a new version; checks record which one they used."""

    __tablename__ = "policy_versions"
    __table_args__ = (UniqueConstraint("policy_id", "version"),)

    policy_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("policies.id"))
    version: Mapped[int]
    rules: Mapped[dict[str, Any]]
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))


class PullRequestCheck(UUIDPrimaryKey, CreatedAt, Base):
    __tablename__ = "pull_request_checks"
    __table_args__ = (UniqueConstraint("repository_id", "head_sha"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id"))
    pr_number: Mapped[int]
    head_sha: Mapped[str] = mapped_column(String(40))
    base_sha: Mapped[str] = mapped_column(String(40))
    scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id"))
    policy_version_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("policy_versions.id"))
    github_check_run_id: Mapped[int | None] = mapped_column(BigInteger)
    conclusion: Mapped[str | None] = mapped_column(String(32))
    summary: Mapped[dict[str, Any]] = mapped_column(default=dict, server_default="{}")
