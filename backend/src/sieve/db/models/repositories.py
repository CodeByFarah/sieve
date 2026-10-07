import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKey,
    Index,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from sieve.db.base import Base, CreatedAt, Timestamps, UUIDPrimaryKey, enum_column
from sieve.db.enums import ManifestStatus, RepositorySource, ScanStatus, ScanTrigger
from sieve.db.models.identity import SHA256_BYTES


class Repository(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "repositories"
    __table_args__ = (
        UniqueConstraint("organization_id", "full_name"),
        # Demo repositories have no installation; GitHub repositories always have one.
        CheckConstraint(
            "(source = 'demo') = (installation_id IS NULL)", name="source_matches_installation"
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    installation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("github_installations.id"), index=True
    )
    source: Mapped[RepositorySource] = enum_column(RepositorySource, "source")
    github_repo_id: Mapped[int | None] = mapped_column(BigInteger, unique=True)
    full_name: Mapped[str] = mapped_column(String(200))
    default_branch: Mapped[str] = mapped_column(String(255))
    is_private: Mapped[bool] = mapped_column(default=False, server_default=text("false"))
    is_active: Mapped[bool] = mapped_column(default=True, server_default=text("true"))
    latest_scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id", use_alter=True))


class Scan(UUIDPrimaryKey, CreatedAt, Base):
    """One analysis of one commit. Stages and progress are persisted so the UI reads real state."""

    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint("commit_sha ~ '^[0-9a-f]{40}$'", name="commit_sha_hex"),
        Index("ix_scans_repository_id_created_at", "repository_id", text("created_at DESC")),
        Index(
            "ix_scans_active",
            "status",
            postgresql_where=text("status IN ('queued', 'running')"),
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id"))
    commit_sha: Mapped[str] = mapped_column(String(40))
    ref: Mapped[str | None] = mapped_column(String(255))
    trigger: Mapped[ScanTrigger] = enum_column(ScanTrigger, "trigger")
    status: Mapped[ScanStatus] = enum_column(ScanStatus, "status", default=ScanStatus.QUEUED)
    stage: Mapped[str | None] = mapped_column(String(32))
    progress: Mapped[dict[str, Any]] = mapped_column(default=dict, server_default="{}")
    idempotency_key: Mapped[str] = mapped_column(String(255), unique=True)
    analyzer_version: Mapped[str] = mapped_column(String(32))
    sbom_key: Mapped[str | None] = mapped_column(String(512))
    sbom_sha256: Mapped[bytes | None] = mapped_column(LargeBinary(SHA256_BYTES))
    stats: Mapped[dict[str, Any]] = mapped_column(default=dict, server_default="{}")
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(Text)
    correlation_id: Mapped[str | None] = mapped_column(String(64))
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]


class ScanManifest(UUIDPrimaryKey, Base):
    """Every manifest the inventory stage saw, including the ones it could not handle."""

    __tablename__ = "scan_manifests"
    __table_args__ = (UniqueConstraint("scan_id", "path"),)

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"))
    path: Mapped[str] = mapped_column(String(1024))
    format: Mapped[str] = mapped_column(String(32))
    status: Mapped[ManifestStatus] = enum_column(ManifestStatus, "status")
    detail: Mapped[str | None] = mapped_column(Text)


class Package(UUIDPrimaryKey, CreatedAt, Base):
    __tablename__ = "packages"
    __table_args__ = (UniqueConstraint("ecosystem", "name"),)

    ecosystem: Mapped[str] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(String(255))  # PEP 503-normalised for PyPI


class Dependency(UUIDPrimaryKey, Base):
    __tablename__ = "dependencies"
    __table_args__ = (
        UniqueConstraint("scan_id", "package_id", "version", postgresql_nulls_not_distinct=True),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"))
    package_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("packages.id"), index=True)
    version: Mapped[str | None] = mapped_column(String(128))  # None: unpinned, never resolved
    constraint_spec: Mapped[str | None] = mapped_column(String(512))
    is_direct: Mapped[bool]
    manifest_path: Mapped[str] = mapped_column(String(1024))
    purl: Mapped[str | None] = mapped_column(String(1024))
