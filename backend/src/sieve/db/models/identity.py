import uuid
from datetime import datetime

from sqlalchemy import BigInteger, ForeignKey, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from sieve.db.base import Base, CreatedAt, Timestamps, UUIDPrimaryKey, enum_column
from sieve.db.enums import AccountType, Role

SHA256_BYTES = 32


class User(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "users"

    github_user_id: Mapped[int] = mapped_column(BigInteger, unique=True)
    login: Mapped[str] = mapped_column(String(39))  # GitHub's maximum login length
    name: Mapped[str | None] = mapped_column(String(255))
    avatar_url: Mapped[str | None] = mapped_column(String(512))


class Organization(UUIDPrimaryKey, CreatedAt, Base):
    """Tenant boundary. One per GitHub account that installed the App, plus the demo tenant."""

    __tablename__ = "organizations"

    github_account_id: Mapped[int | None] = mapped_column(BigInteger, unique=True)
    login: Mapped[str] = mapped_column(String(100))
    account_type: Mapped[AccountType] = enum_column(AccountType, "account_type")


class Membership(CreatedAt, Base):
    __tablename__ = "memberships"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    role: Mapped[Role] = enum_column(Role, "role")


class UserSession(UUIDPrimaryKey, CreatedAt, Base):
    """Server-side session. The cookie carries a random token; only its SHA-256 is stored."""

    __tablename__ = "sessions"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[bytes] = mapped_column(LargeBinary(SHA256_BYTES), unique=True)
    expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None]
