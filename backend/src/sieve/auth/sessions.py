"""Server-side sessions. The browser holds a random 256-bit token; the database holds only its
SHA-256, so a database leak does not yield usable sessions."""

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from sieve.db.models import User, UserSession

SESSION_COOKIE = "sieve_session"
CSRF_COOKIE = "sieve_csrf"
CSRF_HEADER = "X-Sieve-CSRF"
STATE_COOKIE = "sieve_oauth_state"


def _hash(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def create_session(session: Session, user_id: uuid.UUID, ttl: timedelta) -> str:
    token = new_token()
    session.add(
        UserSession(user_id=user_id, token_hash=_hash(token), expires_at=datetime.now(UTC) + ttl)
    )
    session.flush()
    return token


def resolve_session(session: Session, token: str | None) -> User | None:
    if not token or len(token) > 128:
        return None
    return session.scalar(
        select(User)
        .join(UserSession, UserSession.user_id == User.id)
        .where(
            UserSession.token_hash == _hash(token),
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > datetime.now(UTC),
        )
    )


def revoke_session(session: Session, token: str) -> None:
    session.execute(
        update(UserSession)
        .where(UserSession.token_hash == _hash(token), UserSession.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    )


def tokens_match(a: str | None, b: str | None) -> bool:
    return bool(a) and bool(b) and secrets.compare_digest(str(a), str(b))
