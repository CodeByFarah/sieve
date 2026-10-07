"""Who is asking, and what may they see or change.

Every resource lookup goes through this module and is scoped by the organizations the viewer
belongs to. A resource outside them is reported as not found (404), never forbidden, so ids
cannot be probed for existence. The demo organization is readable by everyone and writable by
no one.
"""

import uuid
from dataclasses import dataclass, field
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from sieve.api.deps import SessionDep
from sieve.auth.sessions import (
    CSRF_COOKIE,
    CSRF_HEADER,
    SESSION_COOKIE,
    resolve_session,
    tokens_match,
)
from sieve.core.errors import (
    AuthenticationRequired,
    NotFoundError,
    PermissionDenied,
    SecurityRejection,
)
from sieve.db.enums import AccountType, Role
from sieve.db.models import Finding, Membership, Organization, Repository, User

WRITERS = frozenset({Role.OWNER, Role.ADMIN, Role.MEMBER})
ADMINS = frozenset({Role.OWNER, Role.ADMIN})
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass(frozen=True)
class Viewer:
    user: User | None
    roles: dict[uuid.UUID, Role] = field(default_factory=dict)

    def role_in(self, organization: Organization) -> Role | None:
        if organization.id in self.roles:
            return self.roles[organization.id]
        if organization.account_type is AccountType.DEMO:
            return Role.VIEWER
        return None

    def require_user(self) -> User:
        if self.user is None:
            raise AuthenticationRequired("no valid session")
        return self.user


def get_viewer(request: Request, session: SessionDep) -> Viewer:
    user = resolve_session(session, request.cookies.get(SESSION_COOKIE))
    if user is None:
        return Viewer(None)
    rows = session.execute(
        select(Membership.organization_id, Membership.role).where(Membership.user_id == user.id)
    ).all()
    return Viewer(user, dict(rows))


ViewerDep = Annotated[Viewer, Depends(get_viewer)]


class CsrfRejected(SecurityRejection):
    code = "csrf_rejected"
    http_status = 403


def csrf_protect(request: Request) -> None:
    """Double-submit token for cookie-authenticated, state-changing requests. Requests without a
    session cookie carry no ambient authority, so there is nothing to forge."""
    if request.method in SAFE_METHODS or SESSION_COOKIE not in request.cookies:
        return
    if not tokens_match(request.cookies.get(CSRF_COOKIE), request.headers.get(CSRF_HEADER)):
        raise CsrfRejected("missing or mismatched CSRF token")


def require_role(role: Role, allowed: frozenset[Role]) -> None:
    if role not in allowed:
        raise PermissionDenied(f"role {role} not in {sorted(allowed)}")


def organization_for(session: Session, viewer: Viewer, login: str) -> tuple[Organization, Role]:
    for organization in session.scalars(select(Organization).where(Organization.login == login)):
        role = viewer.role_in(organization)
        if role is not None:
            return organization, role
    raise NotFoundError(f"organization {login!r} not visible")


def repository_for(
    session: Session, viewer: Viewer, repository_id: uuid.UUID
) -> tuple[Repository, Organization, Role]:
    row = session.execute(
        select(Repository, Organization)
        .join(Organization, Organization.id == Repository.organization_id)
        .where(Repository.id == repository_id)
    ).one_or_none()
    if row is not None:
        role = viewer.role_in(row.Organization)
        if role is not None:
            return row.Repository, row.Organization, role
    raise NotFoundError(f"repository {repository_id} not visible")


def finding_for(
    session: Session, viewer: Viewer, finding_id: uuid.UUID
) -> tuple[Finding, Organization, Role]:
    row = session.execute(
        select(Finding, Organization)
        .join(Organization, Organization.id == Finding.organization_id)
        .where(Finding.id == finding_id)
    ).one_or_none()
    if row is not None:
        role = viewer.role_in(row.Organization)
        if role is not None:
            return row.Finding, row.Organization, role
    raise NotFoundError(f"finding {finding_id} not visible")


def visible_organization_ids(session: Session, viewer: Viewer) -> list[uuid.UUID]:
    demo = session.scalars(
        select(Organization.id).where(Organization.account_type == AccountType.DEMO)
    ).all()
    return sorted({*viewer.roles, *demo})
