"""GitHub login through the GitHub App's user authorization (ADR-0013).

The user access token is used during the callback to learn who the user is and which
installations they can see, then discarded. Memberships mirror GitHub: Sieve never grants access
to an organization that GitHub would not.
"""

from dataclasses import dataclass, field
from urllib.parse import urlencode

import httpx
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from sieve.audit.log import record_event
from sieve.core.config import Settings
from sieve.core.errors import SecurityRejection
from sieve.core.http import raise_for_status
from sieve.db.enums import AccountType, ActorType, Role
from sieve.db.models import Membership, Organization, User

AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"  # noqa: S105 - a URL


@dataclass(frozen=True)
class AccessibleAccount:
    github_account_id: int
    login: str
    account_type: AccountType
    role: Role


@dataclass(frozen=True)
class GitHubIdentity:
    github_user_id: int
    login: str
    name: str | None
    avatar_url: str | None
    accounts: list[AccessibleAccount] = field(default_factory=list)


def callback_url(settings: Settings) -> str:
    return f"{settings.public_api_url}/api/v1/auth/github/callback"


def authorize_url(settings: Settings, state: str) -> str:
    query = urlencode(
        {
            "client_id": settings.github_client_id,
            "redirect_uri": callback_url(settings),
            "state": state,
        }
    )
    return f"{AUTHORIZE_URL}?{query}"


def exchange_code(http: httpx.Client, settings: Settings, code: str) -> str:
    assert settings.github_client_secret is not None  # noqa: S101 - checked by the router
    response = http.post(
        TOKEN_URL,
        headers={"Accept": "application/json"},
        data={
            "client_id": settings.github_client_id,
            "client_secret": settings.github_client_secret.get_secret_value(),
            "code": code,
            "redirect_uri": callback_url(settings),
        },
    )
    raise_for_status(response)
    token = response.json().get("access_token")
    if not isinstance(token, str):
        raise SecurityRejection("GitHub did not issue an access token for this code")
    return token


def _get(http: httpx.Client, settings: Settings, token: str, path: str, **params: str) -> object:
    response = http.get(
        f"{settings.github_api_url}{path}",
        params=params or None,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
    )
    raise_for_status(response)
    return response.json()


def fetch_identity(http: httpx.Client, settings: Settings, token: str) -> GitHubIdentity:
    user = _get(http, settings, token, "/user")
    assert isinstance(user, dict)  # noqa: S101
    accounts: list[AccessibleAccount] = []
    page = 1
    while True:
        result = _get(http, settings, token, "/user/installations", per_page="100", page=str(page))
        assert isinstance(result, dict)  # noqa: S101
        installations = result.get("installations", [])
        for installation in installations:
            account = installation["account"]
            if account["type"] == "User":
                role = Role.OWNER if account["id"] == user["id"] else Role.VIEWER
                kind = AccountType.USER
            else:
                membership = _get(
                    http, settings, token, f"/user/memberships/orgs/{account['login']}"
                )
                assert isinstance(membership, dict)  # noqa: S101
                role = Role.ADMIN if membership.get("role") == "admin" else Role.MEMBER
                kind = AccountType.ORGANIZATION
            accounts.append(AccessibleAccount(account["id"], account["login"], kind, role))
        if len(installations) < 100:
            break
        page += 1
    return GitHubIdentity(
        user["id"], user["login"], user.get("name"), user.get("avatar_url"), accounts
    )


def complete_login(session: Session, identity: GitHubIdentity) -> User:
    user = session.scalar(select(User).where(User.github_user_id == identity.github_user_id))
    if user is None:
        user = User(github_user_id=identity.github_user_id, login=identity.login)
        session.add(user)
    user.login = identity.login
    user.name = identity.name
    user.avatar_url = identity.avatar_url
    session.flush()

    visible: set[int] = set()
    for account in identity.accounts:
        organization = session.scalar(
            select(Organization).where(Organization.github_account_id == account.github_account_id)
        )
        if organization is None:
            organization = Organization(
                github_account_id=account.github_account_id,
                login=account.login,
                account_type=account.account_type,
            )
            session.add(organization)
            session.flush()
        organization.login = account.login
        membership = session.get(Membership, (organization.id, user.id))
        if membership is None:
            session.add(
                Membership(organization_id=organization.id, user_id=user.id, role=account.role)
            )
        else:
            membership.role = account.role
        visible.add(account.github_account_id)

    # Access GitHub no longer grants is removed (the demo organization has no memberships).
    stale = select(Organization.id).where(
        Organization.github_account_id.is_not(None),
        Organization.github_account_id.not_in(visible or {-1}),
    )
    session.execute(
        delete(Membership).where(
            Membership.user_id == user.id, Membership.organization_id.in_(stale)
        )
    )
    record_event(
        session,
        action="user.login",
        actor_type=ActorType.USER,
        actor_id=str(user.id),
        target_type="user",
        target_id=str(user.id),
        data={"login": user.login, "organizations": len(visible)},
    )
    return user
