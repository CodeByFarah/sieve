"""GitHub login, logout and the current viewer."""

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select

from sieve.api.access import ViewerDep, csrf_protect
from sieve.api.deps import SessionDep
from sieve.api.ratelimit import enforce
from sieve.api.schemas import MeOut, OrganizationOut, UserOut
from sieve.auth.login import authorize_url, complete_login, exchange_code, fetch_identity
from sieve.auth.sessions import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    STATE_COOKIE,
    create_session,
    new_token,
    revoke_session,
    tokens_match,
)
from sieve.core.config import Settings
from sieve.core.errors import SecurityRejection
from sieve.db.enums import AccountType, Role
from sieve.db.models import Organization
from sieve.runtime import IntegrationNotConfigured

router = APIRouter(prefix="/api/v1", tags=["auth"])


def _settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def _login_configured(settings: Settings) -> bool:
    return bool(settings.github_client_id and settings.github_client_secret)


def _secure(settings: Settings) -> bool:
    return settings.environment == "production"


@router.get("/me")
def me(request: Request, session: SessionDep, viewer: ViewerDep) -> MeOut:
    settings = _settings(request)
    organizations = []
    if viewer.roles:
        for organization in session.scalars(
            select(Organization).where(Organization.id.in_(viewer.roles))
        ):
            organizations.append(
                OrganizationOut(
                    id=organization.id,
                    login=organization.login,
                    account_type=str(organization.account_type),
                    role=viewer.roles[organization.id],
                )
            )
    demo = session.scalar(select(Organization).where(Organization.account_type == AccountType.DEMO))
    if demo is not None and demo.id not in viewer.roles:
        organizations.append(
            OrganizationOut(id=demo.id, login=demo.login, account_type="demo", role=Role.VIEWER)
        )
    install_url = (
        f"https://github.com/apps/{settings.github_app_slug}/installations/new"
        if settings.github_app_slug
        else None
    )
    return MeOut(
        user=UserOut.model_validate(viewer.user) if viewer.user else None,
        organizations=organizations,
        github_login_enabled=_login_configured(settings),
        github_install_url=install_url,
    )


@router.get("/auth/github/login")
def login(request: Request) -> RedirectResponse:
    settings = _settings(request)
    if not _login_configured(settings):
        raise IntegrationNotConfigured(
            "GitHub login is not configured",
            public_message="GitHub login is not configured on this deployment.",
        )
    enforce(request, "login", limit=20, window_seconds=600)
    state = new_token()
    response = RedirectResponse(authorize_url(settings, state), status_code=302)
    response.set_cookie(
        STATE_COOKIE,
        state,
        max_age=600,
        httponly=True,
        secure=_secure(settings),
        samesite="lax",
        path="/api/v1/auth",
    )
    return response


@router.get("/auth/github/callback")
def callback(
    request: Request,
    session: SessionDep,
    code: Annotated[str, Query(max_length=200)],
    state: Annotated[str, Query(max_length=200)],
) -> RedirectResponse:
    settings = _settings(request)
    if not _login_configured(settings):
        raise IntegrationNotConfigured("GitHub login is not configured")
    enforce(request, "login", limit=20, window_seconds=600)
    if not tokens_match(request.cookies.get(STATE_COOKIE), state):
        raise SecurityRejection(
            "OAuth state mismatch",
            public_message="Login expired or was tampered with. Please try again.",
        )
    http = request.app.state.http
    token = exchange_code(http, settings, code)
    identity = fetch_identity(http, settings, token)
    user = complete_login(session, identity)
    session_token = create_session(session, user.id, timedelta(hours=settings.session_ttl_hours))
    session.commit()

    response = RedirectResponse(f"{settings.public_web_url}/app", status_code=302)
    max_age = settings.session_ttl_hours * 3600
    response.set_cookie(
        SESSION_COOKIE,
        session_token,
        max_age=max_age,
        httponly=True,
        secure=_secure(settings),
        samesite="lax",
        path="/",
    )
    # Readable by the web app, echoed in X-Sieve-CSRF on state-changing requests.
    response.set_cookie(
        CSRF_COOKIE,
        new_token(),
        max_age=max_age,
        httponly=False,
        secure=_secure(settings),
        samesite="lax",
        path="/",
    )
    response.delete_cookie(STATE_COOKIE, path="/api/v1/auth")
    return response


@router.post("/auth/logout", status_code=204, dependencies=[Depends(csrf_protect)])
def logout(request: Request, session: SessionDep) -> Response:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        revoke_session(session, token)
        session.commit()
    response = Response(status_code=204)
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return response
