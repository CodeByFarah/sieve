"""API authorisation and abuse resistance (threat model §3.1-3.3, §3.9)."""

import hashlib
import hmac
import json
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import func, select
from sqlalchemy.engine import URL
from sqlalchemy.orm import Session, sessionmaker

from sieve.api.app import create_app
from sieve.api.deps import get_session
from sieve.auth.sessions import CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE, create_session
from sieve.core.config import Settings
from sieve.db.enums import (
    AccountType,
    AnalysisState,
    Confidence,
    RepositorySource,
    Role,
    ScanStatus,
    ScanTrigger,
    Severity,
    Verdict,
)
from sieve.db.models import (
    Advisory,
    Finding,
    GitHubInstallation,
    Membership,
    Organization,
    Package,
    Repository,
    Scan,
    User,
    UserSession,
)

WEBHOOK_SECRET = "test-webhook-secret"


@dataclass
class World:
    alice: User
    bob: User
    victor: User  # viewer in Alice's organization
    acme: Organization
    globex: Organization
    demo: Organization
    acme_repo: Repository
    globex_repo: Repository
    acme_finding: Finding
    globex_finding: Finding
    demo_finding: Finding


def _org(session: Session, login: str, kind: AccountType, account_id: int | None) -> Organization:
    organization = Organization(login=login, account_type=kind, github_account_id=account_id)
    session.add(organization)
    session.flush()
    return organization


def _repo(
    session: Session, organization: Organization, name: str, github_id: int | None
) -> Repository:
    installation_id = None
    if github_id is not None:
        installation = GitHubInstallation(
            organization_id=organization.id,
            github_installation_id=github_id * 10,
            account_login=organization.login,
            repository_selection="all",
        )
        session.add(installation)
        session.flush()
        installation_id = installation.id
    repo = Repository(
        organization_id=organization.id,
        installation_id=installation_id,
        source=RepositorySource.GITHUB if github_id else RepositorySource.DEMO,
        github_repo_id=github_id,
        full_name=name,
        default_branch="main",
    )
    session.add(repo)
    session.flush()
    scan = Scan(
        organization_id=organization.id,
        repository_id=repo.id,
        commit_sha="a" * 40,
        trigger=ScanTrigger.MANUAL,
        status=ScanStatus.SUCCEEDED,
        idempotency_key=f"k:{repo.id}",
        analyzer_version="t",
    )
    session.add(scan)
    session.flush()
    repo.latest_scan_id = scan.id
    return repo


def _finding(session: Session, repo: Repository, advisory_id: str) -> Finding:
    package = session.scalar(select(Package).where(Package.name == "pyyaml"))
    if package is None:
        package = Package(ecosystem="PyPI", name="pyyaml")
        session.add(package)
        session.flush()
    advisory = Advisory(
        source="osv",
        source_id=advisory_id,
        aliases=[],
        summary="<script>alert(1)</script>",
        severity=Severity.HIGH,
        modified_at=datetime.now(UTC),
        content_hash=b"x" * 32,
        raw={},
    )
    session.add(advisory)
    session.flush()
    finding = Finding(
        organization_id=repo.organization_id,
        repository_id=repo.id,
        advisory_id=advisory.id,
        package_id=package.id,
        installed_version="5.3",
        first_seen_scan_id=repo.latest_scan_id,
        last_seen_scan_id=repo.latest_scan_id,
        analysis_state=AnalysisState.ANALYZED,
        verdict=Verdict.REACHABLE,
        confidence=Confidence.HIGH,
        risk_score=30,
    )
    session.add(finding)
    session.flush()
    return finding


@pytest.fixture
def world(session: Session) -> World:
    alice, bob, victor = (
        User(github_user_id=i, login=n) for i, n in ((1, "alice"), (2, "bob"), (3, "victor"))
    )
    session.add_all([alice, bob, victor])
    acme = _org(session, "acme", AccountType.ORGANIZATION, 100)
    globex = _org(session, "globex", AccountType.ORGANIZATION, 200)
    demo = _org(session, "sieve-demo", AccountType.DEMO, None)
    session.flush()
    session.add_all(
        [
            Membership(organization_id=acme.id, user_id=alice.id, role=Role.ADMIN),
            Membership(organization_id=acme.id, user_id=victor.id, role=Role.VIEWER),
            Membership(organization_id=globex.id, user_id=bob.id, role=Role.OWNER),
        ]
    )
    acme_repo = _repo(session, acme, "acme/api", 11)
    globex_repo = _repo(session, globex, "globex/web", 22)
    demo_repo = _repo(session, demo, "sieve-demo/acme-config", None)
    world = World(
        alice,
        bob,
        victor,
        acme,
        globex,
        demo,
        acme_repo,
        globex_repo,
        _finding(session, acme_repo, "GHSA-aaaa"),
        _finding(session, globex_repo, "GHSA-bbbb"),
        _finding(session, demo_repo, "GHSA-cccc"),
    )
    session.commit()
    return world


@pytest.fixture
def app_client(
    session_factory: sessionmaker[Session], database_url: URL, tmp_path: Path
) -> Iterator[TestClient]:
    settings = Settings(
        environment="test",
        database_url=SecretStr(database_url.render_as_string(hide_password=False)),
        log_json=False,
        artifact_root=tmp_path / "artifacts",
        github_webhook_secret=SecretStr(WEBHOOK_SECRET),
        demo_snapshot_dir=Path(__file__).parents[3] / "demo" / "advisory-snapshot",
        demo_app_dir=Path(__file__).parents[3] / "demo" / "vulnerable-python-app",
    )
    app = create_app(settings)
    app.state.session_factory = session_factory

    def session_override() -> Iterator[Session]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = session_override
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


def login(client: TestClient, session: Session, user: User) -> None:
    token = create_session(session, user.id, timedelta(hours=1))
    session.commit()
    client.cookies.set(SESSION_COOKIE, token)
    client.cookies.set(CSRF_COOKIE, "csrf-token-value")


CSRF = {CSRF_HEADER: "csrf-token-value"}


def review_body(finding: Finding, **overrides: object) -> dict[str, object]:
    return {
        "expected_version": finding.version,
        "decided_verdict": "reachable",
        "vex_status": "affected",
        **overrides,
    }


# ------------------------------------------------------------------ identity and tenancy


def test_anonymous_sees_only_the_demo(app_client: TestClient, world: World) -> None:
    me = app_client.get("/api/v1/me").json()
    assert me["user"] is None
    assert [o["login"] for o in me["organizations"]] == ["sieve-demo"]
    assert app_client.get("/api/v1/orgs/acme/overview").status_code == 404
    assert app_client.get(f"/api/v1/findings/{world.demo_finding.id}").status_code == 200


def test_members_see_their_organizations(
    app_client: TestClient, session: Session, world: World
) -> None:
    login(app_client, session, world.alice)
    me = app_client.get("/api/v1/me").json()
    assert sorted(o["login"] for o in me["organizations"]) == ["acme", "sieve-demo"]
    assert app_client.get("/api/v1/orgs/acme/overview").status_code == 200


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/orgs/globex/overview",
        "/api/v1/orgs/globex/findings",
        "/api/v1/orgs/globex/activity",
        "/api/v1/findings/{globex_finding}",
        "/api/v1/repositories/{globex_repo}",
        "/api/v1/repositories/{globex_repo}/vex/preview",
        "/api/v1/findings/{random}",
    ],
)
def test_other_tenants_resources_are_indistinguishable_from_missing_ones(
    app_client: TestClient, session: Session, world: World, path: str
) -> None:
    login(app_client, session, world.alice)
    url = path.format(
        globex_finding=world.globex_finding.id,
        globex_repo=world.globex_repo.id,
        random=uuid.uuid4(),
    )
    response = app_client.get(url)
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_cannot_review_another_tenants_finding(
    app_client: TestClient, session: Session, world: World
) -> None:
    login(app_client, session, world.alice)
    response = app_client.post(
        f"/api/v1/findings/{world.globex_finding.id}/reviews",
        json=review_body(world.globex_finding),
        headers=CSRF,
    )
    assert response.status_code == 404


# ------------------------------------------------------------------ roles, CSRF, concurrency


def test_viewer_role_cannot_review(app_client: TestClient, session: Session, world: World) -> None:
    login(app_client, session, world.victor)
    response = app_client.post(
        f"/api/v1/findings/{world.acme_finding.id}/reviews",
        json=review_body(world.acme_finding),
        headers=CSRF,
    )
    assert response.status_code == 403


def test_demo_is_read_only_even_for_signed_in_users(
    app_client: TestClient, session: Session, world: World
) -> None:
    assert (
        app_client.post(
            f"/api/v1/findings/{world.demo_finding.id}/reviews",
            json=review_body(world.demo_finding),
        ).status_code
        == 401
    )
    login(app_client, session, world.alice)
    detail = app_client.get(f"/api/v1/findings/{world.demo_finding.id}").json()
    assert detail["can_review"] is False
    response = app_client.post(
        f"/api/v1/findings/{world.demo_finding.id}/reviews",
        json=review_body(world.demo_finding),
        headers=CSRF,
    )
    assert response.status_code == 403


def test_state_changes_require_the_csrf_token(
    app_client: TestClient, session: Session, world: World
) -> None:
    login(app_client, session, world.alice)
    url = f"/api/v1/findings/{world.acme_finding.id}/reviews"
    assert (
        app_client.post(url, json=review_body(world.acme_finding)).json()["error"]["code"]
        == "csrf_rejected"
    )
    assert (
        app_client.post(
            url, json=review_body(world.acme_finding), headers={CSRF_HEADER: "wrong"}
        ).status_code
        == 403
    )
    created = app_client.post(url, json=review_body(world.acme_finding), headers=CSRF)
    assert created.status_code == 201
    assert created.json()["review_state"] == "accepted"


def test_stale_review_is_rejected(app_client: TestClient, session: Session, world: World) -> None:
    login(app_client, session, world.alice)
    url = f"/api/v1/findings/{world.acme_finding.id}/reviews"
    stale = review_body(world.acme_finding)
    assert app_client.post(url, json=stale, headers=CSRF).status_code == 201
    assert app_client.post(url, json=stale, headers=CSRF).status_code == 409


def test_review_payload_is_validated(
    app_client: TestClient, session: Session, world: World
) -> None:
    login(app_client, session, world.alice)
    url = f"/api/v1/findings/{world.acme_finding.id}/reviews"
    unknown_field = app_client.post(
        url,
        json={**review_body(world.acme_finding), "reviewer_id": str(world.bob.id)},
        headers=CSRF,
    )
    assert unknown_field.status_code == 422  # no mass assignment of the reviewer
    inconsistent = app_client.post(
        url, json=review_body(world.acme_finding, vex_status="not_affected"), headers=CSRF
    )
    assert inconsistent.json()["error"]["code"] == "invalid_review"


def test_policy_changes_need_an_admin_and_are_versioned(
    app_client: TestClient, session: Session, world: World
) -> None:
    rules = {"rules": [{"action": "block", "when": {"verdict": ["reachable"]}}]}
    login(app_client, session, world.victor)
    assert (
        app_client.put("/api/v1/orgs/acme/policy", json={"rules": rules}, headers=CSRF).status_code
        == 403
    )
    login(app_client, session, world.alice)
    assert app_client.get("/api/v1/orgs/acme/policy").json()["version"] == 1
    updated = app_client.put("/api/v1/orgs/acme/policy", json={"rules": rules}, headers=CSRF)
    assert updated.status_code == 200
    assert updated.json()["version"] == 2
    invalid = app_client.put(
        "/api/v1/orgs/acme/policy",
        json={"rules": {"rules": [{"action": "explode", "when": {}}]}},
        headers=CSRF,
    )
    assert invalid.json()["error"]["code"] == "invalid_policy"


# ------------------------------------------------------------------ injection


@pytest.mark.parametrize(
    "probe", ["' OR 1=1 --", "%' UNION SELECT token_hash FROM sessions --", "\\x00", "😀" * 30]
)
def test_search_inputs_are_data_not_sql(
    app_client: TestClient, session: Session, world: World, probe: str
) -> None:
    login(app_client, session, world.alice)
    response = app_client.get("/api/v1/orgs/acme/findings", params={"q": probe})
    assert response.status_code in (200, 422)
    if response.status_code == 200:
        assert response.json()["total"] == 0


def test_stored_markup_is_returned_as_inert_text(
    app_client: TestClient, session: Session, world: World
) -> None:
    login(app_client, session, world.alice)
    response = app_client.get(f"/api/v1/findings/{world.acme_finding.id}")
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["summary"] == "<script>alert(1)</script>"


# ------------------------------------------------------------------ webhooks


def _signed(body: bytes, secret: str = WEBHOOK_SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _push(world: World, after: str = "b" * 40) -> bytes:
    return json.dumps(
        {
            "ref": "refs/heads/main",
            "after": after,
            "repository": {"id": 11},
            "installation": {"id": 110},
        }
    ).encode()


def _post_webhook(
    client: TestClient, body: bytes, signature: str | None, delivery: str = "d-1"
) -> object:
    headers = {
        "X-GitHub-Event": "push",
        "X-GitHub-Delivery": delivery,
        "Content-Type": "application/json",
    }
    if signature is not None:
        headers["X-Hub-Signature-256"] = signature
    return client.post("/webhooks/github", content=body, headers=headers)


def test_forged_webhooks_are_rejected(
    app_client: TestClient, world: World, session: Session
) -> None:
    body = _push(world)
    assert _post_webhook(app_client, body, None).status_code == 401  # type: ignore[attr-defined]
    assert _post_webhook(app_client, body, _signed(body, "wrong-secret")).status_code == 401  # type: ignore[attr-defined]
    tampered = body.replace(b"refs/heads/main", b"refs/heads/evil")
    assert _post_webhook(app_client, tampered, _signed(body)).status_code == 401  # type: ignore[attr-defined]
    assert (
        session.scalar(
            select(func.count()).select_from(Scan).where(Scan.trigger == ScanTrigger.PUSH)
        )
        == 0
    )


def test_signed_push_queues_one_scan_and_replays_are_ignored(
    app_client: TestClient, world: World, session: Session
) -> None:
    body = _push(world)
    first = _post_webhook(app_client, body, _signed(body), delivery="delivery-1")
    replay = _post_webhook(app_client, body, _signed(body), delivery="delivery-1")
    assert first.status_code == 202  # type: ignore[attr-defined]
    assert replay.json()["status"] == "duplicate delivery ignored"  # type: ignore[attr-defined]
    assert (
        session.scalar(
            select(func.count()).select_from(Scan).where(Scan.trigger == ScanTrigger.PUSH)
        )
        == 1
    )


def test_webhook_for_a_repository_under_another_installation_is_ignored(
    app_client: TestClient, world: World, session: Session
) -> None:
    """A valid signature proves the payload came from GitHub, not that the repository/installation
    pairing in it is one Sieve trusts."""
    body = json.dumps(
        {
            "ref": "refs/heads/main",
            "after": "c" * 40,
            "repository": {"id": 11},
            "installation": {"id": 220},
        }
    ).encode()
    response = _post_webhook(app_client, body, _signed(body), delivery="cross")
    assert response.json()["status"] == "ignored push"  # type: ignore[attr-defined]


def test_oversized_webhook_is_refused(app_client: TestClient) -> None:
    body = b"{" + b" " * (6 * 1024 * 1024) + b"}"
    assert _post_webhook(app_client, body, _signed(body)).status_code == 413  # type: ignore[attr-defined]


# ------------------------------------------------------------------ demo abuse


def test_demo_scans_are_coalesced_and_rate_limited(app_client: TestClient, world: World) -> None:
    first = app_client.post("/api/v1/demo/scans").json()
    second = app_client.post("/api/v1/demo/scans").json()
    assert second["scan"]["id"] == first["scan"]["id"]
    assert second["created"] is False
    statuses = [app_client.post("/api/v1/demo/scans").status_code for _ in range(6)]
    assert statuses[-1] == 429


# ------------------------------------------------------------------ streaming and exports


def test_scan_events_stream_ends_for_finished_scans(app_client: TestClient, world: World) -> None:
    scan_id = world.demo_finding.first_seen_scan_id
    with app_client.stream("GET", f"/api/v1/scans/{scan_id}/events") as response:
        body = "".join(response.iter_text())
    assert "event: scan" in body
    assert "event: done" in body


def test_vex_documents_are_generated_validated_and_tenant_scoped(
    app_client: TestClient, session: Session, world: World
) -> None:
    login(app_client, session, world.alice)
    created = app_client.post(
        f"/api/v1/repositories/{world.acme_repo.id}/vex", json={"format": "openvex"}, headers=CSRF
    )
    assert created.status_code == 201
    document_id = created.json()["id"]
    download = app_client.get(f"/api/v1/vex/{document_id}/download")
    assert download.status_code == 200
    assert json.loads(download.content)["statements"][0]["status"] == "under_investigation"
    login(app_client, session, world.bob)
    assert app_client.get(f"/api/v1/vex/{document_id}/download").status_code == 404


def test_oauth_callback_with_a_forged_state_is_rejected_before_contacting_github(
    app_client: TestClient,
) -> None:
    settings: Settings = app_client.app.state.settings  # type: ignore[attr-defined]
    app_client.app.state.settings = settings.model_copy(  # type: ignore[attr-defined]
        update={"github_client_id": "client", "github_client_secret": SecretStr("secret")}
    )
    app_client.cookies.set("sieve_oauth_state", "the-state-we-issued", path="/api/v1/auth")
    # The test client has no route to GitHub: reaching the token exchange would be an error, not 400.
    response = app_client.get(
        "/api/v1/auth/github/callback",
        params={"code": "attacker-code", "state": "a-state-the-attacker-chose"},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "session" not in " ".join(response.headers.get_list("set-cookie"))


def test_sessions_are_stored_as_hashes_only(session: Session, world: World) -> None:
    token = create_session(session, world.alice.id, timedelta(hours=1))
    session.flush()
    stored = session.scalars(select(UserSession.token_hash)).all()
    assert hashlib.sha256(token.encode()).digest() in stored
    assert all(token.encode() not in value for value in stored)
