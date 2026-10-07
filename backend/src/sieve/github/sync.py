"""Synchronising an installation's organization and repositories from the GitHub API."""

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from sieve.audit.log import record_event
from sieve.db.enums import AccountType, ActorType, RepositorySource, ScanTrigger
from sieve.db.models import GitHubInstallation, Organization, Repository
from sieve.github.app import GitHubApp
from sieve.policy.service import ensure_default_policy
from sieve.scans.service import request_scan


def _organization(session: Session, account: dict[str, Any]) -> Organization:
    organization = session.scalar(
        select(Organization).where(Organization.github_account_id == account["id"])
    )
    if organization is None:
        organization = Organization(
            github_account_id=account["id"],
            login=account["login"],
            account_type=AccountType.ORGANIZATION
            if account["type"] == "Organization"
            else AccountType.USER,
        )
        session.add(organization)
        session.flush()
        ensure_default_policy(session, organization.id)
    organization.login = account["login"]
    return organization


def sync_installation(session: Session, app: GitHubApp, installation_id: int) -> dict[str, int]:
    data = app.as_app("GET", f"/app/installations/{installation_id}")
    organization = _organization(session, data["account"])
    installation = session.scalar(
        select(GitHubInstallation).where(
            GitHubInstallation.github_installation_id == installation_id
        )
    )
    if installation is None:
        installation = GitHubInstallation(
            organization_id=organization.id,
            github_installation_id=installation_id,
            account_login=data["account"]["login"],
            repository_selection=data["repository_selection"],
        )
        session.add(installation)
        session.flush()
        record_event(
            session,
            action="github.installed",
            actor_type=ActorType.GITHUB,
            organization_id=organization.id,
            target_type="installation",
            target_id=str(installation_id),
            data={"account": data["account"]["login"]},
        )
    installation.repository_selection = data["repository_selection"]
    installation.permissions = data.get("permissions", {})
    installation.suspended_at = (
        None if data.get("suspended_at") is None else installation.suspended_at
    )

    listed = app.installation_repositories(installation_id)
    seen: set[int] = set()
    added = 0
    for item in listed:
        seen.add(item["id"])
        repository = session.scalar(
            select(Repository).where(Repository.github_repo_id == item["id"])
        )
        is_new = repository is None or not repository.is_active
        if repository is None:
            repository = Repository(
                organization_id=organization.id,
                installation_id=installation.id,
                source=RepositorySource.GITHUB,
                github_repo_id=item["id"],
                full_name=item["full_name"],
                default_branch=item["default_branch"],
            )
            session.add(repository)
        repository.full_name = item["full_name"]
        repository.default_branch = item["default_branch"]
        repository.is_private = bool(item.get("private"))
        repository.is_active = True
        repository.installation_id = installation.id
        session.flush()
        if is_new:
            added += 1
            record_event(
                session,
                action="repository.added",
                actor_type=ActorType.GITHUB,
                organization_id=organization.id,
                target_type="repository",
                target_id=str(repository.id),
                data={"full_name": repository.full_name},
            )
            head = app.head_commit(installation_id, repository.full_name, repository.default_branch)
            request_scan(
                session,
                repository,
                commit_sha=head,
                trigger=ScanTrigger.MANUAL,
                ref=f"refs/heads/{repository.default_branch}",
                actor_type=ActorType.GITHUB,
            )

    removed = 0
    for repository in session.scalars(
        select(Repository).where(
            Repository.installation_id == installation.id, Repository.is_active.is_(True)
        )
    ):
        if repository.github_repo_id not in seen:
            repository.is_active = False
            removed += 1
            record_event(
                session,
                action="repository.removed",
                actor_type=ActorType.GITHUB,
                organization_id=organization.id,
                target_type="repository",
                target_id=str(repository.id),
                data={"full_name": repository.full_name},
            )
    return {"repositories": len(listed), "added": added, "removed": removed}
