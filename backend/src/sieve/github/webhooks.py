"""GitHub webhook verification and dispatch.

* The HMAC-SHA256 signature is checked over the raw body, in constant time, before the body is
  parsed.
* Each delivery id is recorded first; a redelivered event is acknowledged and ignored.
* Payloads are hints, not truth: installation events only trigger a sync job that re-reads the
  installation from the GitHub API; push and pull-request events are honoured only for
  repositories Sieve already knows under that same installation.
"""

import hashlib
import hmac
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from sieve.core.errors import SecurityRejection
from sieve.db.enums import ActorType, ScanTrigger
from sieve.db.models import GitHubInstallation, PullRequestCheck, Repository, WebhookDelivery
from sieve.scans.service import ANALYZER_VERSION, request_scan
from sieve.worker import queue

MAX_BODY_BYTES = 5 * 1024 * 1024
_NULL_SHA = "0" * 40
PR_ACTIONS = frozenset({"opened", "synchronize", "reopened"})


class InvalidSignature(SecurityRejection):
    code = "invalid_signature"
    http_status = 401


def verify_signature(secret: bytes, body: bytes, header: str | None) -> None:
    if not header or not header.startswith("sha256="):
        raise InvalidSignature("missing or malformed X-Hub-Signature-256")
    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, header.removeprefix("sha256=")):
        raise InvalidSignature("webhook signature mismatch")


def record_delivery(
    session: Session, delivery_id: str, event: str, payload: dict[str, Any]
) -> bool:
    """True if this delivery is new."""
    inserted = session.scalar(
        insert(WebhookDelivery)
        .values(
            github_delivery_id=delivery_id[:64],
            event=event[:64],
            action=str(payload.get("action", ""))[:64] or None,
            github_installation_id=(payload.get("installation") or {}).get("id"),
        )
        .on_conflict_do_nothing()
        .returning(WebhookDelivery.github_delivery_id)
    )
    return inserted is not None


def _known_repository(session: Session, payload: dict[str, Any]) -> Repository | None:
    repo_id = (payload.get("repository") or {}).get("id")
    installation_id = (payload.get("installation") or {}).get("id")
    if not isinstance(repo_id, int) or not isinstance(installation_id, int):
        return None
    return session.scalar(
        select(Repository)
        .join(GitHubInstallation, GitHubInstallation.id == Repository.installation_id)
        .where(
            Repository.github_repo_id == repo_id,
            Repository.is_active.is_(True),
            GitHubInstallation.github_installation_id == installation_id,
            GitHubInstallation.suspended_at.is_(None),
        )
    )


def dispatch(session: Session, event: str, payload: dict[str, Any]) -> str:
    """Returns a short description of what was done (for the response and logs)."""
    if event in ("installation", "installation_repositories"):
        installation_id = (payload.get("installation") or {}).get("id")
        if not isinstance(installation_id, int):
            return "ignored: no installation id"
        queue.enqueue(
            session,
            kind="github.sync_installation",
            idempotency_key=f"github.sync_installation:{installation_id}:{payload.get('action')}:{hashlib.sha256(repr(payload.get('repositories_added')).encode()).hexdigest()[:12]}",
            payload={"installation_id": installation_id, "action": str(payload.get("action", ""))},
            priority=20,
        )
        return "installation sync queued"
    if event == "push":
        return _push(session, payload)
    if event == "pull_request":
        return _pull_request(session, payload)
    return f"ignored event {event}"


def _push(session: Session, payload: dict[str, Any]) -> str:
    repository = _known_repository(session, payload)
    after = str(payload.get("after", ""))
    if repository is None or after == _NULL_SHA or len(after) != 40:
        return "ignored push"
    if payload.get("ref") != f"refs/heads/{repository.default_branch}":
        return "ignored push to non-default branch"
    scan, created = request_scan(
        session,
        repository,
        commit_sha=after,
        trigger=ScanTrigger.PUSH,
        ref=str(payload.get("ref")),
        actor_type=ActorType.GITHUB,
    )
    return f"scan {'queued' if created else 'already exists'}: {scan.id}"


def _pull_request(session: Session, payload: dict[str, Any]) -> str:
    if payload.get("action") not in PR_ACTIONS:
        return "ignored pull_request action"
    repository = _known_repository(session, payload)
    pull = payload.get("pull_request") or {}
    head = str((pull.get("head") or {}).get("sha", ""))
    base = str((pull.get("base") or {}).get("sha", ""))
    number = payload.get("number")
    if repository is None or len(head) != 40 or len(base) != 40 or not isinstance(number, int):
        return "ignored pull_request"
    scan, _ = request_scan(
        session,
        repository,
        commit_sha=head,
        trigger=ScanTrigger.PULL_REQUEST,
        ref=f"refs/pull/{number}/head",
        idempotency_key=f"scan:{repository.id}:{head}:{ANALYZER_VERSION}:pr:{number}",
        actor_type=ActorType.GITHUB,
        priority=30,
    )
    session.execute(
        insert(PullRequestCheck)
        .values(
            organization_id=repository.organization_id,
            repository_id=repository.id,
            pr_number=number,
            head_sha=head,
            base_sha=base,
            scan_id=scan.id,
            summary={},
        )
        .on_conflict_do_nothing(
            index_elements=[PullRequestCheck.repository_id, PullRequestCheck.head_sha]
        )
    )
    return f"pull request scan: {scan.id}"
