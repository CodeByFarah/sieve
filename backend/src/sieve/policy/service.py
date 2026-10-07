"""Policies are versioned: an update writes a new immutable version; checks record which version
they were evaluated against."""

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from sieve.audit.log import record_event
from sieve.db.enums import ActorType
from sieve.db.models import Policy, PolicyVersion
from sieve.policy.engine import DEFAULT_POLICY, PolicyDocument, parse_policy

DEFAULT_NAME = "default"


def ensure_default_policy(
    session: Session, organization_id: uuid.UUID
) -> tuple[Policy, PolicyVersion]:
    policy = session.scalar(
        select(Policy).where(Policy.organization_id == organization_id, Policy.name == DEFAULT_NAME)
    )
    if policy is not None:
        version = session.scalar(
            select(PolicyVersion).where(
                PolicyVersion.policy_id == policy.id,
                PolicyVersion.version == policy.current_version,
            )
        )
        assert version is not None  # noqa: S101
        return policy, version
    policy = Policy(organization_id=organization_id, name=DEFAULT_NAME, current_version=1)
    session.add(policy)
    session.flush()
    version = PolicyVersion(policy_id=policy.id, version=1, rules=DEFAULT_POLICY)
    session.add(version)
    session.flush()
    return policy, version


def active_policy(
    session: Session, organization_id: uuid.UUID
) -> tuple[PolicyVersion, PolicyDocument]:
    _, version = ensure_default_policy(session, organization_id)
    return version, parse_policy(version.rules)


def update_policy(
    session: Session, organization_id: uuid.UUID, rules: Any, user_id: uuid.UUID
) -> PolicyVersion:
    document = parse_policy(rules)
    policy, current = ensure_default_policy(session, organization_id)
    version = PolicyVersion(
        policy_id=policy.id,
        version=current.version + 1,
        rules=document.model_dump(mode="json", exclude_none=True),
        created_by=user_id,
    )
    session.add(version)
    policy.current_version = version.version
    session.flush()
    record_event(
        session,
        action="policy.changed",
        actor_type=ActorType.USER,
        actor_id=str(user_id),
        organization_id=organization_id,
        target_type="policy",
        target_id=str(policy.id),
        data={"from_version": current.version, "to_version": version.version},
    )
    return version
