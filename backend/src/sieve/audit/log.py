"""Recording and verifying audit events.

Each organization has its own hash chain (system-wide events form one more chain). Appends to a
chain are serialised with a transaction-scoped advisory lock so two concurrent writers cannot both
link to the same predecessor.
"""

import hashlib
import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.orm import Session

from sieve.core.correlation import get_correlation_id
from sieve.core.ids import uuid7
from sieve.db.enums import ActorType
from sieve.db.models import AuditEvent

_SYSTEM_CHAIN_LOCK_KEY = 0x5E1E_A0D1  # arbitrary constant for the organization-less chain


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hashed_content(event: AuditEvent) -> dict[str, Any]:
    return {
        "id": str(event.id),
        "organization_id": str(event.organization_id) if event.organization_id else None,
        "actor_type": str(event.actor_type),
        "actor_id": event.actor_id,
        "action": event.action,
        "target_type": event.target_type,
        "target_id": event.target_id,
        "data": event.data,
        "correlation_id": event.correlation_id,
        "occurred_at": event.occurred_at.astimezone(UTC).isoformat(),
    }


def compute_hash(prev_hash: bytes | None, event: AuditEvent) -> bytes:
    digest = hashlib.sha256()
    digest.update(prev_hash or b"")
    digest.update(_canonical_json(_hashed_content(event)).encode())
    return digest.digest()


def _chain_filter(organization_id: uuid.UUID | None) -> ColumnElement[bool]:
    if organization_id is None:
        return AuditEvent.organization_id.is_(None)
    return AuditEvent.organization_id == organization_id


def _chain_lock_key(organization_id: uuid.UUID | None) -> int:
    if organization_id is None:
        return _SYSTEM_CHAIN_LOCK_KEY
    return int.from_bytes(hashlib.sha256(organization_id.bytes).digest()[:8], "big", signed=True)


def record_event(
    session: Session,
    *,
    action: str,
    actor_type: ActorType,
    actor_id: str | None = None,
    organization_id: uuid.UUID | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    data: Mapping[str, Any] | None = None,
) -> AuditEvent:
    """Append an event in the caller's transaction. It commits or rolls back with the change it
    describes, so the log can never claim something happened that did not."""
    session.execute(select(func.pg_advisory_xact_lock(_chain_lock_key(organization_id))))
    prev_hash = session.scalar(
        select(AuditEvent.hash)
        .where(_chain_filter(organization_id))
        .order_by(AuditEvent.seq.desc())
        .limit(1)
    )
    event = AuditEvent(
        id=uuid7(),
        organization_id=organization_id,
        actor_type=actor_type,
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        # Round-trip through JSON so what is stored is exactly what is hashed.
        data=json.loads(_canonical_json(dict(data or {}))),
        correlation_id=get_correlation_id(),
        occurred_at=datetime.now(UTC),
        prev_hash=prev_hash,
    )
    event.hash = compute_hash(prev_hash, event)
    session.add(event)
    session.flush()
    return event


@dataclass(frozen=True)
class ChainVerification:
    valid: bool
    events_checked: int
    first_invalid_seq: int | None = None


def verify_chain(session: Session, organization_id: uuid.UUID | None) -> ChainVerification:
    prev_hash: bytes | None = None
    checked = 0
    events = session.scalars(
        select(AuditEvent)
        .where(_chain_filter(organization_id))
        .order_by(AuditEvent.seq)
        .execution_options(yield_per=500)
    )
    try:
        for event in events:
            checked += 1
            if event.prev_hash != prev_hash or event.hash != compute_hash(prev_hash, event):
                return ChainVerification(
                    valid=False, events_checked=checked, first_invalid_seq=event.seq
                )
            prev_hash = event.hash
    finally:
        # yield_per uses a server-side cursor; release it even when returning early.
        events.close()
    return ChainVerification(valid=True, events_checked=checked)
