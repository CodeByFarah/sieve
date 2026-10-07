import pytest
from sqlalchemy import Connection, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from sieve.audit.log import record_event, verify_chain
from sieve.core.correlation import correlation_scope
from sieve.db.enums import AccountType, ActorType
from sieve.db.models import AuditEvent, Organization


@pytest.fixture
def org(session: Session) -> Organization:
    organization = Organization(login="acme", account_type=AccountType.ORGANIZATION)
    session.add(organization)
    session.flush()
    return organization


def record(session: Session, org: Organization, action: str, **data: object) -> AuditEvent:
    return record_event(
        session,
        action=action,
        actor_type=ActorType.SYSTEM,
        organization_id=org.id,
        target_type="scan",
        target_id="s-1",
        data=data,
    )


def test_events_form_a_verifiable_chain(session: Session, org: Organization) -> None:
    with correlation_scope("corr-00000001"):
        first = record(session, org, "scan.started")
        second = record(session, org, "scan.completed", findings=3)

    assert first.prev_hash is None
    assert second.prev_hash == first.hash
    assert second.correlation_id == "corr-00000001"
    assert verify_chain(session, org.id).valid
    assert verify_chain(session, org.id).events_checked == 2


def test_chains_are_per_organization(session: Session, org: Organization) -> None:
    other = Organization(login="other", account_type=AccountType.ORGANIZATION)
    session.add(other)
    session.flush()
    record(session, org, "a")
    other_event = record(session, other, "b")

    assert other_event.prev_hash is None
    assert verify_chain(session, org.id).events_checked == 1


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_events SET action = 'rewritten'",
        "DELETE FROM audit_events",
        "TRUNCATE audit_events CASCADE",
    ],
)
def test_database_rejects_rewriting_history(
    session: Session, org: Organization, statement: str
) -> None:
    record(session, org, "scan.started")
    session.commit()  # releases to the outer test transaction via savepoint

    with pytest.raises(DBAPIError, match="append-only"), session.begin_nested():
        session.execute(text(statement))


def test_tampering_that_bypasses_the_trigger_is_detected(
    session: Session, connection: Connection, org: Organization
) -> None:
    record(session, org, "review.decided", verdict="reachable")
    record(session, org, "vex.generated")
    session.flush()

    # Simulates a privileged attacker: disable the trigger and rewrite a decision.
    session.execute(text("ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only"))
    session.execute(
        text(
            'UPDATE audit_events SET data = \'{"verdict": "not_reached"}\' '
            "WHERE action = 'review.decided'"
        )
    )
    session.execute(text("ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only"))
    session.expire_all()

    result = verify_chain(session, org.id)
    assert result.valid is False
    assert result.first_invalid_seq is not None
