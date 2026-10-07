"""Correlation ids tie together everything caused by one request or one job.

Jobs store the correlation id of whatever enqueued them, so a webhook, the scan it triggers and
the check run that scan publishes all share one id in logs and traces.
"""

import re
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from sieve.core.ids import uuid7

_correlation_id: ContextVar[str | None] = ContextVar("correlation_id", default=None)

# Inbound ids come from clients; accept only short, boring values so they are safe to log
# and echo back in headers.
_SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")


def new_correlation_id() -> str:
    return str(uuid7())


def accept_inbound(value: str | None) -> str:
    """Return the client-supplied id if it is safe, otherwise a fresh one."""
    if value and _SAFE_ID.fullmatch(value):
        return value
    return new_correlation_id()


def get_correlation_id() -> str | None:
    return _correlation_id.get()


@contextmanager
def correlation_scope(correlation_id: str) -> Iterator[str]:
    token = _correlation_id.set(correlation_id)
    try:
        yield correlation_id
    finally:
        _correlation_id.reset(token)
