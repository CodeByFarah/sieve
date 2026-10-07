"""GitHub webhook endpoint."""

import json

from fastapi import APIRouter, Request

from sieve.api.deps import SessionDep
from sieve.core.config import Settings
from sieve.core.errors import SecurityRejection
from sieve.core.logging import get_logger
from sieve.github.webhooks import MAX_BODY_BYTES, dispatch, record_delivery, verify_signature
from sieve.runtime import IntegrationNotConfigured

router = APIRouter(tags=["webhooks"])
log = get_logger(__name__)


class PayloadTooLarge(SecurityRejection):
    code = "payload_too_large"
    http_status = 413


@router.post("/webhooks/github", status_code=202)
async def github_webhook(request: Request, session: SessionDep) -> dict[str, str]:
    settings: Settings = request.app.state.settings
    if settings.github_webhook_secret is None:
        raise IntegrationNotConfigured("webhook secret not configured")
    declared = int(request.headers.get("content-length") or 0)
    if declared > MAX_BODY_BYTES:
        raise PayloadTooLarge(f"declared body of {declared} bytes")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BODY_BYTES:
            raise PayloadTooLarge("body exceeded limit")
    # Signature first: nothing about the payload is trusted, or even parsed, before this.
    verify_signature(
        settings.github_webhook_secret.get_secret_value().encode(),
        bytes(body),
        request.headers.get("x-hub-signature-256"),
    )
    event = request.headers.get("x-github-event", "")
    delivery = request.headers.get("x-github-delivery", "")
    if not event or not delivery:
        raise SecurityRejection("missing GitHub event headers")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise SecurityRejection("webhook body is not JSON") from exc
    if not isinstance(payload, dict):
        raise SecurityRejection("webhook body is not an object")
    if not record_delivery(session, delivery, event, payload):
        return {"status": "duplicate delivery ignored"}
    outcome = dispatch(session, event, payload)
    session.commit()
    log.info("webhook.processed", github_event=event, delivery=delivery, outcome=outcome)
    return {"status": outcome}
