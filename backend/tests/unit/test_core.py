import time
import uuid

import pytest

from sieve.core.correlation import accept_inbound, correlation_scope, get_correlation_id
from sieve.core.errors import (
    ConflictError,
    ErrorCategory,
    ExternalServiceError,
    NotFoundError,
    SecurityRejection,
    TransientError,
    UserError,
)
from sieve.core.ids import uuid7, uuid7_timestamp_ms
from sieve.core.logging import REDACTED, redact_secrets, redact_text


class TestUuid7:
    def test_version_and_variant(self) -> None:
        value = uuid7()
        assert value.version == 7
        assert value.variant == uuid.RFC_4122

    def test_embeds_timestamp(self) -> None:
        assert uuid7_timestamp_ms(uuid7(timestamp_ms=1_700_000_000_123)) == 1_700_000_000_123

    def test_orders_by_time_across_milliseconds(self) -> None:
        earlier = uuid7(timestamp_ms=1_000)
        later = uuid7(timestamp_ms=1_001)
        assert earlier < later

    def test_uses_current_time_by_default(self) -> None:
        before = time.time_ns() // 1_000_000
        stamp = uuid7_timestamp_ms(uuid7())
        after = time.time_ns() // 1_000_000
        assert before <= stamp <= after

    def test_rejects_out_of_range_timestamp(self) -> None:
        with pytest.raises(ValueError, match="out of range"):
            uuid7(timestamp_ms=1 << 48)


class TestErrors:
    @pytest.mark.parametrize(
        ("error", "retryable"),
        [
            (UserError("x"), False),
            (NotFoundError("x"), False),
            (SecurityRejection("x"), False),
            (ExternalServiceError("x"), True),
            (TransientError("x"), True),
        ],
    )
    def test_only_external_and_transient_errors_retry(
        self, error: Exception, retryable: bool
    ) -> None:
        assert error.retryable is retryable  # type: ignore[attr-defined]

    def test_internal_message_is_not_the_public_message(self) -> None:
        error = ConflictError("finding 123 version 4 != 5")
        assert "123" not in error.public_message
        assert error.http_status == 409
        assert error.category is ErrorCategory.USER


class TestCorrelation:
    @pytest.mark.parametrize(
        "unsafe",
        [None, "", "short", "has spaces in it", "x" * 65, "evil\r\nSet-Cookie: a=b", "<script>"],
    )
    def test_unsafe_inbound_ids_are_replaced(self, unsafe: str | None) -> None:
        accepted = accept_inbound(unsafe)
        assert accepted != unsafe
        assert uuid.UUID(accepted).version == 7

    def test_safe_inbound_id_is_kept(self) -> None:
        assert accept_inbound("req-0123456789") == "req-0123456789"

    def test_scope_sets_and_restores(self) -> None:
        assert get_correlation_id() is None
        with correlation_scope("abc-12345678"):
            assert get_correlation_id() == "abc-12345678"
        assert get_correlation_id() is None


class TestRedaction:
    @pytest.mark.parametrize(
        "secret",
        [
            "ghs_" + "a" * 36,
            "ghp_" + "B" * 36,
            "github_pat_" + "c" * 40,
            "sk-ant-" + "d" * 30,
            "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----",
        ],
    )
    def test_secret_patterns_are_redacted_in_text(self, secret: str) -> None:
        redacted = redact_text(f"token was {secret} here")
        assert secret not in redacted
        assert REDACTED in redacted

    def test_url_credentials_are_redacted(self) -> None:
        redacted = redact_text("postgresql+psycopg://sieve:hunter2@db:5432/sieve")
        assert "hunter2" not in redacted
        assert "db:5432/sieve" in redacted

    def test_sensitive_keys_are_redacted_recursively(self) -> None:
        event = {
            "event": "x",
            "headers": {"Authorization": "Bearer abc", "accept": "json"},
            "token": "plain",
        }
        result = redact_secrets(None, "info", event)
        assert result["headers"] == {"Authorization": REDACTED, "accept": "json"}
        assert result["token"] == REDACTED
        assert result["event"] == "x"
