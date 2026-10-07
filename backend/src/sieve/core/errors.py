"""Error taxonomy shared by the API and the workers.

Every error carries a category that decides how it is handled: which HTTP status it maps to,
whether a job that raised it is retried, and what (if anything) the user is told. The internal
``message`` is for logs; ``public_message`` is the only text that may reach a user.
"""

from collections.abc import Mapping
from enum import StrEnum
from typing import Any, ClassVar


class ErrorCategory(StrEnum):
    USER = "user"
    EXTERNAL = "external"
    TRANSIENT = "transient"
    ANALYSIS = "analysis"
    SECURITY = "security"
    INTERNAL = "internal"


_RETRYABLE = frozenset({ErrorCategory.EXTERNAL, ErrorCategory.TRANSIENT})


class SieveError(Exception):
    category: ClassVar[ErrorCategory] = ErrorCategory.INTERNAL
    code: ClassVar[str] = "internal_error"
    http_status: ClassVar[int] = 500
    default_public_message: ClassVar[str] = "Something went wrong on our side."

    def __init__(
        self,
        message: str,
        *,
        public_message: str | None = None,
        detail: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.public_message = public_message or self.default_public_message
        self.detail: Mapping[str, Any] = detail or {}

    @property
    def retryable(self) -> bool:
        return self.category in _RETRYABLE


class UserError(SieveError):
    category = ErrorCategory.USER
    code = "invalid_request"
    http_status = 400
    default_public_message = "The request could not be processed."


class NotFoundError(UserError):
    """Also used for resources the caller may not see, so existence is never revealed."""

    code = "not_found"
    http_status = 404
    default_public_message = "The requested resource was not found."


class ConflictError(UserError):
    code = "conflict"
    http_status = 409
    default_public_message = "The resource was changed by someone else. Reload and try again."


class ExternalServiceError(SieveError):
    category = ErrorCategory.EXTERNAL
    code = "external_service_error"
    http_status = 502
    default_public_message = "An upstream service failed. The operation will be retried."


class TransientError(SieveError):
    category = ErrorCategory.TRANSIENT
    code = "temporarily_unavailable"
    http_status = 503
    default_public_message = "The service is temporarily unavailable. Please retry."


class AnalysisError(SieveError):
    category = ErrorCategory.ANALYSIS
    code = "analysis_failed"
    http_status = 422
    default_public_message = "Analysis could not be completed for this input."


class SecurityRejection(SieveError):
    """Input was rejected for security reasons. Always audited; never retried."""

    category = ErrorCategory.SECURITY
    code = "security_rejection"
    http_status = 400
    default_public_message = "The request was rejected."


class AuthenticationRequired(SecurityRejection):
    code = "authentication_required"
    http_status = 401
    default_public_message = "Authentication is required."


class PermissionDenied(SecurityRejection):
    code = "permission_denied"
    http_status = 403
    default_public_message = "You do not have permission to perform this action."
