"""Fixed-window rate limiting (spec §40). Redis in production so limits hold across API tasks;
an in-process limiter for development and tests."""

import threading
import time
from typing import Any, Protocol

import redis
from fastapi import Request

from sieve.core.config import Settings
from sieve.core.errors import ErrorCategory, SieveError, TransientError
from sieve.core.logging import get_logger

log = get_logger(__name__)


class RateLimited(SieveError):
    category = ErrorCategory.USER
    code = "rate_limited"
    http_status = 429
    default_public_message = "Too many requests. Please wait a moment and try again."


class RateLimiter(Protocol):
    def allow(self, key: str, limit: int, window_seconds: int) -> bool: ...


class MemoryRateLimiter:
    def __init__(self) -> None:
        self._counts: dict[tuple[str, int], int] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        window = int(time.time() // window_seconds)
        with self._lock:
            if len(self._counts) > 10_000:
                self._counts = {k: v for k, v in self._counts.items() if k[1] >= window - 1}
            count = self._counts.get((key, window), 0) + 1
            self._counts[(key, window)] = count
        return count <= limit


class RedisRateLimiter:
    def __init__(self, client: Any) -> None:
        self.client = client

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        bucket = f"sieve:rl:{key}:{int(time.time() // window_seconds)}"
        try:
            pipe = self.client.pipeline()
            pipe.incr(bucket)
            pipe.expire(bucket, window_seconds + 1)
            count, _ = pipe.execute()
        except redis.RedisError as exc:
            # Fail closed: the limited endpoints are the expensive or abusable ones.
            raise TransientError(f"rate limiter unavailable: {type(exc).__name__}") from exc
        return int(count) <= limit


def build_rate_limiter(settings: Settings) -> RateLimiter:
    if settings.redis_url is None:
        if settings.environment == "production":
            log.warning("ratelimit.in_process_only", reason="SIEVE_REDIS_URL not set")
        return MemoryRateLimiter()
    return RedisRateLimiter(
        redis.Redis.from_url(settings.redis_url.get_secret_value(), socket_timeout=1)
    )


def client_ip(request: Request) -> str:
    """The peer address. Behind the load balancer uvicorn runs with --proxy-headers and a trusted
    forwarded-allow-ips list, so this is the original client, not the balancer."""
    return request.client.host if request.client else "unknown"


def enforce(
    request: Request, name: str, *, limit: int, window_seconds: int, subject: str | None = None
) -> None:
    limiter: RateLimiter = request.app.state.rate_limiter
    if not limiter.allow(f"{name}:{subject or client_ip(request)}", limit, window_seconds):
        raise RateLimited(f"{name} limit {limit}/{window_seconds}s exceeded")
