"""Outbound HTTP with an egress allow-list (threat model §3.5).

Every request — including each redirect hop — must be HTTPS to an allow-listed host. Advisory
reference URLs are never fetched directly: they are parsed into structured identifiers and
fetched through a known API instead.
"""

import hashlib
from importlib.metadata import version
from pathlib import Path

import httpx

from sieve.core.errors import ExternalServiceError, SecurityRejection, SieveError

ALLOWED_HOSTS = frozenset(
    {
        "api.osv.dev",
        "osv-vulnerabilities.storage.googleapis.com",
        "www.cisa.gov",
        "api.first.org",
        "pypi.org",
        "files.pythonhosted.org",
        "api.github.com",
        "github.com",
        "codeload.github.com",
        "api.anthropic.com",
        "api.openai.com",
    }
)


class EgressDenied(SecurityRejection):
    code = "egress_denied"


class UpstreamRejected(SieveError):
    """The upstream answered with a 4xx: retrying the same request will not help."""

    code = "upstream_rejected"
    http_status = 502
    default_public_message = "An upstream service rejected the request."


def build_client(
    *, timeout: float = 30.0, allowed_hosts: frozenset[str] | None = None
) -> httpx.Client:
    hosts = allowed_hosts or ALLOWED_HOSTS

    def check(request: httpx.Request) -> None:
        if request.url.scheme != "https" or request.url.host not in hosts:
            raise EgressDenied(
                f"egress to {request.url.scheme}://{request.url.host} is not allowed"
            )

    return httpx.Client(
        timeout=timeout,
        follow_redirects=True,
        max_redirects=5,
        headers={
            "User-Agent": f"sieve/{version('sieve')} (+https://github.com/sieve-security/sieve)"
        },
        event_hooks={"request": [check]},
    )


def raise_for_status(response: httpx.Response) -> None:
    if response.status_code >= 500 or response.status_code == 429:
        raise ExternalServiceError(f"{response.request.url.host} returned {response.status_code}")
    if response.status_code >= 400:
        raise UpstreamRejected(f"{response.request.url} returned {response.status_code}")


def get_json(client: httpx.Client, url: str, *, params: dict[str, str] | None = None) -> object:
    try:
        response = client.get(url, params=params)
    except httpx.TransportError as exc:
        raise ExternalServiceError(f"request to {url} failed: {type(exc).__name__}") from exc
    raise_for_status(response)
    return response.json()


def post_json(client: httpx.Client, url: str, payload: object) -> object:
    try:
        response = client.post(url, json=payload)
    except httpx.TransportError as exc:
        raise ExternalServiceError(f"request to {url} failed: {type(exc).__name__}") from exc
    raise_for_status(response)
    return response.json()


class DownloadTooLarge(SecurityRejection):
    code = "download_too_large"


class DigestMismatch(SecurityRejection):
    code = "digest_mismatch"


def download(
    client: httpx.Client,
    url: str,
    destination: Path,
    *,
    max_bytes: int,
    expected_sha256: str | None = None,
    headers: dict[str, str] | None = None,
) -> str:
    """Stream ``url`` to ``destination`` with a hard size cap. Returns the SHA-256 hex digest and
    verifies it when the expected digest is known."""
    digest = hashlib.sha256()
    written = 0
    try:
        with client.stream("GET", url, headers=headers) as response:
            raise_for_status(response)
            with destination.open("wb") as out:
                for chunk in response.iter_bytes():
                    written += len(chunk)
                    if written > max_bytes:
                        raise DownloadTooLarge(f"{url} exceeds {max_bytes} bytes")
                    digest.update(chunk)
                    out.write(chunk)
    except httpx.TransportError as exc:
        raise ExternalServiceError(f"download of {url} failed: {type(exc).__name__}") from exc
    actual = digest.hexdigest()
    if expected_sha256 is not None and actual != expected_sha256.lower():
        destination.unlink(missing_ok=True)
        raise DigestMismatch(f"{url}: expected sha256 {expected_sha256}, got {actual}")
    return actual
