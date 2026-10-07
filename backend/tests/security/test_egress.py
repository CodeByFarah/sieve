"""SSRF defences: outbound requests only to allow-listed HTTPS hosts (threat model §3.5)."""

from pathlib import Path

import httpx
import pytest
import respx

from sieve.core.http import (
    DigestMismatch,
    DownloadTooLarge,
    EgressDenied,
    build_client,
    download,
    get_json,
)


@pytest.mark.parametrize(
    "url",
    [
        "https://169.254.169.254/latest/meta-data/",  # cloud metadata
        "https://localhost/admin",
        "http://api.osv.dev/v1/vulns/X",  # plain HTTP to an allowed host
        "https://api.osv.dev.evil.example/x",
        "https://internal.corp/",
    ],
)
def test_requests_outside_the_allow_list_are_refused(url: str) -> None:
    with build_client() as client, pytest.raises(EgressDenied):
        client.get(url)


@respx.mock
def test_redirects_off_the_allow_list_are_refused() -> None:
    respx.get("https://pypi.org/pypi/x/json").mock(
        return_value=httpx.Response(302, headers={"Location": "https://169.254.169.254/"})
    )
    with build_client() as client, pytest.raises(EgressDenied):
        get_json(client, "https://pypi.org/pypi/x/json")


@respx.mock
def test_download_enforces_size_cap(tmp_path: Path) -> None:
    respx.get("https://files.pythonhosted.org/big.whl").mock(
        return_value=httpx.Response(200, content=b"x" * 2048)
    )
    with build_client() as client, pytest.raises(DownloadTooLarge):
        download(client, "https://files.pythonhosted.org/big.whl", tmp_path / "f", max_bytes=1024)


@respx.mock
def test_download_verifies_digest_and_removes_bad_files(tmp_path: Path) -> None:
    respx.get("https://files.pythonhosted.org/p.whl").mock(
        return_value=httpx.Response(200, content=b"tampered")
    )
    target = tmp_path / "p.whl"
    with build_client() as client, pytest.raises(DigestMismatch):
        download(
            client,
            "https://files.pythonhosted.org/p.whl",
            target,
            max_bytes=1024,
            expected_sha256="00" * 32,
        )
    assert not target.exists()
