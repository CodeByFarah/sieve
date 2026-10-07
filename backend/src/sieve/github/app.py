"""GitHub App credentials and API access.

Installation tokens are minted on demand and kept only in process memory until shortly before
they expire. Nothing GitHub issues is stored in the database.
"""

import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
import jwt
from sqlalchemy.orm import Session, sessionmaker

from sieve.core.archives import ArchiveLimits, extract_tar
from sieve.core.config import Settings
from sieve.core.errors import ExternalServiceError, UserError
from sieve.core.http import download, raise_for_status
from sieve.db.models import GitHubInstallation, Repository, Scan

API_VERSION = "2022-11-28"
TOKEN_REFRESH_MARGIN_SECONDS = 300
MAX_TARBALL_BYTES = 200 * 1024 * 1024


class GitHubApp:
    def __init__(self, http: httpx.Client, *, app_id: str, private_key: str, api_url: str) -> None:
        self.http = http
        self.app_id = app_id
        self._private_key = private_key
        self.api_url = api_url.rstrip("/")
        self._tokens: dict[int, tuple[str, float]] = {}
        self._lock = threading.Lock()

    @classmethod
    def from_settings(cls, settings: Settings, http: httpx.Client) -> "GitHubApp | None":
        if not (settings.github_app_id and settings.github_private_key):
            return None
        return cls(
            http,
            app_id=settings.github_app_id,
            private_key=settings.github_private_key.get_secret_value(),
            api_url=settings.github_api_url,
        )

    def app_jwt(self) -> str:
        now = int(time.time())
        payload = {"iat": now - 60, "exp": now + 540, "iss": self.app_id}
        return jwt.encode(payload, self._private_key, algorithm="RS256")

    def installation_token(self, installation_id: int) -> str:
        with self._lock:
            cached = self._tokens.get(installation_id)
            if cached and cached[1] - time.time() > TOKEN_REFRESH_MARGIN_SECONDS:
                return cached[0]
        data = self._call(
            "POST", f"/app/installations/{installation_id}/access_tokens", bearer=self.app_jwt()
        )
        token = str(data["token"])
        expires = datetime.fromisoformat(str(data["expires_at"])).timestamp()
        with self._lock:
            self._tokens[installation_id] = (token, expires)
        return token

    def _call(
        self,
        method: str,
        path: str,
        *,
        bearer: str,
        json: object = None,
        params: dict[str, str] | None = None,
    ) -> Any:
        try:
            response = self.http.request(
                method,
                f"{self.api_url}{path}",
                json=json,
                params=params,
                headers={
                    "Authorization": f"Bearer {bearer}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": API_VERSION,
                },
            )
        except httpx.TransportError as exc:
            raise ExternalServiceError(
                f"GitHub {method} {path} failed: {type(exc).__name__}"
            ) from exc
        raise_for_status(response)
        return response.json() if response.content else None

    def as_installation(self, installation_id: int, method: str, path: str, **kwargs: Any) -> Any:
        return self._call(method, path, bearer=self.installation_token(installation_id), **kwargs)

    def as_app(self, method: str, path: str, **kwargs: Any) -> Any:
        return self._call(method, path, bearer=self.app_jwt(), **kwargs)

    def installation_repositories(self, installation_id: int) -> list[dict[str, Any]]:
        repositories: list[dict[str, Any]] = []
        page = 1
        while True:
            data = self.as_installation(
                installation_id,
                "GET",
                "/installation/repositories",
                params={"per_page": "100", "page": str(page)},
            )
            batch = data.get("repositories", [])
            repositories.extend(batch)
            if len(batch) < 100:
                return repositories
            page += 1

    def head_commit(self, installation_id: int, full_name: str, branch: str) -> str:
        data = self.as_installation(installation_id, "GET", f"/repos/{full_name}/commits/{branch}")
        return str(data["sha"])

    def download_tarball(
        self, installation_id: int, full_name: str, sha: str, destination: Path
    ) -> None:
        download(
            self.http,
            f"{self.api_url}/repos/{full_name}/tarball/{sha}",
            destination,
            max_bytes=MAX_TARBALL_BYTES,
            headers={
                "Authorization": f"Bearer {self.installation_token(installation_id)}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION,
            },
        )


class GitHubWorkspaces:
    """Checks out a commit by downloading its tarball into an isolated temporary directory."""

    def __init__(self, app: GitHubApp, session_factory: sessionmaker[Session]) -> None:
        self.app = app
        self.session_factory = session_factory

    @contextmanager
    def checkout(self, repository: Repository, scan: Scan) -> Iterator[Path]:
        with self.session_factory() as session:
            installation = session.get(GitHubInstallation, repository.installation_id)
            if installation is None or installation.suspended_at is not None:
                raise UserError(
                    "the GitHub installation for this repository is missing or suspended"
                )
            installation_id = installation.github_installation_id
        with tempfile.TemporaryDirectory(prefix="sieve-gh-") as tmp:
            archive = Path(tmp) / "source.tar.gz"
            self.app.download_tarball(
                installation_id, repository.full_name, scan.commit_sha, archive
            )
            target = Path(tmp) / "repo"
            target.mkdir()
            extract_tar(
                archive,
                target,
                strip_components=1,
                limits=ArchiveLimits(max_total_bytes=1024 * 1024 * 1024),
            )
            archive.unlink()
            yield target
