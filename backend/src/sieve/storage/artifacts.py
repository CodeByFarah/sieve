"""Immutable artifacts addressed by key; integrity is checked against the SHA-256 recorded in
PostgreSQL when the artifact is read back."""

import hashlib
import re
from pathlib import Path
from typing import Any, Protocol

from sieve.core.errors import NotFoundError, SecurityRejection

_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,500}$")


class IntegrityError(SecurityRejection):
    code = "artifact_integrity"


def _check_key(key: str) -> None:
    if not _KEY.match(key) or ".." in key.split("/"):
        raise SecurityRejection(f"invalid artifact key {key[:80]!r}")


class ArtifactStore(Protocol):
    def put(self, key: str, content: bytes, content_type: str) -> str: ...

    def get(self, key: str, expected_sha256: str | None = None) -> bytes: ...


def _verify(content: bytes, expected: str | None) -> bytes:
    if expected is not None and hashlib.sha256(content).hexdigest() != expected:
        raise IntegrityError("artifact content does not match its recorded digest")
    return content


class FilesystemArtifactStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def put(self, key: str, content: bytes, content_type: str) -> str:
        _check_key(key)
        path = self.root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return hashlib.sha256(content).hexdigest()

    def get(self, key: str, expected_sha256: str | None = None) -> bytes:
        _check_key(key)
        path = self.root / key
        if not path.is_file():
            raise NotFoundError(f"artifact {key} not found")
        return _verify(path.read_bytes(), expected_sha256)


class S3ArtifactStore:
    def __init__(self, client: Any, bucket: str) -> None:
        self.client = client
        self.bucket = bucket

    def put(self, key: str, content: bytes, content_type: str) -> str:
        _check_key(key)
        digest = hashlib.sha256(content).hexdigest()
        self.client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=content,
            ContentType=content_type,
            ServerSideEncryption="AES256",
            Metadata={"sha256": digest},
        )
        return digest

    def get(self, key: str, expected_sha256: str | None = None) -> bytes:
        _check_key(key)
        try:
            response = self.client.get_object(Bucket=self.bucket, Key=key)
        except self.client.exceptions.NoSuchKey as exc:
            raise NotFoundError(f"artifact {key} not found") from exc
        return _verify(response["Body"].read(), expected_sha256)
