"""Fetch the exact released artifact of ``name==version`` from PyPI and extract its Python files.

* Wheels are preferred (no build step exists for them, and their layout is the import layout).
  An sdist is used only as an archive of files: nothing in it is run.
* The artifact's SHA-256 is checked against the digest PyPI publishes.
* Extraction keeps ``.py`` files only and goes through the safe extractor.
* Results are cached on disk by artifact digest, so every scan using ``requests==2.19.1`` shares
  one copy.
"""

import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from sieve.core.archives import extract_tar, extract_zip
from sieve.core.errors import ExternalServiceError
from sieve.core.http import download, get_json

PYPI_JSON = "https://pypi.org/pypi/{name}/{version}/json"
ARTIFACT_HOST = "files.pythonhosted.org"
MAX_ARTIFACT_BYTES = 100 * 1024 * 1024
_COMPLETE_MARKER = ".sieve-complete"


@dataclass(frozen=True)
class Artifact:
    filename: str
    url: str
    sha256: str
    kind: str  # "wheel" | "sdist"


@dataclass(frozen=True)
class FetchedSource:
    root: Path
    cache_key: str  # artifact sha256
    artifact: Artifact


class NoUsableArtifact(ExternalServiceError):
    code = "no_usable_artifact"

    @property
    def retryable(self) -> bool:
        return False


def _rank(entry: dict[str, Any]) -> tuple[int, int, str] | None:
    filename: str = entry.get("filename", "")
    if entry.get("packagetype") == "bdist_wheel":
        parts = filename[:-4].split("-")
        python_tags = parts[-3].split(".") if len(parts) >= 5 else []
        py3 = [t for t in python_tags if t.startswith(("py3", "cp3"))]
        if not py3:
            return None  # Python 2-only wheels contain Python 2 source
        # Newest CPython first (cp313 before cp36): later wheels track the released source.
        newest = max((int(t[3:]) if t[3:].isdigit() else 0) for t in py3)
        return (0 if filename.endswith("-none-any.whl") else 1, -newest, filename)
    if entry.get("packagetype") == "sdist" and filename.endswith((".tar.gz", ".zip", ".tgz")):
        return (2, 0, filename)
    return None


def choose_artifact(files: list[dict[str, Any]]) -> Artifact | None:
    candidates = []
    for entry in files:
        rank = _rank(entry)
        digest = (entry.get("digests") or {}).get("sha256")
        url = entry.get("url", "")
        if (
            rank is None
            or not digest
            or urlparse(url).hostname != ARTIFACT_HOST
            or entry.get("yanked")
        ):
            continue
        kind = "wheel" if rank[0] < 2 else "sdist"
        candidates.append((rank, Artifact(entry["filename"], url, digest, kind)))
    return min(candidates, key=lambda c: c[0])[1] if candidates else None


def _python_only(path: str) -> bool:
    return path.endswith(".py")


def _source_root(tree: Path) -> Path:
    """sdists commonly use a src/ layout; wheels never do."""
    src = tree / "src"
    has_top_level_python = any(
        child.suffix == ".py" or (child / "__init__.py").exists() for child in tree.iterdir()
    )
    if src.is_dir() and not has_top_level_python:
        return src
    return tree


class PypiSourceCache:
    def __init__(self, cache_dir: Path, client: httpx.Client) -> None:
        self.cache_dir = cache_dir
        self.client = client

    def resolve(self, name: str, version: str) -> Artifact:
        metadata = get_json(self.client, PYPI_JSON.format(name=quote(name), version=quote(version)))
        assert isinstance(metadata, dict)  # noqa: S101
        artifact = choose_artifact(metadata.get("urls", []))
        if artifact is None:
            raise NoUsableArtifact(f"{name}=={version} has no wheel or sdist on PyPI")
        return artifact

    def fetch(self, name: str, version: str) -> FetchedSource:
        artifact = self.resolve(name, version)
        target = self.cache_dir / "src" / artifact.sha256
        tree = target / "tree"
        if (target / _COMPLETE_MARKER).exists():
            return FetchedSource(_source_root(tree), artifact.sha256, artifact)

        shutil.rmtree(target, ignore_errors=True)
        tree.mkdir(parents=True)
        with tempfile.TemporaryDirectory(prefix="sieve-pkg-") as tmp:
            archive = Path(tmp) / artifact.filename
            download(
                self.client,
                artifact.url,
                archive,
                max_bytes=MAX_ARTIFACT_BYTES,
                expected_sha256=artifact.sha256,
            )
            if artifact.kind == "wheel" or artifact.filename.endswith(".zip"):
                strip = 0 if artifact.kind == "wheel" else 1
                extract_zip(archive, tree, strip_components=strip, include=_python_only)
            else:
                extract_tar(archive, tree, strip_components=1, include=_python_only)
        (target / _COMPLETE_MARKER).write_text(artifact.filename)
        return FetchedSource(_source_root(tree), artifact.sha256, artifact)
