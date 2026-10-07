"""Composition root: long-lived collaborators built once from settings."""

from collections.abc import Callable
from importlib.metadata import version

import boto3
import httpx

from sieve.analysis.engine import ReachabilityEngine
from sieve.analysis.sandbox import Indexer
from sieve.core.config import Settings
from sieve.core.errors import UserError
from sieve.db.enums import RepositorySource
from sieve.db.models import Repository
from sieve.packages.pypi import PypiSourceCache
from sieve.scans.workspaces import DirectoryWorkspaces, WorkspaceProvider
from sieve.storage.artifacts import ArtifactStore, FilesystemArtifactStore, S3ArtifactStore


class IntegrationNotConfigured(UserError):
    code = "integration_not_configured"


def tool_version() -> str:
    return version("sieve")


def build_artifact_store(settings: Settings) -> ArtifactStore:
    if settings.artifact_backend == "s3":
        if not settings.s3_bucket:
            raise IntegrationNotConfigured(
                "SIEVE_S3_BUCKET is required with the s3 artifact backend"
            )
        return S3ArtifactStore(
            boto3.client("s3", region_name=settings.aws_region), settings.s3_bucket
        )
    return FilesystemArtifactStore(settings.artifact_root)


def build_engine(settings: Settings, client: httpx.Client, indexer: Indexer) -> ReachabilityEngine:
    return ReachabilityEngine(
        PypiSourceCache(settings.package_cache_dir / "packages", client),
        indexer,
        index_cache=settings.package_cache_dir / "index",
    )


def build_workspaces(
    settings: Settings, github: Callable[[Repository], WorkspaceProvider] | None
) -> Callable[[Repository], WorkspaceProvider]:
    demo = DirectoryWorkspaces(settings.demo_app_dir)

    def select(repository: Repository) -> WorkspaceProvider:
        if repository.source is RepositorySource.DEMO:
            return demo
        if github is None:
            raise IntegrationNotConfigured("GitHub App credentials are not configured")
        return github(repository)

    return select
