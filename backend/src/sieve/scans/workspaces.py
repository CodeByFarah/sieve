"""Where a scan's source tree comes from. Each checkout is an isolated temporary directory that is
removed when the scan finishes, whatever the outcome."""

import hashlib
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import Protocol

from sieve.core.workspace import Workspace
from sieve.db.models import Repository, Scan


class WorkspaceProvider(Protocol):
    def checkout(self, repository: Repository, scan: Scan) -> AbstractContextManager[Path]: ...


def tree_digest(root: Path) -> str:
    """A 40-hex content digest standing in for a commit SHA for trees that are not git checkouts
    (the bundled demo application). Changes whenever any file's path or content changes."""
    workspace = Workspace(root)
    digest = hashlib.sha1(usedforsecurity=False)
    for path in workspace.iter_files():
        digest.update(path.encode() + b"\0")
        digest.update(hashlib.sha256((root / path).read_bytes()).digest())
    return digest.hexdigest()


class DirectoryWorkspaces:
    """Serves a project-owned directory (the demo app) as a copy, never in place."""

    def __init__(self, source: Path) -> None:
        self.source = source

    @contextmanager
    def checkout(self, repository: Repository, scan: Scan) -> Iterator[Path]:
        with tempfile.TemporaryDirectory(prefix="sieve-scan-") as tmp:
            target = Path(tmp) / "repo"
            shutil.copytree(self.source, target, symlinks=True)
            yield target
