"""Indexing untrusted source in resource-limited child processes.

``ast.parse`` of hostile input can consume a lot of memory or CPU. Production indexing runs in a
pool of spawned processes with ``RLIMIT_AS``/``RLIMIT_CPU`` (Linux) and a wall-clock timeout; a
child that dies or times out fails the analysis with a budget error instead of taking the worker
down. On platforms without ``resource`` (Windows dev machines) only the timeout applies.
"""

import multiprocessing
from collections.abc import Sequence
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from concurrent.futures.process import BrokenProcessPool
from pathlib import Path
from typing import Any, Protocol

from sieve.analysis.discovery import SourceFile
from sieve.analysis.indexer import index_module
from sieve.analysis.model import ModuleSummary
from sieve.core.errors import AnalysisError
from sieve.core.workspace import Workspace


class AnalysisBudgetExceeded(AnalysisError):
    code = "analysis_budget_exceeded"


def index_files(
    root: str, files: Sequence[tuple[str, str, bool]], max_file_bytes: int
) -> list[dict[str, Any]]:
    """Runs in the child process. Plain data in, plain data out."""
    workspace = Workspace(Path(root), max_file_bytes=max_file_bytes)
    summaries = []
    for module, path, is_package in files:
        source = workspace.read_text(path)
        if source is None:
            summary = ModuleSummary(
                module, path, is_package, parse_error="file too large or unreadable"
            )
        else:
            summary = index_module(module, path, source, is_package)
        summaries.append(summary.to_dict())
    return summaries


def _limit_resources(memory_bytes: int, cpu_seconds: int) -> None:
    try:
        import resource
    except ImportError:
        return
    resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))


class Indexer(Protocol):
    def index(self, root: Path, files: Sequence[SourceFile]) -> list[ModuleSummary]: ...


class InProcessIndexer:
    """For tests and trusted fixtures only."""

    def __init__(self, max_file_bytes: int = 1_000_000) -> None:
        self.max_file_bytes = max_file_bytes

    def index(self, root: Path, files: Sequence[SourceFile]) -> list[ModuleSummary]:
        raw = index_files(
            str(root), [(f.module, f.path, f.is_package) for f in files], self.max_file_bytes
        )
        return [ModuleSummary.from_dict(item) for item in raw]


class ProcessIndexer:
    def __init__(
        self,
        *,
        workers: int = 2,
        memory_bytes: int = 1024 * 1024 * 1024,
        cpu_seconds: int = 300,
        timeout_seconds: float = 300.0,
        max_file_bytes: int = 1_000_000,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_file_bytes = max_file_bytes
        self._pool = ProcessPoolExecutor(
            max_workers=workers,
            mp_context=multiprocessing.get_context("spawn"),
            initializer=_limit_resources,
            initargs=(memory_bytes, cpu_seconds),
        )

    def index(self, root: Path, files: Sequence[SourceFile]) -> list[ModuleSummary]:
        future = self._pool.submit(
            index_files,
            str(root),
            [(f.module, f.path, f.is_package) for f in files],
            self.max_file_bytes,
        )
        try:
            raw = future.result(timeout=self.timeout_seconds)
        except (FutureTimeout, BrokenProcessPool, MemoryError) as exc:
            raise AnalysisBudgetExceeded(
                f"indexing {root.name} exceeded its limits: {type(exc).__name__}"
            ) from exc
        return [ModuleSummary.from_dict(item) for item in raw]

    def close(self) -> None:
        self._pool.shutdown(cancel_futures=True)

    def __enter__(self) -> "ProcessIndexer":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
