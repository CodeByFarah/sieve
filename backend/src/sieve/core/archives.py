"""Safe extraction of untrusted zip and tar archives (repository tarballs, wheels, sdists).

Every member is checked before anything is written:

* the normalised path must stay inside the destination (no absolute paths, drive letters, ``..``);
* only regular files are extracted — symlinks, hardlinks, devices and FIFOs are skipped;
* member count, per-member size and total size are capped, counting the bytes actually
  decompressed rather than trusting archive headers (decompression bombs lie about sizes).
"""

import posixpath
import re
import shutil
import stat
import tarfile
import zipfile
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

from sieve.core.errors import SecurityRejection

_DRIVE = re.compile(r"^[A-Za-z]:")
_CHUNK = 64 * 1024

MemberFilter = Callable[[str], bool]


@dataclass(frozen=True)
class ArchiveLimits:
    max_members: int = 50_000
    max_member_bytes: int = 50 * 1024 * 1024
    max_total_bytes: int = 500 * 1024 * 1024


@dataclass
class ExtractionReport:
    extracted: int = 0
    total_bytes: int = 0
    skipped: Counter[str] = field(default_factory=Counter)


class ArchiveRejected(SecurityRejection):
    code = "archive_rejected"
    default_public_message = "The archive was rejected by safety checks."


def safe_member_path(name: str, strip_components: int = 0) -> str | None:
    """The member's destination-relative path, or ``None`` if it must not be extracted."""
    if "\x00" in name:
        return None
    normalized = posixpath.normpath(name.replace("\\", "/"))
    if normalized.startswith("/") or _DRIVE.match(normalized):
        return None
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if ".." in parts:
        return None
    parts = parts[strip_components:]
    return "/".join(parts) if parts else None


class _Budget:
    def __init__(self, limits: ArchiveLimits, report: ExtractionReport) -> None:
        self.limits = limits
        self.report = report

    def copy(self, source: IO[bytes], destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        with destination.open("xb") as out:
            while chunk := source.read(_CHUNK):
                written += len(chunk)
                self.report.total_bytes += len(chunk)
                if written > self.limits.max_member_bytes:
                    raise ArchiveRejected(f"member exceeds {self.limits.max_member_bytes} bytes")
                if self.report.total_bytes > self.limits.max_total_bytes:
                    raise ArchiveRejected(f"archive exceeds {self.limits.max_total_bytes} bytes")
                out.write(chunk)
        self.report.extracted += 1

    def count_member(self) -> None:
        if self.report.extracted + sum(self.report.skipped.values()) >= self.limits.max_members:
            raise ArchiveRejected(f"archive has more than {self.limits.max_members} members")


def _target(destination: Path, relative: str) -> Path | None:
    target = (destination / relative).resolve()
    return target if target.is_relative_to(destination) else None


def extract_zip(
    archive: Path,
    destination: Path,
    *,
    limits: ArchiveLimits = ArchiveLimits(),
    strip_components: int = 0,
    include: MemberFilter | None = None,
) -> ExtractionReport:
    destination = destination.resolve()
    report = ExtractionReport()
    budget = _Budget(limits, report)
    try:
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                budget.count_member()
                if info.is_dir():
                    continue
                # Many zip writers set no file-type bits at all; only an explicit non-regular
                # type (symlink, device, ...) is refused.
                kind = stat.S_IFMT(info.external_attr >> 16)
                if kind and kind != stat.S_IFREG:
                    report.skipped["not_regular_file"] += 1
                    continue
                relative = safe_member_path(info.filename, strip_components)
                target = _target(destination, relative) if relative else None
                if relative is None or target is None:
                    report.skipped["unsafe_path"] += 1
                    continue
                if include is not None and not include(relative):
                    report.skipped["filtered"] += 1
                    continue
                if target.exists():
                    report.skipped["duplicate"] += 1
                    continue
                with zf.open(info) as source:
                    budget.copy(source, target)
    except zipfile.BadZipFile as exc:
        raise ArchiveRejected(f"invalid zip: {exc}") from exc
    return report


def extract_tar(
    archive: Path,
    destination: Path,
    *,
    limits: ArchiveLimits = ArchiveLimits(),
    strip_components: int = 0,
    include: MemberFilter | None = None,
) -> ExtractionReport:
    destination = destination.resolve()
    report = ExtractionReport()
    budget = _Budget(limits, report)
    try:
        with tarfile.open(archive, mode="r:*") as tf:
            for member in tf:
                budget.count_member()
                if member.isdir():
                    continue
                if not member.isreg():
                    report.skipped["not_regular_file"] += 1
                    continue
                relative = safe_member_path(member.name, strip_components)
                target = _target(destination, relative) if relative else None
                if relative is None or target is None:
                    report.skipped["unsafe_path"] += 1
                    continue
                if include is not None and not include(relative):
                    report.skipped["filtered"] += 1
                    continue
                if target.exists():
                    report.skipped["duplicate"] += 1
                    continue
                source = tf.extractfile(member)
                if source is None:
                    report.skipped["unreadable"] += 1
                    continue
                with source:
                    budget.copy(source, target)
    except tarfile.TarError as exc:
        raise ArchiveRejected(f"invalid tar: {exc}") from exc
    return report


def remove_tree(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)
