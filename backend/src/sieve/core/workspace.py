"""Read-only, path-safe access to an untrusted directory tree (a checked-out repository or an
extracted package). Symlinks are never followed; paths may not escape the root."""

import os
import posixpath
import re
import stat
from collections.abc import Iterator
from pathlib import Path

from sieve.core.errors import SecurityRejection, UserError

_DRIVE = re.compile(r"^[A-Za-z]:")


class WorkspaceTooLarge(UserError):
    code = "workspace_too_large"
    default_public_message = "The repository exceeds Sieve's size limits for analysis."


def _is_link(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


class Workspace:
    def __init__(
        self,
        root: Path,
        *,
        max_files: int = 20_000,
        max_file_bytes: int = 2_000_000,
        max_depth: int = 32,
    ) -> None:
        self.root = root.resolve()
        self.max_files = max_files
        self.max_file_bytes = max_file_bytes
        self.max_depth = max_depth

    def resolve(self, relative: str) -> Path:
        """Map a workspace-relative POSIX path to a real path, refusing anything that escapes."""
        if "\x00" in relative:
            raise SecurityRejection("NUL byte in path")
        normalized = posixpath.normpath(relative.replace("\\", "/"))
        if (
            normalized.startswith("/")
            or normalized == ".."
            or normalized.startswith("../")
            or _DRIVE.match(normalized)
        ):
            raise SecurityRejection(f"path escapes workspace: {relative[:200]!r}")
        current = self.root
        for part in normalized.split("/"):
            if part in ("", "."):
                continue
            current = current / part
            if _is_link(current):
                raise SecurityRejection(f"symlink in path: {relative[:200]!r}")
        return current

    def read_text(self, relative: str) -> str | None:
        """File contents, or ``None`` if missing, not a regular file, or over the size limit."""
        try:
            path = self.resolve(relative)
            info = path.lstat()
        except (FileNotFoundError, NotADirectoryError):
            return None
        if not stat.S_ISREG(info.st_mode) or info.st_size > self.max_file_bytes:
            return None
        return path.read_bytes().decode("utf-8", errors="replace")

    def iter_files(self, *, skip_dirs: frozenset[str] = frozenset()) -> Iterator[str]:
        """Regular files as sorted, workspace-relative POSIX paths."""
        count = 0
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            directory = Path(dirpath)
            relative_dir = directory.relative_to(self.root)
            depth = len(relative_dir.parts)
            dirnames[:] = sorted(
                name
                for name in dirnames
                if name not in skip_dirs
                and depth < self.max_depth
                and not _is_link(directory / name)
            )
            for name in sorted(filenames):
                if not stat.S_ISREG((directory / name).lstat().st_mode):
                    continue
                count += 1
                if count > self.max_files:
                    raise WorkspaceTooLarge(f"more than {self.max_files} files")
                yield (relative_dir / name).as_posix()
