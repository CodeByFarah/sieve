"""Hostile repository and archive content (threat model §3.4)."""

import io
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

from sieve.core.archives import (
    ArchiveLimits,
    ArchiveRejected,
    extract_tar,
    extract_zip,
    safe_member_path,
)
from sieve.core.errors import SecurityRejection
from sieve.core.workspace import Workspace, WorkspaceTooLarge


@pytest.mark.parametrize(
    "name",
    [
        "../evil.py",
        "a/../../evil.py",
        "/etc/passwd",
        "C:/Windows/evil",
        "..\\..\\evil",
        "a\x00b",
        "",
    ],
)
def test_unsafe_member_paths_are_refused(name: str) -> None:
    assert safe_member_path(name) is None


def test_strip_components() -> None:
    assert safe_member_path("owner-repo-abc123/app/main.py", 1) == "app/main.py"
    assert safe_member_path("owner-repo-abc123/", 1) is None


def make_zip(path: Path, members: dict[str, bytes], symlink: str | None = None) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, "/etc/passwd")
    return path


def test_zip_slip_and_symlinks_are_skipped(tmp_path: Path) -> None:
    archive = make_zip(
        tmp_path / "evil.zip",
        {"pkg/ok.py": b"x = 1", "../../escaped.py": b"boom", "/abs.py": b"boom"},
        symlink="pkg/link.py",
    )
    dest = tmp_path / "out"
    dest.mkdir()

    report = extract_zip(archive, dest)

    assert (dest / "pkg" / "ok.py").read_bytes() == b"x = 1"
    assert not (tmp_path / "escaped.py").exists()
    assert not (dest / "pkg" / "link.py").exists()
    assert report.skipped["unsafe_path"] == 2
    assert report.skipped["not_regular_file"] == 1


def test_zip_bomb_is_rejected_by_actual_decompressed_size(tmp_path: Path) -> None:
    archive = tmp_path / "bomb.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.bin", b"\0" * 2_000_000)  # compresses to a few KB
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(ArchiveRejected):
        extract_zip(archive, dest, limits=ArchiveLimits(max_member_bytes=1_000_000))


def test_member_count_limit(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "many.zip", {f"f{i}.py": b"" for i in range(20)})
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(ArchiveRejected):
        extract_zip(archive, dest, limits=ArchiveLimits(max_members=10))


def test_tar_links_devices_and_traversal_are_skipped(tmp_path: Path) -> None:
    archive = tmp_path / "evil.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:

        def add(
            name: str, data: bytes = b"", kind: bytes = tarfile.REGTYPE, link: str = ""
        ) -> None:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.linkname = link
            info.size = len(data) if kind == tarfile.REGTYPE else 0
            tf.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)

        add("repo-sha/app/main.py", b"print(1)")
        add("repo-sha/../../escape.py", b"boom")
        add("repo-sha/app/link", kind=tarfile.SYMTYPE, link="/etc/passwd")
        add("repo-sha/app/hard", kind=tarfile.LNKTYPE, link="repo-sha/app/main.py")
        add("repo-sha/app/dev", kind=tarfile.CHRTYPE)
    dest = tmp_path / "out"
    dest.mkdir()

    report = extract_tar(archive, dest, strip_components=1)

    assert (dest / "app" / "main.py").read_bytes() == b"print(1)"
    assert sorted(p.name for p in (dest / "app").iterdir()) == ["main.py"]
    assert report.skipped["not_regular_file"] == 3
    assert report.skipped["unsafe_path"] == 1


def test_corrupt_archive_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "corrupt.zip"
    archive.write_bytes(b"PK\x03\x04 definitely not a zip")
    with pytest.raises(ArchiveRejected):
        extract_zip(archive, tmp_path)


class TestWorkspace:
    @pytest.mark.parametrize("path", ["../outside", "/etc/passwd", "a/../../x", "C:/x", "a\x00"])
    def test_traversal_is_rejected(self, tmp_path: Path, path: str) -> None:
        with pytest.raises(SecurityRejection):
            Workspace(tmp_path).read_text(path)

    def test_symlinks_are_not_followed(self, tmp_path: Path) -> None:
        secret = tmp_path / "secret.txt"
        secret.write_text("token")
        root = tmp_path / "repo"
        root.mkdir()
        try:
            (root / "requirements.txt").symlink_to(secret)
            (root / "linked_dir").symlink_to(tmp_path, target_is_directory=True)
        except OSError:
            pytest.skip("creating symlinks requires extra privileges on this platform")
        workspace = Workspace(root)
        assert list(workspace.iter_files()) == []
        with pytest.raises(SecurityRejection):
            workspace.read_text("requirements.txt")

    def test_oversized_files_are_not_read(self, tmp_path: Path) -> None:
        (tmp_path / "big.txt").write_bytes(b"x" * 101)
        assert Workspace(tmp_path, max_file_bytes=100).read_text("big.txt") is None

    def test_file_count_limit(self, tmp_path: Path) -> None:
        for i in range(5):
            (tmp_path / f"{i}.py").write_text("")
        with pytest.raises(WorkspaceTooLarge):
            list(Workspace(tmp_path, max_files=3).iter_files())

    def test_odd_but_legal_filenames_are_data(self, tmp_path: Path) -> None:
        name = "<script>alert(1)</script>.py"
        try:
            (tmp_path / name).write_text("x = 1")
        except OSError:
            pytest.skip("filesystem does not allow this name")
        assert list(Workspace(tmp_path).iter_files()) == [name]
