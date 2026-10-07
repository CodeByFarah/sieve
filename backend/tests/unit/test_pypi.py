import hashlib
import io
import zipfile
from pathlib import Path

import httpx
import pytest
import respx

from sieve.core.http import DigestMismatch, build_client
from sieve.packages.pypi import NoUsableArtifact, PypiSourceCache, choose_artifact


def wheel_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as wheel:
        wheel.writestr("demo/__init__.py", "def load(x):\n    return x\n")
        wheel.writestr("demo/data.bin", b"\x00\x01")
        wheel.writestr("demo-1.0.dist-info/METADATA", "Name: demo\n")
        wheel.writestr("../escape.py", "boom")
    return buffer.getvalue()


def entry(
    filename: str, packagetype: str, digest: str = "ab" * 32, host: str = "files.pythonhosted.org"
) -> dict[str, object]:
    return {
        "filename": filename,
        "packagetype": packagetype,
        "url": f"https://{host}/packages/{filename}",
        "digests": {"sha256": digest},
    }


def test_artifact_preference_pure_wheel_then_platform_wheel_then_sdist() -> None:
    files = [
        entry("demo-1.0.tar.gz", "sdist"),
        entry("demo-1.0-cp313-cp313-manylinux.whl", "bdist_wheel"),
        entry("demo-1.0-py3-none-any.whl", "bdist_wheel"),
        entry("demo-1.0.exe", "bdist_wininst"),
    ]
    assert choose_artifact(files).filename == "demo-1.0-py3-none-any.whl"  # type: ignore[union-attr]
    assert choose_artifact(files[:2]).filename.endswith("manylinux.whl")  # type: ignore[union-attr]
    assert choose_artifact(files[:1]).kind == "sdist"  # type: ignore[union-attr]


def test_python2_wheels_are_never_chosen_and_newest_cpython_wins() -> None:
    files = [
        entry("PyYAML-5.3-cp27-cp27m-win32.whl", "bdist_wheel"),
        entry("PyYAML-5.3-cp36-cp36m-win32.whl", "bdist_wheel"),
        entry("PyYAML-5.3-cp38-cp38-win_amd64.whl", "bdist_wheel"),
        entry("PyYAML-5.3.tar.gz", "sdist"),
    ]
    assert choose_artifact(files).filename == "PyYAML-5.3-cp38-cp38-win_amd64.whl"  # type: ignore[union-attr]
    only_py2 = [entry("x-1.0-py2-none-any.whl", "bdist_wheel"), entry("x-1.0.tar.gz", "sdist")]
    assert choose_artifact(only_py2).kind == "sdist"  # type: ignore[union-attr]


def test_artifacts_from_other_hosts_or_yanked_are_ignored() -> None:
    assert (
        choose_artifact([entry("demo-1.0-py3-none-any.whl", "bdist_wheel", host="evil.example")])
        is None
    )
    yanked = {**entry("demo-1.0-py3-none-any.whl", "bdist_wheel"), "yanked": True}
    assert choose_artifact([yanked]) is None


@respx.mock
def test_fetch_extracts_python_files_only_and_caches(tmp_path: Path) -> None:
    content = wheel_bytes()
    digest = hashlib.sha256(content).hexdigest()
    respx.get("https://pypi.org/pypi/demo/1.0/json").mock(
        return_value=httpx.Response(
            200, json={"urls": [entry("demo-1.0-py3-none-any.whl", "bdist_wheel", digest)]}
        )
    )
    download = respx.get("https://files.pythonhosted.org/packages/demo-1.0-py3-none-any.whl").mock(
        return_value=httpx.Response(200, content=content)
    )
    with build_client() as client:
        cache = PypiSourceCache(tmp_path, client)
        fetched = cache.fetch("demo", "1.0")
        again = cache.fetch("demo", "1.0")

    assert sorted(
        p.relative_to(fetched.root).as_posix() for p in fetched.root.rglob("*") if p.is_file()
    ) == ["demo/__init__.py"]
    assert not (tmp_path / "escape.py").exists()
    assert again.root == fetched.root
    assert download.call_count == 1


@respx.mock
def test_tampered_artifact_is_rejected(tmp_path: Path) -> None:
    respx.get("https://pypi.org/pypi/demo/1.0/json").mock(
        return_value=httpx.Response(
            200, json={"urls": [entry("demo-1.0-py3-none-any.whl", "bdist_wheel")]}
        )
    )
    respx.get("https://files.pythonhosted.org/packages/demo-1.0-py3-none-any.whl").mock(
        return_value=httpx.Response(200, content=wheel_bytes())
    )
    with build_client() as client, pytest.raises(DigestMismatch):
        PypiSourceCache(tmp_path, client).fetch("demo", "1.0")


@respx.mock
def test_release_without_artifacts(tmp_path: Path) -> None:
    respx.get("https://pypi.org/pypi/demo/1.0/json").mock(
        return_value=httpx.Response(200, json={"urls": []})
    )
    with build_client() as client, pytest.raises(NoUsableArtifact):
        PypiSourceCache(tmp_path, client).fetch("demo", "1.0")
