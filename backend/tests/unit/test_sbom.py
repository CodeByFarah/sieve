import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sieve.core.workspace import Workspace
from sieve.db.enums import ManifestStatus
from sieve.sbom.cyclonedx import SbomSubject, build_cyclonedx
from sieve.sbom.inventory import build_inventory
from sieve.sbom.models import DeclaredDependency, pypi_purl
from sieve.sbom.requirements import parse_requirements
from sieve.schemas import cyclonedx_errors


def write(root: Path, files: dict[str, str]) -> Workspace:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return Workspace(root)


def deps(workspace: Workspace) -> dict[str, DeclaredDependency]:
    return {d.name: d for d in build_inventory(workspace).dependencies}


class TestRequirements:
    def parse(self, text: str, extra: dict[str, str] | None = None) -> list[DeclaredDependency]:
        files = {"requirements.txt": text, **(extra or {})}
        return parse_requirements("requirements.txt", files.get).dependencies

    def test_pins_extras_markers_and_normalisation(self) -> None:
        result = self.parse(
            "PyYAML==5.3  # comment\n"
            "requests[socks]==2.19.1 ; python_version >= '3.6'\n"
            "Flask>=1.0,<2\n"
            "Jinja2===2.10\n"
            "django==3.2.*\n"
        )
        by_name = {d.name: d for d in result}
        assert by_name["pyyaml"].version == "5.3"
        assert by_name["requests"].version == "2.19.1"
        assert by_name["flask"].version is None
        assert by_name["flask"].constraint == "<2,>=1.0"
        assert by_name["jinja2"].version == "2.10"
        assert by_name["django"].version is None  # wildcard is not a pin

    def test_hashes_and_continuations(self) -> None:
        result = self.parse("urllib3==1.24.1 \\\n    --hash=sha256:aaa \\\n    --hash=sha256:bbb\n")
        assert [(d.name, d.version) for d in result] == [("urllib3", "1.24.1")]

    def test_includes_stay_inside_the_workspace(self) -> None:
        result = self.parse(
            "-r base.txt\n-r ../../etc/passwd\n",
            {"base.txt": "click==7.0\n"},
        )
        assert [(d.name, d.version) for d in result] == [("click", "7.0")]

    def test_include_cycles_terminate(self) -> None:
        files = {"requirements.txt": "-r a.txt\nsix==1.0\n", "a.txt": "-r requirements.txt\n"}
        report = parse_requirements("requirements.txt", files.get)
        assert [d.name for d in report.dependencies] == ["six"]
        assert report.detail is not None
        assert "cycle" in report.detail

    def test_urls_paths_and_editables_are_reported_not_fetched(self) -> None:
        report = parse_requirements(
            "requirements.txt",
            {
                "requirements.txt": "-e .\n./local-pkg\ngit+https://example.com/x.git\n"
                "pkg @ https://example.com/pkg.whl\nok==1.0\n"
            }.get,
        )
        assert [d.name for d in report.dependencies] == ["ok"]
        assert report.detail is not None
        assert "editable" in report.detail
        assert "non-index" in report.detail

    def test_pip_compile_via_annotations_mark_transitive_dependencies(self) -> None:
        result = self.parse(
            "flask==1.0\n    # via -r requirements.in\nwerkzeug==0.15\n    # via flask\n"
        )
        by_name = {d.name: d for d in result}
        assert by_name["flask"].is_direct
        assert not by_name["werkzeug"].is_direct


class TestLockfiles:
    def test_poetry_lock_with_pyproject_direct_dependencies(self, tmp_path: Path) -> None:
        workspace = write(
            tmp_path,
            {
                "poetry.lock": '[[package]]\nname = "Flask"\nversion = "1.0"\n\n'
                '[[package]]\nname = "Werkzeug"\nversion = "0.15"\n',
                "pyproject.toml": '[tool.poetry.dependencies]\npython = "^3.8"\nflask = "^1.0"\n',
            },
        )
        result = deps(workspace)
        assert result["flask"].version == "1.0"
        assert result["flask"].is_direct
        assert not result["werkzeug"].is_direct

    def test_uv_lock_skips_the_project_itself(self, tmp_path: Path) -> None:
        workspace = write(
            tmp_path,
            {
                "uv.lock": '[[package]]\nname = "app"\nversion = "0.1"\nsource = { editable = "." }\n'
                'dependencies = [{ name = "pyyaml" }]\n\n'
                '[[package]]\nname = "pyyaml"\nversion = "6.0.1"\n'
                'source = { registry = "https://pypi.org/simple" }\n',
            },
        )
        result = deps(workspace)
        assert set(result) == {"pyyaml"}
        assert result["pyyaml"].is_direct

    def test_pipfile_lock(self, tmp_path: Path) -> None:
        workspace = write(
            tmp_path,
            {
                "Pipfile.lock": json.dumps(
                    {
                        "default": {"requests": {"version": "==2.19.1"}},
                        "develop": {"pytest": {"version": "==7.0.0"}},
                    }
                ),
                "Pipfile": '[packages]\nrequests = "*"\n',
            },
        )
        result = deps(workspace)
        assert result["requests"].version == "2.19.1"
        assert result["requests"].is_direct
        assert result["pytest"].version == "7.0.0"

    def test_pyproject_without_lock_is_unpinned(self, tmp_path: Path) -> None:
        workspace = write(
            tmp_path,
            {"pyproject.toml": '[project]\nname="x"\ndependencies=["flask>=2", "six==1.16.0"]\n'},
        )
        result = deps(workspace)
        assert result["flask"].version is None
        assert result["six"].version == "1.16.0"


class TestInventory:
    def test_unsupported_and_invalid_manifests_are_reported(self, tmp_path: Path) -> None:
        workspace = write(
            tmp_path,
            {
                "setup.py": "raise SystemExit('never executed')",
                "environment.yml": "dependencies: []",
                "svc/poetry.lock": "this is [ not toml",
            },
        )
        statuses = {m.path: m.status for m in build_inventory(workspace).manifests}
        assert statuses == {
            "environment.yml": ManifestStatus.UNSUPPORTED,
            "setup.py": ManifestStatus.UNSUPPORTED,
            "svc/poetry.lock": ManifestStatus.ERROR,
        }

    def test_vendored_and_virtualenv_directories_are_ignored(self, tmp_path: Path) -> None:
        workspace = write(
            tmp_path,
            {
                "requirements.txt": "a==1\n",
                ".venv/lib/requirements.txt": "b==1\n",
                "node_modules/x/requirements.txt": "c==1\n",
            },
        )
        assert set(deps(workspace)) == {"a"}

    def test_pins_win_over_unpinned_declarations_and_directness_merges(
        self, tmp_path: Path
    ) -> None:
        workspace = write(
            tmp_path,
            {
                "requirements.txt": "flask==1.0\n    # via jinja\n",
                "requirements-dev.txt": "flask\n",
                "tools/requirements.txt": "flask==1.0\n",
            },
        )
        inventory = build_inventory(workspace)
        assert [(d.name, d.version, d.is_direct) for d in inventory.dependencies] == [
            ("flask", "1.0", True)
        ]

    def test_compiled_txt_supersedes_in_file(self, tmp_path: Path) -> None:
        workspace = write(
            tmp_path, {"requirements.in": "flask\n", "requirements.txt": "flask==1.0\n"}
        )
        assert [m.path for m in build_inventory(workspace).manifests] == ["requirements.txt"]


class TestCycloneDx:
    SUBJECT = SbomSubject(repository="acme/app", commit_sha="a" * 40, tool_version="0.1.0")
    WHEN = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)

    def sbom(self, tmp_path: Path) -> bytes:
        workspace = write(
            tmp_path,
            {"requirements.txt": "flask==1.0\npyyaml==5.3\nlocal==1.0+abc\nunpinned>=1\n"},
        )
        return build_cyclonedx(build_inventory(workspace), self.SUBJECT, self.WHEN)

    def test_is_valid_cyclonedx_1_6(self, tmp_path: Path) -> None:
        document = json.loads(self.sbom(tmp_path))
        assert cyclonedx_errors(document) == []
        assert document["metadata"]["timestamp"] == "2026-10-06T12:00:00Z"

    def test_is_byte_identical_for_identical_input(self, tmp_path: Path) -> None:
        first = self.sbom(tmp_path / "one")
        second = self.sbom(tmp_path / "two")
        assert first == second

    def test_components_purls_and_unpinned_entries(self, tmp_path: Path) -> None:
        document = json.loads(self.sbom(tmp_path))
        purls = [c["purl"] for c in document["components"]]
        assert purls == sorted(purls)
        assert "pkg:pypi/local@1.0%2Babc" in purls
        unpinned = next(c for c in document["components"] if c["name"] == "unpinned")
        assert "version" not in unpinned

    def test_schema_validation_catches_broken_documents(self) -> None:
        assert cyclonedx_errors(
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{}]}
        )


@pytest.mark.parametrize(
    ("name", "version", "purl"),
    [("PyYAML", "5.3", "pkg:pypi/pyyaml@5.3"), ("zope.interface", None, "pkg:pypi/zope-interface")],
)
def test_purl(name: str, version: str | None, purl: str) -> None:
    assert pypi_purl(name, version) == purl
