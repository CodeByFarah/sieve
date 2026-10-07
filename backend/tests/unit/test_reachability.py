"""Reachability verdicts on small, hand-checked programs.

Each test builds an application and fake dependency distributions on disk, runs the real engine
(discovery → indexing → call graph → verdict rules) and checks the verdict, confidence, reason and
evidence path.
"""

import textwrap
from pathlib import Path

import pytest

from sieve.analysis.engine import DependencyPin, ReachabilityEngine
from sieve.analysis.reachability import Outcome, SymbolInput, decide
from sieve.analysis.sandbox import InProcessIndexer
from sieve.core.errors import ExternalServiceError
from sieve.core.workspace import Workspace
from sieve.db.enums import Confidence, SymbolOrigin, Verdict
from sieve.packages.pypi import Artifact, FetchedSource

ADVISORY = SymbolOrigin.ADVISORY


def write_tree(root: Path, files: dict[str, str]) -> Path:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content), encoding="utf-8")
    return root


class FakeSources:
    def __init__(self, root: Path, dists: dict[str, dict[str, str]]) -> None:
        self.root = root
        self.dists = dists
        self.fetched: list[str] = []

    def fetch(self, name: str, version: str) -> FetchedSource:
        if name not in self.dists:
            raise ExternalServiceError(f"{name} unavailable")
        self.fetched.append(name)
        tree = write_tree(self.root / f"{name}-{version}", self.dists[name])
        artifact = Artifact(
            f"{name}-{version}.whl", "https://files.pythonhosted.org/x", "0" * 64, "wheel"
        )
        return FetchedSource(tree, f"{name}-{version}", artifact)


YAML_DIST = {
    "yaml/__init__.py": """
        from .loader import FullLoader, SafeLoader
        def load(stream, Loader=None):
            loader = Loader(stream)
            return loader.get_single_data()
        def safe_load(stream):
            return load(stream, SafeLoader)
    """,
    "yaml/loader.py": """
        class SafeLoader:
            def __init__(self, stream): self.stream = stream
            def get_single_data(self): return None
        class FullLoader(SafeLoader):
            pass
    """,
}


def analyse(
    tmp_path: Path,
    app: dict[str, str],
    dists: dict[str, dict[str, str]],
    package: str,
    symbols: list[str],
    *,
    pins: dict[str, str | None] | None = None,
    origin: SymbolOrigin = ADVISORY,
) -> Outcome:
    workspace = Workspace(write_tree(tmp_path / "app", app))
    sources = FakeSources(tmp_path / "dists", dists)
    engine = ReachabilityEngine(sources, InProcessIndexer())
    pins = pins if pins is not None else dict.fromkeys(dists, "1.0")
    result = engine.analyze(
        workspace, [DependencyPin(name, version) for name, version in pins.items()]
    )
    return decide(result.context, package, [SymbolInput(s, origin) for s in symbols])


def reason(outcome: Outcome) -> str:
    return str(outcome.reasons[0]["code"])


def symbols_on_path(outcome: Outcome) -> list[str]:
    return [step["symbol"] for step in outcome.paths[0]["steps"]]


FLASK_APP = {
    "app/__init__.py": "",
    "app/routes.py": """
        from flask import Flask, request
        from app.parser import parse_config
        app = Flask(__name__)

        @app.route("/upload", methods=["POST"])
        def upload():
            return parse_config(request.data)
    """,
    "app/parser.py": """
        import yaml
        def parse_config(data):
            return yaml.load(data, Loader=yaml.FullLoader)
    """,
}
FLASK_DIST = {
    "flask/__init__.py": "from .app import Flask\nrequest = None\n",
    "flask/app.py": "class Flask:\n    def __init__(self, name): pass\n    def route(self, rule, **kw):\n        return lambda f: f\n",
}


def test_direct_call_from_http_route_is_reachable_with_evidence(tmp_path: Path) -> None:
    outcome = analyse(
        tmp_path, FLASK_APP, {"pyyaml": YAML_DIST, "flask": FLASK_DIST}, "pyyaml", ["yaml.load"]
    )

    assert outcome.verdict is Verdict.REACHABLE
    assert outcome.confidence is Confidence.HIGH
    path = outcome.paths[0]
    assert path["entrypoint_kind"] == "http_route"
    assert symbols_on_path(outcome) == ["app.routes.upload", "app.parser.parse_config", "yaml.load"]
    first = path["steps"][0]
    assert first["file"] == "app/routes.py"
    assert first["call"]["line"] == 8
    assert path["steps"][-1]["package"] == "pyyaml"
    assert outcome.symbols[0]["status"] == "found"


def test_alias_imports_resolve(tmp_path: Path) -> None:
    app = {"main.py": "from yaml import load as parse\n\ndef run(x):\n    return parse(x)\n"}
    outcome = analyse(tmp_path, app, {"pyyaml": YAML_DIST}, "pyyaml", ["yaml.load"])
    assert outcome.verdict is Verdict.REACHABLE


def test_imported_package_with_uncalled_symbol_is_not_reached(tmp_path: Path) -> None:
    app = {"main.py": "import yaml\n\ndef run(x):\n    return yaml.safe_load(x)\n"}
    outcome = analyse(tmp_path, app, {"pyyaml": YAML_DIST}, "pyyaml", ["yaml.loader.FullLoader"])
    assert outcome.verdict is Verdict.NOT_REACHED
    assert outcome.confidence is Confidence.HIGH
    assert reason(outcome) == "no_path"


def test_safe_load_internally_calls_load_so_load_is_reachable(tmp_path: Path) -> None:
    """Transitive calls inside a dependency count: safe_load → load."""
    app = {"main.py": "import yaml\n\ndef run(x):\n    return yaml.safe_load(x)\n"}
    outcome = analyse(tmp_path, app, {"pyyaml": YAML_DIST}, "pyyaml", ["yaml.load"])
    assert outcome.verdict is Verdict.REACHABLE
    assert symbols_on_path(outcome) == ["main.run", "yaml.safe_load", "yaml.load"]


def test_package_never_imported_is_not_reached(tmp_path: Path) -> None:
    app = {"main.py": "import json\n\ndef run(x):\n    return json.loads(x)\n"}
    sources_dists = {"pyyaml": YAML_DIST}
    outcome = analyse(tmp_path, app, sources_dists, "pyyaml", ["yaml.load"])
    assert outcome.verdict is Verdict.NOT_REACHED
    assert reason(outcome) == "package_not_imported"


def test_vulnerable_code_reached_through_another_dependency(tmp_path: Path) -> None:
    app = {
        "client.py": "import httplib_like\n\ndef fetch(url):\n    return httplib_like.get(url)\n"
    }
    dists = {
        "httplib-like": {
            "httplib_like/__init__.py": "from .api import get\n",
            "httplib_like/api.py": "from transport_like.pool import Pool\n\ndef get(url):\n    pool = Pool()\n    return pool.urlopen(url)\n",
        },
        "transport-like": {
            "transport_like/__init__.py": "",
            "transport_like/pool.py": "class Pool:\n    def urlopen(self, url):\n        return self._make(url)\n    def _make(self, url):\n        return url\n",
        },
    }
    outcome = analyse(tmp_path, app, dists, "transport-like", ["transport_like.pool.Pool.urlopen"])

    assert outcome.verdict is Verdict.REACHABLE
    assert outcome.confidence is Confidence.MEDIUM  # the last hop needed receiver-type inference
    assert symbols_on_path(outcome) == [
        "client.fetch",
        "httplib_like.api.get",
        "transport_like.pool.Pool.urlopen",
    ]


def test_self_methods_and_attribute_types(tmp_path: Path) -> None:
    app = {
        "service.py": """
            import yaml
            class Parser:
                def parse(self, data):
                    return yaml.load(data)
            class Service:
                def __init__(self):
                    self.parser = Parser()
                def handle(self, data):
                    return self.parser.parse(data)
        """
    }
    outcome = analyse(tmp_path, app, {"pyyaml": YAML_DIST}, "pyyaml", ["yaml.load"])
    assert outcome.verdict is Verdict.REACHABLE
    assert symbols_on_path(outcome)[-2:] == ["service.Parser.parse", "yaml.load"]


def test_unknown_receiver_with_matching_method_name_needs_review(tmp_path: Path) -> None:
    app = {
        "client.py": """
            import transport_like
            def fetch(factory, url):
                conn = factory()
                return conn.urlopen(url)
        """
    }
    dists = {
        "transport-like": {
            "transport_like/__init__.py": "from .pool import Pool\n",
            "transport_like/pool.py": "class Pool:\n    def urlopen(self, url):\n        return url\n",
        }
    }
    outcome = analyse(tmp_path, app, dists, "transport-like", ["transport_like.pool.Pool.urlopen"])

    assert outcome.verdict is Verdict.NEEDS_REVIEW
    assert reason(outcome) == "dynamic_dispatch"
    path = outcome.paths[0]
    assert "name_match" in path["edge_kinds"]
    assert symbols_on_path(outcome) == ["client.fetch", "transport_like.pool.Pool.urlopen"]
    assert path["steps"][0]["call"] == {
        "file": "client.py",
        "line": 5,
        "col": 11,
        "edge": "name_match",
    }


def test_super_calls_resolve_through_base_classes(tmp_path: Path) -> None:
    dists = {
        "pyyaml": YAML_DIST,
        "framework": {
            "framework/__init__.py": "import yaml\nclass Base:\n    def handle(self, data):\n        return yaml.load(data)\n"
        },
    }
    app = {
        "main.py": """
            from framework import Base
            class Child(Base):
                def handle(self, data):
                    return super().handle(data)
        """
    }
    outcome = analyse(tmp_path, app, dists, "pyyaml", ["yaml.load"])
    assert outcome.verdict is Verdict.REACHABLE
    assert outcome.confidence is Confidence.MEDIUM  # super() is resolved by inference
    assert symbols_on_path(outcome) == ["main.Child.handle", "framework.Base.handle", "yaml.load"]


def test_bound_method_aliases_resolve(tmp_path: Path) -> None:
    dists = {
        "pyjwt": {
            "jwt/__init__.py": "from .api_jwt import decode\n",
            "jwt/api_jwt.py": "class PyJWT:\n    def decode(self, token):\n        return token\n\n_jwt = PyJWT()\ndecode = _jwt.decode\n",
        }
    }
    app = {"auth.py": "import jwt\n\ndef check(token):\n    return jwt.decode(token)\n"}
    outcome = analyse(tmp_path, app, dists, "pyjwt", ["jwt.decode"])
    assert outcome.verdict is Verdict.REACHABLE
    assert outcome.symbols[0]["canonical"] == "jwt.api_jwt.PyJWT.decode"


def test_dotted_string_in_app_counts_as_a_potential_import(tmp_path: Path) -> None:
    """A module-level advisory symbol (the whole module is affected) reached only by name."""
    app = {"settings.py": "CONFIG_OBJECT = 'yaml.loader'\n"}
    outcome = analyse(tmp_path, app, {"pyyaml": YAML_DIST}, "pyyaml", ["yaml.loader"])
    assert outcome.verdict is Verdict.NEEDS_REVIEW
    assert reason(outcome) == "dynamic_import"


def test_function_registered_as_a_value_is_reference_only(tmp_path: Path) -> None:
    app = {"main.py": "import templating\n\ndef render(t):\n    return templating.render(t)\n"}
    dists = {
        "templating": {
            "templating/__init__.py": "from .filters import FILTERS\n\ndef render(t):\n    return FILTERS[t]('x')\n",
            "templating/filters.py": "def do_urlize(value):\n    return value\n\nFILTERS = {'urlize': do_urlize}\n",
        }
    }
    outcome = analyse(tmp_path, app, dists, "templating", ["templating.filters.do_urlize"])

    assert outcome.verdict is Verdict.NEEDS_REVIEW
    assert reason(outcome) == "reference_only"
    assert outcome.paths[0]["steps"][-1]["symbol"] == "templating.filters.do_urlize"


def test_dynamic_import_prevents_package_not_imported_conclusion(tmp_path: Path) -> None:
    app = {
        "plugins.py": "import importlib\n\ndef load(name):\n    return importlib.import_module(name)\n"
    }
    outcome = analyse(tmp_path, app, {"pyyaml": YAML_DIST}, "pyyaml", ["yaml.load"])
    assert outcome.verdict is Verdict.NEEDS_REVIEW
    assert reason(outcome) == "dynamic_import"


def test_literal_dynamic_import_is_a_normal_import(tmp_path: Path) -> None:
    app = {
        "plugins.py": "import importlib\n\ndef load(x):\n    return importlib.import_module('yaml').load(x)\n"
    }
    outcome = analyse(tmp_path, app, {"pyyaml": YAML_DIST}, "pyyaml", ["yaml.loader.FullLoader"])
    assert outcome.verdict is Verdict.NOT_REACHED
    assert reason(outcome) == "no_path"


def test_unpinned_and_unavailable_packages_need_review(tmp_path: Path) -> None:
    app = {"main.py": "import yaml\n"}
    unpinned = analyse(
        tmp_path / "a", app, {"pyyaml": YAML_DIST}, "pyyaml", ["yaml.load"], pins={"pyyaml": None}
    )
    assert reason(unpinned) == "version_unpinned"
    unavailable = analyse(tmp_path / "b", app, {}, "pyyaml", ["yaml.load"], pins={"pyyaml": "1.0"})
    assert reason(unavailable) == "package_source_unavailable"
    assert unavailable.verdict is Verdict.NEEDS_REVIEW


def test_unavailable_imported_dependency_blocks_not_imported_conclusions(tmp_path: Path) -> None:
    app = {"main.py": "import mystery\n"}
    outcome = analyse(
        tmp_path,
        app,
        {"pyyaml": YAML_DIST},
        "pyyaml",
        ["yaml.load"],
        pins={"pyyaml": "1.0", "mystery": "1.0"},
    )
    assert reason(outcome) == "incomplete_import_graph"


def test_symbols_missing_from_installed_source_are_not_verified(tmp_path: Path) -> None:
    app = {"main.py": "import yaml\n\ndef run(x):\n    return yaml.load(x)\n"}
    outcome = analyse(tmp_path, app, {"pyyaml": YAML_DIST}, "pyyaml", ["yaml.does_not_exist"])
    assert outcome.verdict is Verdict.NEEDS_REVIEW
    assert reason(outcome) == "no_verified_symbols"
    assert outcome.symbols == [
        {"requested": "yaml.does_not_exist", "origin": "advisory", "status": "not_found"}
    ]
    assert outcome.paths, "context path showing where the package is imported"


def test_test_files_are_not_application_code(tmp_path: Path) -> None:
    app = {
        "main.py": "import yaml\n\ndef run(x):\n    return yaml.safe_load(x)\n",
        "tests/test_main.py": "import yaml\n\ndef test_it():\n    yaml.load('a')\n",
        "test_other.py": "import yaml\nyaml.load('a')\n",
    }
    outcome = analyse(tmp_path, app, {"pyyaml": YAML_DIST}, "pyyaml", ["yaml.loader.FullLoader"])
    assert outcome.verdict is Verdict.NOT_REACHED


def test_unparseable_application_file_blocks_not_reached(tmp_path: Path) -> None:
    app = {"main.py": "import yaml\nyaml.safe_load('a')\n", "broken.py": "def oops(:\n"}
    outcome = analyse(tmp_path, app, {"pyyaml": YAML_DIST}, "pyyaml", ["yaml.loader.FullLoader"])
    assert outcome.verdict is Verdict.NEEDS_REVIEW
    assert reason(outcome) == "parse_failure"


def test_class_symbol_reached_by_instantiation(tmp_path: Path) -> None:
    app = {
        "main.py": "from yaml.loader import FullLoader\n\ndef run(s):\n    return FullLoader(s)\n"
    }
    outcome = analyse(tmp_path, app, {"pyyaml": YAML_DIST}, "pyyaml", ["yaml.FullLoader"])
    assert outcome.verdict is Verdict.REACHABLE
    assert outcome.symbols[0]["canonical"] == "yaml.loader.FullLoader"


def test_ai_proposed_symbols_lower_confidence(tmp_path: Path) -> None:
    outcome = analyse(
        tmp_path,
        FLASK_APP,
        {"pyyaml": YAML_DIST, "flask": FLASK_DIST},
        "pyyaml",
        ["yaml.load"],
        origin=SymbolOrigin.AI,
    )
    assert outcome.verdict is Verdict.REACHABLE
    assert outcome.confidence is Confidence.MEDIUM


def test_star_imports_and_main_guard(tmp_path: Path) -> None:
    app = {
        "cli.py": """
            from yaml import *
            if __name__ == "__main__":
                load(open("config.yml"))
        """
    }
    outcome = analyse(tmp_path, app, {"pyyaml": YAML_DIST}, "pyyaml", ["yaml.load"])
    assert outcome.verdict is Verdict.REACHABLE
    assert outcome.paths[0]["entrypoint_kind"] == "main"


def test_not_imported_dependencies_are_never_parsed(tmp_path: Path) -> None:
    workspace = Workspace(write_tree(tmp_path / "app", {"main.py": "import yaml\n"}))
    sources = FakeSources(
        tmp_path / "dists", {"pyyaml": YAML_DIST, "unused": {"unused/__init__.py": "x = ("}}
    )
    result = ReachabilityEngine(sources, InProcessIndexer()).analyze(
        workspace, [DependencyPin("pyyaml", "1.0"), DependencyPin("unused", "2.0")]
    )
    assert result.stats.distributions_indexed == 1
    assert result.stats.parse_failures == 0


@pytest.mark.parametrize(
    "source",
    [
        "x = " + "(" * 1000 + ")" * 1000,
        "def f(:\n",
        "\x00",
        "a" * 10 + " = [" + "1," * 100_000 + "]",
    ],
    ids=["deep-nesting", "syntax-error", "nul-byte", "huge-literal"],
)
def test_pathological_sources_never_crash_the_indexer(source: str) -> None:
    from sieve.analysis.indexer import index_module

    summary = index_module("m", "m.py", source, False)
    assert summary.name == "m"
