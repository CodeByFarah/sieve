"""Fix-commit diffs: fetched through the GitHub API (never by following advisory URLs), size-capped,
and reduced to the set of functions the fix touched."""

import re
from collections import defaultdict
from dataclasses import dataclass, field

import httpx

from sieve.advisories.osv import FixCommit
from sieve.core.http import raise_for_status

MAX_DIFF_BYTES = 300_000
_FILE = re.compile(r"^diff --git a/(\S+) b/(\S+)")
_HUNK_CONTEXT = re.compile(r"^@@ [^@]* @@\s*(?:async\s+)?(?:def|class)\s+(\w+)")
_CHANGED_DEF = re.compile(r"^[+-](?![+-])\s*(?:async\s+)?(?:def|class)\s+(\w+)")
_SOURCE_PREFIXES = ("lib3/", "lib/", "src/")


@dataclass
class Touched:
    by_file: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    @property
    def functions(self) -> set[str]:
        return {name for names in self.by_file.values() for name in names}


def touched(diff: str) -> Touched:
    """Function and class names whose bodies or signatures the diff changes (Python files only)."""
    result = Touched()
    current: str | None = None
    for line in diff.splitlines():
        file_match = _FILE.match(line)
        if file_match:
            path = file_match.group(2)
            current = path if path.endswith(".py") and "/test" not in f"/{path}" else None
            continue
        if current is None:
            continue
        for pattern in (_HUNK_CONTEXT, _CHANGED_DEF):
            match = pattern.match(line)
            if match:
                result.by_file[current].add(match.group(1))
    return result


def module_for(path: str) -> str | None:
    for prefix in _SOURCE_PREFIXES:
        if path.startswith(prefix):
            path = path[len(prefix) :]
            break
    if not path.endswith(".py"):
        return None
    parts = path[:-3].split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) if parts and all(p.isidentifier() for p in parts) else None


def fetch_commit_diff(
    client: httpx.Client, commit: FixCommit, api_url: str = "https://api.github.com"
) -> str | None:
    response = client.get(
        f"{api_url}/repos/{commit.owner}/{commit.repo}/commits/{commit.sha}",
        headers={"Accept": "application/vnd.github.diff", "X-GitHub-Api-Version": "2022-11-28"},
    )
    if response.status_code == 404:
        return None
    raise_for_status(response)
    text = response.text
    return text if len(text.encode()) <= MAX_DIFF_BYTES else text[:MAX_DIFF_BYTES]
