# ADR-0007: Static analysis only — repository and dependency code is never executed

- Status: Accepted
- Date: 2026-10-06

## Problem

Determining reachability could use dynamic techniques (running tests, tracing, fuzzing) which are
more precise for some questions. But Sieve processes untrusted repositories on shared infrastructure.

## Alternatives

- **Dynamic analysis in sandboxes** (gVisor/Firecracker) — better precision for executed paths, but
  only covers paths the tests exercise, requires installing dependencies (running build backends and
  `setup.py`), and makes Sieve a remote-code-execution service with a sandbox as the only barrier.
- **Static analysis** — chosen.

## Decision

- Repository files are read and parsed with `ast.parse`; nothing is imported or executed.
- Dependency source comes from the exact released PyPI artifact (wheel preferred), verified against
  PyPI's published SHA-256, extracted with archive-safety checks, and parsed. Never installed.
- Unpinned dependencies are **not** resolved (resolution can execute `setup.py`); they produce
  `needs_review / version_unpinned`.
- No subprocess is ever invoked with repository-derived arguments. The only subprocess is Sieve's own
  parser worker, receiving file paths inside the workspace.

## Trade-offs

- Python's dynamism (reflection, monkey-patching, plugin loading) limits precision. Sieve reports
  these cases as `needs_review` rather than guessing.
- Native extensions (C code in wheels) are opaque; vulnerabilities inside them can only be matched at
  the Python API boundary that calls into them.

## 10× scale

Unchanged; static analysis is embarrassingly parallel per repository and cacheable per package.

## Enterprise

An optional, customer-hosted runtime-evidence agent could later *add* evidence (e.g. "this function
was executed in production"), but would never be required for a verdict.
