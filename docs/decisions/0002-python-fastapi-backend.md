# ADR-0002: Python + FastAPI for the backend

- Status: Accepted
- Date: 2026-10-06

## Problem

The core of Sieve is static analysis of **Python** code. The backend language determines whether that
analysis can use the reference parser for the target language or a reimplementation.

## Alternatives

- **Go / Rust backend** with a Python analysis sidecar — faster HTTP layer, but two languages,
  serialisation boundaries, and the analysis engine (the product's heart) becomes a second-class
  component.
- **Go/Rust/TS with a third-party Python parser** (tree-sitter) — loses exact CPython grammar
  fidelity for new syntax, and loses `packaging` (the reference PEP 440 implementation).
- **Python with Django** — batteries included, but its ORM and sync-first model are a poorer fit for
  an API-only service with typed schemas.
- **Python with FastAPI** — chosen.

## Decision

Python 3.13 (container runtime and CI), FastAPI, Pydantic v2, SQLAlchemy 2.x, Alembic; uv for
dependency management with a committed lockfile.

## Why

- `ast` *is* CPython's parser: the analysis sees exactly the syntax tree the interpreter would.
- `packaging` provides PEP 440 versions and specifiers — the same semantics pip uses.
- One language across API, workers and analysis; one test runner; one type checker (mypy strict).
- FastAPI + Pydantic give request validation and an OpenAPI contract from which the frontend types are
  generated.

## Trade-offs

- CPU-bound analysis in Python is slower than Go/Rust. Mitigated by caching per-package indexes and
  running analysis in worker processes, not in the API.
- The GIL limits in-process parallelism; workers scale by process count.

## 10× scale

Analysis throughput scales horizontally with worker processes. If parsing becomes the bottleneck,
the per-file indexer can be swapped for a Rust extension (e.g. via `ruff`'s parser) behind the same
interface — measured first.

## Enterprise

Same choice; enterprise concerns (SSO, multi-region) don't change the language decision.
