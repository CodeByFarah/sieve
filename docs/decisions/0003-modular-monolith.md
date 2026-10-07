# ADR-0003: Modular monolith with an API process and a worker process

- Status: Accepted
- Date: 2026-10-06

## Problem

Sieve has many domains (GitHub, advisories, SBOM, analysis, AI, findings, VEX, policy, audit). They
need clear boundaries, but splitting them into network services adds failure modes and operational
cost without a team-scaling reason.

## Alternatives

- **Microservices per domain** — independent deploys, but distributed transactions (e.g. "record a
  review decision *and* its audit event"), network failure handling everywhere, and N deploy pipelines
  for one engineer.
- **Single process doing everything** — simplest, but long scans would block API workers.
- **Modular monolith, two entry points** — chosen.

## Decision

One Python package (`sieve`) with domain sub-packages and downward-only dependencies. The same image
runs as `api` (uvicorn) or `worker` (job runner). The Next.js frontend is a separate deployable because
it is a different runtime.

The spec's suggested top-level split (`workers/`, `analysis/`, `ai/`, `packages/`) is replaced by
sub-packages of `sieve` (see [spec-review §1.5](../spec-review.md)).

## Trade-offs

- Module boundaries are enforced by convention and `import-linter`, not by the network.
- API and worker share a release cadence.

## 10× scale

Workers scale independently by queue depth already. If one domain (e.g. analysis) needs different
hardware, it becomes a separate worker *pool* consuming specific job kinds — still the same codebase.

## Enterprise

A larger team might extract advisory ingestion into its own service owned by a data team, because it
has a different change cadence and no user-facing latency requirement. The job-queue boundary makes
that extraction straightforward.
