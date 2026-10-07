# ADR-0005: PostgreSQL as the system of record

- Status: Accepted
- Date: 2026-10-06

## Problem

Findings, reviews, audit events and jobs need relational integrity, transactions spanning several
tables, concurrency control, and flexible querying for dashboards.

## Alternatives

- **DynamoDB** — scales without operation, but multi-entity transactions and ad-hoc filtering for the
  findings table are awkward; foreign keys don't exist.
- **MongoDB** — flexible documents, weaker relational integrity.
- **PostgreSQL** — chosen.
- **Vector database** — rejected: no requirement involves similarity search (spec §8).

## Decision

PostgreSQL 16 (RDS in production). JSONB is used for genuinely schemaless payloads (raw advisory
records, evidence steps, policy rules); everything queried or constrained is a typed column.

## Trade-offs

Vertical scaling limits and connection management (pgbouncer/RDS Proxy at larger scale).

## 10× scale

Read replicas for dashboards; partition `audit_events` and `jobs` by time; archive finished jobs.

## Enterprise

Same engine; add RLS policies as defence in depth for tenant isolation, and Multi-AZ.
