# ADR-0004: PostgreSQL-backed job queue

- Status: Accepted
- Date: 2026-10-06

## Problem

Scans, ingestion, AI extraction, fan-out and check publishing are slow, must survive crashes, must
retry with backoff, must not run twice for duplicate events, and must expose failures (dead letters).

## Alternatives

| Option | Durability | Exactly-once enqueue with DB change | Ops cost |
|---|---|---|---|
| Redis lists / RQ / Celery+Redis | Depends on AOF config; not the system of record | No — dual write needs an outbox | Low |
| SQS + transactional outbox | High | Yes, via outbox relay | Medium: relay process, DLQ config, local emulation |
| Kafka / event bus | High | Via outbox | High; not justified ([§59](../spec-review.md)) |
| **Postgres table + `FOR UPDATE SKIP LOCKED`** | Same as the data | **Yes — same transaction** | Lowest: no new infrastructure |

## Decision

A `jobs` table with `UNIQUE (idempotency_key)`, lease-based claiming (`SKIP LOCKED`), heartbeats,
exponential backoff with jitter, `max_attempts`, and a `dead` status as the dead-letter queue.
Enqueuing happens inside the transaction that produced the work.

This removes the need for a separate outbox: the job row *is* the outbox entry, committed atomically
with the state change.

## Trade-offs

- Polling adds small latency (mitigated with `LISTEN/NOTIFY` wake-ups; polling remains the fallback).
- Queue traffic shares the primary database's capacity.
- No built-in fan-out/pub-sub semantics; fan-out is implemented as a job that enqueues jobs.

## 10× scale

Postgres comfortably handles thousands of job transitions per second with a partial index on pending
rows; Sieve's expected volume is orders of magnitude lower. If queue load ever competes with
application queries, the `JobQueue` interface is re-implemented on SQS, and the existing transactional
insert becomes an outbox relayed to SQS. Callers do not change.

## Enterprise

Likely SQS (or the organisation's standard broker) with the outbox relay, for isolation from the
OLTP database and for cross-team consumption of events.
