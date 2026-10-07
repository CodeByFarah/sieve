# ADR-0001: Record architecture decisions

- Status: Accepted
- Date: 2026-10-06

## Context

Sieve's design involves non-obvious trade-offs (where AI is allowed, what "not reachable" requires,
why the queue is in Postgres). Reviewers need to understand *why*, not just *what*.

## Decision

Keep Architecture Decision Records in `docs/decisions/`, numbered, one decision per file. Each ADR
answers the six questions from the specification (§58):

1. What problem are we solving?
2. What alternatives exist?
3. Why did we choose this?
4. What are the trade-offs?
5. What happens at 10× scale?
6. What would we change in a real enterprise environment?

ADRs are immutable once accepted; a changed decision gets a new ADR that supersedes the old one.

## Consequences

Small writing overhead per decision; reviewers can audit reasoning without reconstructing it from code.
