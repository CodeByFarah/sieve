# ADR-0008: AI proposes symbols; deterministic analysis decides

- Status: Accepted
- Date: 2026-10-06

## Problem

Reachability needs to know *which functions* an advisory concerns. Most advisories don't state this
in machine-readable form. Humans infer it from the advisory text and the fix commit; an LLM can do the
same at scale — but LLM output can be wrong, fabricated, or manipulated by prompt injection.

## Alternatives

1. **No AI; only advisories with structured symbol data** — trustworthy but leaves most findings in
   `needs_review`.
2. **LLM decides reachability end-to-end** (give it the code and advisory, ask "is this reachable?")
   — unverifiable, unauditable, sends customer code to a third party, and susceptible to injection.
3. **Heuristics only** (functions touched by the fix diff) — deterministic, but diffs often touch
   helpers, tests and refactors; precision is poor without judgement.
4. **LLM proposes candidate symbols; deterministic code verifies and decides** — chosen.

## Decision

- The LLM receives only public data (advisory text, references, upstream fix diff) and returns
  schema-constrained candidate symbols with quoted evidence. It has no tools.
- Each candidate must (a) exist in the package source at a vulnerable version, with the claimed kind,
  and (b) when a fix diff exists, be modified by it or directly call a modified function. Failures are
  recorded with a reason.
- Only verified symbols reach the reachability engine. The verdict comes from the call graph.
- Every AI contribution is labelled as such in the UI and the evidence bundle.

## Trade-offs

- Verification may reject correct symbols when the fix is far from the vulnerable entry point
  (measured as "verifier rejection precision" in evaluation).
- Model cost and latency, mitigated by per-advisory caching (one extraction serves every repository).

## 10× scale

Cost scales with **new advisories**, not with repositories or scans. Batch extraction runs at
ingestion time.

## Enterprise

Customers may require a specific provider or a self-hosted model; the `AIProvider` interface supports
that without pipeline changes.
