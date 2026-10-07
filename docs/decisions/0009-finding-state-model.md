# ADR-0009: Findings carry orthogonal state dimensions

- Status: Accepted
- Date: 2026-10-06

## Problem

The spec's single linear state (`DISCOVERED → … → REVIEWED → VEX_GENERATED`) conflates analysis
progress, verdict, human review and document generation. Re-analysis after a review, or a review that
disagrees with analysis, cannot be represented without losing information.

## Decision

Four independent fields, each with its own validated transition table:

```
analysis_state: pending → analyzing → analyzed | failed      (re-analysis: analyzed|failed → analyzing)
verdict:        null | reachable | not_reached | needs_review (set only by analysis)
review_state:   unreviewed → accepted | overridden
                accepted|overridden → stale   (when a new analysis changes the verdict or evidence)
                stale → accepted | overridden
presence:       present ↔ resolved            (dependency upgraded/removed; reappearing reopens it)
```

The **effective** status shown to users and used for VEX is:
`review.decided_verdict` if `review_state ∈ {accepted, overridden}`, else the analysis `verdict`.

VEX generation is not a finding state: a VEX document references the review decisions it was built
from. Transitions are implemented in one module (`sieve.findings.state`) and anything else is
rejected with an error; every transition writes an audit event.

## Trade-offs

Four fields are more to explain than one. The UI presents a single combined badge plus detail.

## 10× scale / Enterprise

Unchanged. Enterprise may add approval chains (two-person review for `not_affected`), which become
additional `review_state` values.
