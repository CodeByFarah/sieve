# ADR-0010: Confidence is a rule-derived level with reasons, not a percentage

- Status: Accepted
- Date: 2026-10-06

## Problem

The spec's UI mock-ups show "Confidence: 94%". A percentage implies a calibrated probability. Sieve's
analysis has no calibration data, so any percentage would be invented.

## Decision

Confidence is one of `high`, `medium`, `low`, computed by explicit rules, always shown with the
reasons that produced it.

| Level | Reachable verdict | Not-reached verdict |
|---|---|---|
| high | Every edge on the path is `direct` or `attribute`; symbol verified from advisory or curated data, or AI-proposed and diff-confirmed. | All imports of the package resolved; no unresolved edges in scope; symbols from advisory/curated data. |
| medium | Path includes `method_inferred` edges, or symbol is AI-proposed and source-verified but not diff-confirmed. | Symbols AI-proposed and verified; no unresolved edges in scope. |
| low | Never assigned — weaker evidence produces `needs_review` instead. | Never assigned — same rule. |

`needs_review` findings carry `low` and a reason code.

## Trade-offs

Less "impressive" than a number. Far more defensible.

## Future

Once a labelled reachability benchmark exists, measured precision per level can be shown next to the
level ("high: 0.xx precision on N labelled cases"), with the dataset linked.
