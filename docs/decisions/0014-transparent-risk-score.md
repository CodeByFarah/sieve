# ADR-0014: A transparent, additive risk score

- Status: Proposed (implemented in Phase 7; constants may be tuned, every change is a new ADR revision)
- Date: 2026-10-06

## Problem

Findings must be ranked so the most urgent appear first. Users must be able to see *why* a finding
ranks where it does (spec §24: "Do not create a mysterious AI risk score").

## Decision

Score in `[0, 100]`, computed from named components that are stored in `findings.risk_breakdown` and
shown verbatim in the UI:

```
severity_points = {critical: 40, high: 30, medium: 18, low: 8, unknown: 15}[severity]
exploit_points  = 30                                   if CVE alias is in CISA KEV
                = round(20 × epss_percentile)          elif EPSS available
                = 0                                     otherwise
reach_factor    = {reachable: 1.0, needs_review: 0.6, not_reached: 0.15}[effective verdict]

risk = min(100, (severity_points + exploit_points) × reach_factor), rounded to 1 decimal
```

Design intent:

- Reachability dominates: a reachable medium outranks an unreachable critical
  (`18 × 1.0 = 18` vs `40 × 0.15 = 6`).
- Known exploitation (KEV) is the strongest exploit signal; EPSS contributes proportionally when KEV
  is absent. Missing EPSS contributes 0 and is displayed as "EPSS: not available", not as a low score.
- `needs_review` keeps meaningful weight so unknowns aren't buried.
- `not_reached` never goes to zero — the analysis could be wrong.
- `unknown` severity is placed between medium and high to avoid hiding unscored advisories.

Confidence is **not** a multiplier; it is displayed next to the score. Mixing it in would make the
score harder to explain.

## Trade-offs

The weights are judgement, not learned. They are constants in one module with unit tests pinning
the documented orderings above, so any change is deliberate and reviewable.

## Future

Production exposure (e.g. "repository is deployed to production") as an additional named component
once a data source exists.
