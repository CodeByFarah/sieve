"""risk = min(100, (severity_points + exploit_points) × reach_factor) — see ADR-0014.

Every component is returned in the breakdown so the UI can show exactly why a finding ranks
where it does. Confidence is shown beside the score, never folded into it.
"""

from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

from sieve.db.enums import Severity, Verdict

SEVERITY_POINTS = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 30,
    Severity.MEDIUM: 18,
    Severity.LOW: 8,
    Severity.UNKNOWN: 15,
}
KEV_POINTS = 30
EPSS_MAX_POINTS = 20
REACH_FACTOR = {
    Verdict.REACHABLE: Decimal("1.0"),
    Verdict.NEEDS_REVIEW: Decimal("0.6"),
    Verdict.NOT_REACHED: Decimal("0.15"),
}
PENDING_FACTOR = REACH_FACTOR[Verdict.NEEDS_REVIEW]
FORMULA = "min(100, (severity + exploitation) × reachability)"


@dataclass(frozen=True)
class RiskInputs:
    severity: Severity
    verdict: Verdict | None  # the effective verdict (reviewed, else analysed); None = pending
    in_kev: bool
    epss_percentile: Decimal | None


@dataclass(frozen=True)
class RiskScore:
    value: Decimal
    breakdown: dict[str, Any]


def score(inputs: RiskInputs) -> RiskScore:
    severity_points = SEVERITY_POINTS[inputs.severity]
    if inputs.in_kev:
        exploit_points = KEV_POINTS
        exploit_basis = "CISA KEV: known exploited"
    elif inputs.epss_percentile is not None:
        exploit_points = int(
            (EPSS_MAX_POINTS * inputs.epss_percentile).to_integral_value(ROUND_HALF_UP)
        )
        exploit_basis = f"EPSS percentile {inputs.epss_percentile}"
    else:
        exploit_points = 0
        exploit_basis = "EPSS not available"
    factor = REACH_FACTOR[inputs.verdict] if inputs.verdict is not None else PENDING_FACTOR
    raw = Decimal(severity_points + exploit_points) * factor
    value = min(Decimal(100), raw).quantize(Decimal("0.1"), ROUND_HALF_UP)
    return RiskScore(
        value=value,
        breakdown={
            "formula": FORMULA,
            "severity": {"level": str(inputs.severity), "points": severity_points},
            "exploitation": {
                "kev": inputs.in_kev,
                "epss_percentile": str(inputs.epss_percentile)
                if inputs.epss_percentile is not None
                else None,
                "points": exploit_points,
                "basis": exploit_basis,
            },
            "reachability": {
                "verdict": str(inputs.verdict) if inputs.verdict else "pending",
                "factor": str(factor),
            },
            "score": str(value),
        },
    )
