"""Policy evaluation. Every rule match is returned with the facts that matched, so a check can
explain exactly why it passed or failed.

Unknown severity is treated as ``high`` when compared against a threshold: an unscored advisory
should not slip under a "high or above" rule.
"""

from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sieve.core.errors import UserError
from sieve.db.enums import Severity, Verdict

_RANK = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.UNKNOWN: 3,
    Severity.CRITICAL: 4,
}


class Condition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kev: bool | None = None
    verdict: list[Verdict] | None = None
    severity_at_least: Severity | None = None
    epss_percentile_at_least: Decimal | None = Field(default=None, ge=0, le=1)


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["block", "warn"]
    when: Condition
    description: str = Field(default="", max_length=200)


class PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rules: list[Rule] = Field(max_length=50)


DEFAULT_POLICY: dict[str, Any] = {
    "rules": [
        {
            "action": "block",
            "when": {"kev": True, "verdict": ["reachable"]},
            "description": "Known-exploited vulnerability reachable from application code",
        },
        {
            "action": "block",
            "when": {"severity_at_least": "critical", "verdict": ["reachable"]},
            "description": "Critical vulnerability reachable from application code",
        },
        {
            "action": "warn",
            "when": {"severity_at_least": "high", "verdict": ["reachable"]},
            "description": "High-severity vulnerability reachable from application code",
        },
        {
            "action": "warn",
            "when": {"severity_at_least": "high", "verdict": ["needs_review"]},
            "description": "High-severity vulnerability whose reachability needs review",
        },
    ]
}


class InvalidPolicy(UserError):
    code = "invalid_policy"


def parse_policy(data: Any) -> PolicyDocument:
    try:
        return PolicyDocument.model_validate(data)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:5]
        )
        raise InvalidPolicy(str(exc), public_message=f"Invalid policy: {details}") from exc


@dataclass(frozen=True)
class FindingFacts:
    key: str  # e.g. "GHSA-…:pyyaml"
    advisory: str
    package: str
    version: str | None
    severity: Severity
    verdict: Verdict
    kev: bool
    epss_percentile: Decimal | None


@dataclass(frozen=True)
class RuleMatch:
    facts: FindingFacts
    rule: Rule


@dataclass(frozen=True)
class Evaluation:
    conclusion: Literal["success", "neutral", "failure"]
    blocking: list[RuleMatch]
    warnings: list[RuleMatch]


def matches(condition: Condition, facts: FindingFacts) -> bool:
    if condition.kev is not None and facts.kev != condition.kev:
        return False
    if condition.verdict is not None and facts.verdict not in condition.verdict:
        return False
    if (
        condition.severity_at_least is not None
        and _RANK[facts.severity] < _RANK[condition.severity_at_least]
    ):
        return False
    return condition.epss_percentile_at_least is None or (
        facts.epss_percentile is not None
        and facts.epss_percentile >= condition.epss_percentile_at_least
    )


def evaluate(policy: PolicyDocument, findings: list[FindingFacts]) -> Evaluation:
    """Each finding is reported under the first (most severe) rule it matches."""
    blocking: list[RuleMatch] = []
    warnings: list[RuleMatch] = []
    ordered = sorted(policy.rules, key=lambda rule: rule.action != "block")
    for facts in findings:
        for rule in ordered:
            if matches(rule.when, facts):
                (blocking if rule.action == "block" else warnings).append(RuleMatch(facts, rule))
                break
    conclusion: Literal["success", "neutral", "failure"] = (
        "failure" if blocking else "neutral" if warnings else "success"
    )
    return Evaluation(conclusion, blocking, warnings)
