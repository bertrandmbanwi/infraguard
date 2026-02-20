"""Risk scoring engine for Terraform plan changes."""

from __future__ import annotations

import re

from infraguard.common.models import Report, RiskChange
from infraguard.common.severity import Severity
from infraguard.plan_risk.parser import ResourceChange
from infraguard.plan_risk.rules import (
    ACTION_WEIGHTS,
    DEFAULT_CRITICALITY,
    DEFAULT_ENVIRONMENT_MULTIPLIER,
    ENVIRONMENT_MULTIPLIERS,
    RESOURCE_CRITICALITY,
)


def score_changes(
    changes: list[ResourceChange],
    criticality_overrides: dict[str, Severity] | None = None,
    env_overrides: dict[str, float] | None = None,
) -> Report:
    """Score a list of Terraform resource changes and produce a report.

    Args:
        changes: Parsed resource changes from a Terraform plan.
        criticality_overrides: Optional overrides for resource type criticality.
        env_overrides: Optional overrides for environment multipliers.
    """
    criticality_map = dict(RESOURCE_CRITICALITY)
    if criticality_overrides:
        criticality_map.update(criticality_overrides)

    env_map = dict(ENVIRONMENT_MULTIPLIERS)
    if env_overrides:
        env_map.update(env_overrides)

    scored: list[RiskChange] = []

    for change in changes:
        action_weight = ACTION_WEIGHTS.get(change.action, 0)
        criticality = criticality_map.get(change.resource_type, DEFAULT_CRITICALITY)
        env_multiplier = _detect_environment(change.address, env_map)

        risk_score = int(action_weight * int(criticality) * env_multiplier)

        detail = _build_detail(change, criticality, env_multiplier)

        scored.append(
            RiskChange(
                address=change.address,
                action=change.action,
                resource_type=change.resource_type,
                criticality=criticality,
                action_weight=action_weight,
                environment_multiplier=env_multiplier,
                risk_score=risk_score,
                detail=detail,
            )
        )

    scored.sort(key=lambda c: c.risk_score, reverse=True)

    total = sum(c.risk_score for c in scored)
    highest = scored[0] if scored else None
    actions_summary = {}
    for c in scored:
        actions_summary[c.action] = actions_summary.get(c.action, 0) + 1

    summary = {
        "total_changes": len(scored),
        "total_risk_score": total,
        "actions": actions_summary,
        "highest_risk": highest.address if highest else None,
        "highest_risk_score": highest.risk_score if highest else 0,
    }

    return Report(module="plan-risk", changes=scored, summary=summary)

def _detect_environment(address: str, env_map: dict[str, float]) -> float:
    """Detect environment from resource address using pattern matching."""
    addr_lower = address.lower()

    for pattern, multiplier in sorted(env_map.items(), key=lambda x: -len(x[0])):
        if re.search(rf"(?:^|[._\-/]){re.escape(pattern)}(?:$|[._\-/])", addr_lower):
            return multiplier

    return DEFAULT_ENVIRONMENT_MULTIPLIER

def _build_detail(change: ResourceChange, criticality: Severity, env_mult: float) -> str:
    """Build a human-readable detail string for a scored change."""
    parts = [f"{change.action} {criticality.label} resource"]
    if env_mult > 1.0:
        parts.append(f"{env_mult}x environment multiplier")
    return " — ".join(parts)
