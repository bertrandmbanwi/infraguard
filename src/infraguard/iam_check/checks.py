"""Individual IAM policy checks — each function returns findings for a single statement."""

from __future__ import annotations

from typing import Any

from infraguard.common.models import Finding
from infraguard.common.severity import Severity
from infraguard.iam_check.rules import (
    DANGEROUS_ACTIONS,
    SENSITIVE_SERVICE_PREFIXES,
    WILDCARD_SUGGESTIONS,
)


def check_admin_access(
    statement: dict[str, Any], stmt_index: int, policy_name: str
) -> list[Finding]:
    """Check for full admin access (Action: *, Resource: *)."""
    findings = []
    actions = _normalize_list(statement.get("Action", []))
    resources = _normalize_list(statement.get("Resource", []))
    effect = statement.get("Effect", "")

    if effect != "Allow":
        return findings

    if "*" in actions and "*" in resources:
        findings.append(
            Finding(
                title="Full admin access (Action:*, Resource:*)",
                severity=Severity.CRITICAL,
                resource=f"{policy_name} / Statement[{stmt_index}]",
                detail="This statement grants unrestricted access to all AWS actions and resources.",
                suggestion="Apply least-privilege: scope actions and resources to what is actually needed.",
            )
        )
    return findings


def check_wildcard_actions(
    statement: dict[str, Any], stmt_index: int, policy_name: str
) -> list[Finding]:
    """Check for service-level wildcards like s3:* or ec2:*."""
    findings = []
    actions = _normalize_list(statement.get("Action", []))
    effect = statement.get("Effect", "")

    if effect != "Allow":
        return findings

    for action in actions:
        if action == "*":
            continue  # Handled by admin_access check

        if action.endswith(":*"):
            service = action.split(":")[0]
            severity = Severity.HIGH if any(
                action.startswith(p) for p in SENSITIVE_SERVICE_PREFIXES
            ) else Severity.MEDIUM

            suggestion = ""
            if action in WILDCARD_SUGGESTIONS:
                replacements = ", ".join(WILDCARD_SUGGESTIONS[action])
                suggestion = f"Replace '{action}' with specific actions: {replacements}"
            else:
                suggestion = f"Replace '{action}' with specific {service} actions needed."

            findings.append(
                Finding(
                    title=f"Wildcard action: {action}",
                    severity=severity,
                    resource=f"{policy_name} / Statement[{stmt_index}]",
                    detail=f"Grants all actions on {service}. Most workloads need only a few specific actions.",
                    suggestion=suggestion,
                )
            )
    return findings


def check_wildcard_resources(
    statement: dict[str, Any], stmt_index: int, policy_name: str
) -> list[Finding]:
    """Check for wildcard resources on sensitive actions."""
    findings = []
    actions = _normalize_list(statement.get("Action", []))
    resources = _normalize_list(statement.get("Resource", []))
    effect = statement.get("Effect", "")

    if effect != "Allow":
        return findings

    if "*" not in resources:
        return findings

    # Skip if already flagged as full admin
    if "*" in actions:
        return findings

    # Check if any action is on a sensitive service
    has_sensitive = any(
        any(a.startswith(prefix) for prefix in SENSITIVE_SERVICE_PREFIXES)
        for a in actions
    )

    severity = Severity.HIGH if has_sensitive else Severity.MEDIUM

    findings.append(
        Finding(
            title="Wildcard resource on scoped actions",
            severity=severity,
            resource=f"{policy_name} / Statement[{stmt_index}]",
            detail=f"Actions {actions} are granted on all resources (Resource: *).",
            suggestion="Scope Resource to specific ARNs or ARN patterns.",
        )
    )
    return findings


def check_dangerous_actions(
    statement: dict[str, Any], stmt_index: int, policy_name: str
) -> list[Finding]:
    """Check for individually dangerous actions."""
    findings = []
    actions = _normalize_list(statement.get("Action", []))
    effect = statement.get("Effect", "")

    if effect != "Allow":
        return findings

    for action in actions:
        if action in DANGEROUS_ACTIONS:
            severity = DANGEROUS_ACTIONS[action]
            findings.append(
                Finding(
                    title=f"Dangerous action: {action}",
                    severity=severity,
                    resource=f"{policy_name} / Statement[{stmt_index}]",
                    detail=f"Action '{action}' can cause significant damage if misused.",
                    suggestion=f"Verify '{action}' is required and add Condition constraints.",
                )
            )
    return findings


def check_missing_conditions(
    statement: dict[str, Any], stmt_index: int, policy_name: str
) -> list[Finding]:
    """Check for sensitive actions without Condition constraints."""
    findings = []
    actions = _normalize_list(statement.get("Action", []))
    effect = statement.get("Effect", "")
    conditions = statement.get("Condition", {})

    if effect != "Allow":
        return findings

    if conditions:
        return findings  # Conditions present, skip

    sensitive_actions = [
        a for a in actions
        if any(a.startswith(p) for p in SENSITIVE_SERVICE_PREFIXES) and a != "*"
    ]

    if sensitive_actions:
        findings.append(
            Finding(
                title="Missing Condition on sensitive actions",
                severity=Severity.MEDIUM,
                resource=f"{policy_name} / Statement[{stmt_index}]",
                detail=f"Sensitive actions {sensitive_actions} have no Condition constraints.",
                suggestion="Add Condition keys like aws:SourceIp, aws:PrincipalOrgID, or aws:RequestedRegion.",
            )
        )
    return findings


def check_cross_account_access(
    statement: dict[str, Any], stmt_index: int, policy_name: str
) -> list[Finding]:
    """Check for cross-account resource access without conditions."""
    findings = []
    effect = statement.get("Effect", "")
    principal = statement.get("Principal", {})
    conditions = statement.get("Condition", {})

    if effect != "Allow":
        return findings

    if not principal:
        return findings

    # Check for cross-account principals
    aws_principals = []
    if isinstance(principal, str):
        if principal == "*":
            aws_principals = ["*"]
    elif isinstance(principal, dict):
        aws_val = principal.get("AWS", [])
        aws_principals = _normalize_list(aws_val)

    has_external = any(
        p == "*" or (p.startswith("arn:aws") and ":root" in p)
        for p in aws_principals
    )

    if has_external and not conditions:
        findings.append(
            Finding(
                title="Cross-account access without conditions",
                severity=Severity.HIGH,
                resource=f"{policy_name} / Statement[{stmt_index}]",
                detail="Policy allows cross-account access with no Condition constraints.",
                suggestion="Add aws:PrincipalOrgID or aws:SourceAccount conditions.",
            )
        )
    return findings


# ── Helpers ───────────────────────────────────────────────────


def _normalize_list(value: Any) -> list[str]:
    """Ensure a value is a list of strings (IAM allows string or list)."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return value
    return []
