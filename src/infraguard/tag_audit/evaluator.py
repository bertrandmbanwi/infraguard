"""Tag policy evaluator — checks resources against tag compliance rules."""

from __future__ import annotations

import re
from typing import Any

from infraguard.common.models import Finding, Report
from infraguard.common.severity import Severity
from infraguard.tag_audit.rules import DEFAULT_NAMING_RULES, DEFAULT_REQUIRED_TAGS
from infraguard.tag_audit.scanner import TaggedResource


def evaluate(
    resources: list[TaggedResource],
    required_tags: list[dict] | None = None,
    naming_rules: dict | None = None,
    resource_overrides: dict[str, dict] | None = None,
) -> Report:
    """Evaluate a list of resources against tag compliance rules.

    Args:
        resources: Resources to evaluate.
        required_tags: Tag requirements (key, allowed_values, pattern).
        naming_rules: Naming convention rules.
        resource_overrides: Per-resource-type overrides for additional required tags.
    """
    tag_rules = required_tags or DEFAULT_REQUIRED_TAGS
    name_rules = naming_rules or DEFAULT_NAMING_RULES
    overrides = resource_overrides or {}

    findings: list[Finding] = []
    compliant_count = 0
    total_count = len(resources)
    service_stats: dict[str, dict[str, int]] = {}

    for resource in resources:
        resource_findings = _check_resource(resource, tag_rules, name_rules, overrides)

        svc = resource.service
        if svc not in service_stats:
            service_stats[svc] = {"total": 0, "compliant": 0}
        service_stats[svc]["total"] += 1

        if not resource_findings:
            compliant_count += 1
            service_stats[svc]["compliant"] += 1
        else:
            findings.extend(resource_findings)

    compliance_pct = (compliant_count / total_count * 100) if total_count else 100.0
    summary: dict[str, Any] = {
        "total_resources": total_count,
        "compliant_resources": compliant_count,
        "compliance_percentage": round(compliance_pct, 1),
        "total_violations": len(findings),
        "by_service": {
            svc: {
                "total": stats["total"],
                "compliant": stats["compliant"],
                "percentage": round(stats["compliant"] / stats["total"] * 100, 1)
                if stats["total"]
                else 100.0,
            }
            for svc, stats in sorted(service_stats.items())
        },
    }

    return Report(module="tag-audit", findings=findings, summary=summary)

def _check_resource(
    resource: TaggedResource,
    tag_rules: list[dict],
    name_rules: dict,
    overrides: dict[str, dict],
) -> list[Finding]:
    """Check a single resource against all tag rules."""
    findings: list[Finding] = []

    effective_rules = list(tag_rules)

    if resource.resource_type in overrides:
        for extra_key in overrides[resource.resource_type].get("additional_required", []):
            effective_rules.append({"key": extra_key})

    for rule in effective_rules:
        key = rule["key"]
        value = resource.tags.get(key)

        if value is None:
            findings.append(
                Finding(
                    title=f"Missing required tag: {key}",
                    severity=Severity.HIGH,
                    resource=f"{resource.resource_id} ({resource.service})",
                    detail=f"Resource is missing required tag '{key}'.",
                    suggestion=f"Add tag '{key}' to this resource.",
                    location=resource.region,
                    metadata={"tag_key": key, "resource_type": resource.resource_type},
                )
            )
            continue

        allowed = rule.get("allowed_values")
        if allowed and value not in allowed:
            findings.append(
                Finding(
                    title=f"Invalid tag value: {key}={value}",
                    severity=Severity.MEDIUM,
                    resource=f"{resource.resource_id} ({resource.service})",
                    detail=f"Tag '{key}' has value '{value}' which is not in allowed values: {allowed}.",
                    suggestion=f"Set '{key}' to one of: {', '.join(allowed)}.",
                    location=resource.region,
                    metadata={"tag_key": key, "tag_value": value},
                )
            )

        pattern = rule.get("pattern")
        if pattern and not re.match(pattern, value):
            findings.append(
                Finding(
                    title=f"Tag value format error: {key}",
                    severity=Severity.MEDIUM,
                    resource=f"{resource.resource_id} ({resource.service})",
                    detail=f"Tag '{key}' value '{value}' doesn't match pattern '{pattern}'.",
                    suggestion=f"Update '{key}' to match pattern: {pattern}.",
                    location=resource.region,
                    metadata={"tag_key": key, "tag_value": value, "pattern": pattern},
                )
            )

    prohibited_prefixes = name_rules.get("prohibited_prefixes", [])
    prohibited_values = name_rules.get("prohibited_values", [])

    for key, value in resource.tags.items():
        for prefix in prohibited_prefixes:
            if key.startswith(prefix):
                findings.append(
                    Finding(
                        title=f"Prohibited tag prefix: {key}",
                        severity=Severity.LOW,
                        resource=f"{resource.resource_id} ({resource.service})",
                        detail=f"Tag key '{key}' uses prohibited prefix '{prefix}'.",
                        suggestion=f"Rename tag key to remove prefix '{prefix}'.",
                        location=resource.region,
                    )
                )

        if value.lower().strip() in prohibited_values:
            findings.append(
                Finding(
                    title=f"Empty/invalid tag value: {key}",
                    severity=Severity.LOW,
                    resource=f"{resource.resource_id} ({resource.service})",
                    detail=f"Tag '{key}' has empty or placeholder value '{value}'.",
                    suggestion=f"Set a meaningful value for tag '{key}'.",
                    location=resource.region,
                )
            )

    return findings
