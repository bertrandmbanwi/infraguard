"""IAM policy analyzer — parses policies and runs all checks."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from infraguard.common.models import Finding, Report
from infraguard.common.severity import Severity
from infraguard.iam_check.checks import (
    check_admin_access,
    check_cross_account_access,
    check_dangerous_actions,
    check_missing_conditions,
    check_wildcard_actions,
    check_wildcard_resources,
)

ALL_CHECKS = [
    check_admin_access,
    check_wildcard_actions,
    check_wildcard_resources,
    check_dangerous_actions,
    check_missing_conditions,
    check_cross_account_access,
]

def analyze_policy_file(path: Path) -> Report:
    """Analyze a single IAM policy JSON file.

    Accepts either:
    - A raw policy document (with "Version" and "Statement")
    - A file containing {"policies": [{"name": ..., "document": {...}}]}
    """
    with open(path) as f:
        data = json.load(f)

    if "policies" in data:
        return _analyze_multiple(data["policies"])
    elif "Statement" in data:
        return _analyze_single(data, policy_name=path.stem)
    elif "PolicyDocument" in data:
        name = data.get("PolicyName", path.stem)
        return _analyze_single(data["PolicyDocument"], policy_name=name)
    else:
        raise ValueError(
            f"Unrecognized policy format. Expected 'Statement', 'PolicyDocument', "
            f"or 'policies' key in {path}"
        )

def analyze_policy_document(document: dict[str, Any], policy_name: str = "inline") -> Report:
    """Analyze a single IAM policy document dict."""
    return _analyze_single(document, policy_name)

def analyze_aws_role(
    role_name: str, profile: str | None = None, region: str = "us-east-1"
) -> Report:
    """Analyze all policies attached to an IAM role via boto3."""
    try:
        import boto3
    except ImportError:
        raise RuntimeError(
            "boto3 is required for live AWS scanning. "
            "Install with: pip install 'infraguard[aws]'"
        )

    session = boto3.Session(profile_name=profile, region_name=region)
    iam = session.client("iam")

    policies: list[dict[str, Any]] = []

    inline_names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
    for name in inline_names:
        resp = iam.get_role_policy(RoleName=role_name, PolicyName=name)
        doc = resp["PolicyDocument"]
        if isinstance(doc, str):
            doc = json.loads(unquote(doc))
        policies.append({"name": f"{role_name}/{name} (inline)", "document": doc})

    attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    for policy in attached:
        arn = policy["PolicyArn"]
        versions = iam.get_policy(PolicyArn=arn)
        version_id = versions["Policy"]["DefaultVersionId"]
        version = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
        doc = version["PolicyVersion"]["Document"]
        if isinstance(doc, str):
            doc = json.loads(unquote(doc))
        policies.append({"name": f"{policy['PolicyName']} (managed)", "document": doc})

    return _analyze_multiple(policies)

def _analyze_single(document: dict[str, Any], policy_name: str) -> Report:
    """Run all checks against a single policy document."""
    findings: list[Finding] = []
    statements = document.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for i, stmt in enumerate(statements):
        for check_fn in ALL_CHECKS:
            findings.extend(check_fn(stmt, i, policy_name))

    seen = set()
    unique_findings = []
    for f in findings:
        key = (f.title, f.resource)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    summary = _build_summary(unique_findings, [policy_name])
    return Report(module="iam-check", findings=unique_findings, summary=summary)

def _analyze_multiple(policies: list[dict[str, Any]]) -> Report:
    """Run checks across multiple policy documents."""
    all_findings: list[Finding] = []
    policy_names: list[str] = []

    for policy in policies:
        name = policy.get("name", "unknown")
        document = policy.get("document", {})
        policy_names.append(name)

        sub_report = _analyze_single(document, name)
        all_findings.extend(sub_report.findings)

    summary = _build_summary(all_findings, policy_names)
    return Report(module="iam-check", findings=all_findings, summary=summary)

def _build_summary(findings: list[Finding], policy_names: list[str]) -> dict[str, Any]:
    """Build summary statistics for an IAM check report."""
    counts: dict[str, int] = {s.label: 0 for s in Severity}
    for f in findings:
        counts[f.severity.label] += 1

    return {
        "policies_analyzed": len(policy_names),
        "policy_names": policy_names,
        "total_findings": len(findings),
        "severity_counts": counts,
    }
