"""Data models shared across all infraguard modules."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from infraguard.common.severity import Severity


@dataclass
class Finding:
    """A single issue discovered by any infraguard module."""

    title: str
    severity: Severity
    resource: str
    detail: str = ""
    suggestion: str = ""
    location: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def score(self) -> int:
        return int(self.severity)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.label,
            "resource": self.resource,
            "detail": self.detail,
            "suggestion": self.suggestion,
            "location": self.location,
            "score": self.score,
            "metadata": self.metadata,
        }


@dataclass
class RiskChange:
    """A scored resource change from a Terraform plan."""

    address: str
    action: str
    resource_type: str
    criticality: Severity
    action_weight: int
    environment_multiplier: float
    risk_score: int
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "action": self.action,
            "resource_type": self.resource_type,
            "criticality": self.criticality.label,
            "action_weight": self.action_weight,
            "environment_multiplier": self.environment_multiplier,
            "risk_score": self.risk_score,
            "detail": self.detail,
        }


@dataclass
class Report:
    """Aggregated results from an infraguard analysis."""

    module: str
    findings: list[Finding] = field(default_factory=list)
    changes: list[RiskChange] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    @property
    def total_score(self) -> int:
        if self.changes:
            return sum(c.risk_score for c in self.changes)
        return sum(f.score for f in self.findings)

    @property
    def max_severity(self) -> Severity | None:
        if self.findings:
            return max(f.severity for f in self.findings)
        if self.changes:
            return max(c.criticality for c in self.changes)
        return None

    def severity_counts(self) -> dict[str, int]:
        counts = {s.label: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.label] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "module": self.module,
            "total_score": self.total_score,
            "summary": self.summary,
        }
        if self.findings:
            result["findings"] = [f.to_dict() for f in self.findings]
            result["severity_counts"] = self.severity_counts()
        if self.changes:
            result["changes"] = [c.to_dict() for c in self.changes]
        return result

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
