"""Output formatters for infraguard reports — table, JSON, markdown, SARIF."""

from __future__ import annotations

import json
import sys
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from infraguard.common.models import Report
from infraguard.common.severity import Severity

console = Console(stderr=True)


# ── Table (Rich) ──────────────────────────────────────────────


def render_plan_risk_table(report: Report, threshold: int | None = None) -> None:
    """Print a Rich-formatted plan risk report to stderr."""
    console.print()
    console.print(
        Panel.fit(
            "[bold]Terraform Plan Risk Report[/bold]",
            border_style="blue",
        )
    )
    console.print()

    if not report.changes:
        console.print("  [dim]No resource changes detected.[/dim]")
        return

    table = Table(show_header=True, header_style="bold", padding=(0, 2))
    table.add_column("Resource", style="white", min_width=35)
    table.add_column("Action", min_width=10)
    table.add_column("Criticality", min_width=12)
    table.add_column("Score", justify="right", min_width=6)

    for change in sorted(report.changes, key=lambda c: c.risk_score, reverse=True):
        action_color = {
            "delete": "red",
            "replace": "red",
            "update": "yellow",
            "create": "green",
        }.get(change.action, "dim")

        table.add_row(
            change.address,
            Text(change.action, style=action_color),
            Text(change.criticality.label, style=change.criticality.color),
            Text(str(change.risk_score), style="bold"),
        )

    console.print(table)
    console.print()

    # Summary
    total = report.total_score
    highest = max(report.changes, key=lambda c: c.risk_score)
    console.print(f"  [bold]Total Risk Score:[/bold] {total}")
    console.print(
        f"  [bold]Highest Risk:[/bold] {highest.address} "
        f"({highest.action} {highest.criticality.label} resource)"
    )

    if threshold is not None:
        if total > threshold:
            console.print(
                f"  [bold red]Verdict: BLOCK — score {total} exceeds threshold ({threshold})[/bold red]"
            )
        else:
            console.print(
                f"  [bold green]Verdict: PASS — score {total} within threshold ({threshold})[/bold green]"
            )
    console.print()


def render_findings_table(report: Report, title: str, threshold_info: str = "") -> None:
    """Print a Rich-formatted findings report to stderr."""
    console.print()
    console.print(Panel.fit(f"[bold]{title}[/bold]", border_style="blue"))
    console.print()

    if not report.findings:
        console.print("  [dim]No findings.[/dim]")
        return

    table = Table(show_header=True, header_style="bold", padding=(0, 2))
    table.add_column("Finding", style="white", min_width=35)
    table.add_column("Severity", min_width=10)
    table.add_column("Resource", min_width=25)

    for finding in sorted(report.findings, key=lambda f: f.severity, reverse=True):
        table.add_row(
            finding.title,
            Text(finding.severity.label, style=finding.severity.color),
            finding.resource,
        )

    console.print(table)
    console.print()

    # Severity counts
    counts = report.severity_counts()
    parts = []
    for sev in reversed(list(Severity)):
        count = counts[sev.label]
        if count > 0:
            parts.append(f"[{sev.color}]{count} {sev.label}[/{sev.color}]")
    if parts:
        console.print(f"  [bold]Summary:[/bold] {', '.join(parts)}")

    if threshold_info:
        console.print(f"  {threshold_info}")
    console.print()


# ── JSON ──────────────────────────────────────────────────────


def render_json(report: Report) -> None:
    """Print JSON report to stdout."""
    sys.stdout.write(report.to_json() + "\n")


# ── Markdown ──────────────────────────────────────────────────


def render_plan_risk_markdown(report: Report, threshold: int | None = None) -> None:
    """Print markdown-formatted plan risk report to stdout."""
    lines = ["## Terraform Plan Risk Report", ""]

    if not report.changes:
        lines.append("No resource changes detected.")
        sys.stdout.write("\n".join(lines) + "\n")
        return

    lines.append("| Resource | Action | Criticality | Score |")
    lines.append("|----------|--------|-------------|------:|")
    for change in sorted(report.changes, key=lambda c: c.risk_score, reverse=True):
        emoji = _severity_emoji(change.criticality)
        lines.append(
            f"| `{change.address}` | {change.action} | {emoji} {change.criticality.label} | {change.risk_score} |"
        )

    lines.append("")
    total = report.total_score
    lines.append(f"**Total Risk Score:** {total}")

    if threshold is not None:
        if total > threshold:
            lines.append(f"**Verdict:** :no_entry: BLOCK — score exceeds threshold ({threshold})")
        else:
            lines.append(
                f"**Verdict:** :white_check_mark: PASS — score within threshold ({threshold})"
            )

    sys.stdout.write("\n".join(lines) + "\n")


def render_findings_markdown(report: Report, title: str) -> None:
    """Print markdown-formatted findings report to stdout."""
    lines = [f"## {title}", ""]

    if not report.findings:
        lines.append("No findings.")
        sys.stdout.write("\n".join(lines) + "\n")
        return

    lines.append("| Finding | Severity | Resource |")
    lines.append("|---------|----------|----------|")
    for f in sorted(report.findings, key=lambda x: x.severity, reverse=True):
        emoji = _severity_emoji(f.severity)
        lines.append(f"| {f.title} | {emoji} {f.severity.label} | `{f.resource}` |")

    lines.append("")
    counts = report.severity_counts()
    parts = [f"{v} {k}" for k, v in counts.items() if v > 0]
    if parts:
        lines.append(f"**Summary:** {', '.join(parts)}")

    sys.stdout.write("\n".join(lines) + "\n")


# ── SARIF ─────────────────────────────────────────────────────


def render_sarif(report: Report) -> None:
    """Print SARIF 2.1.0 report to stdout for GitHub Code Scanning integration."""
    sarif: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": f"infraguard {report.module}",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/bertrandmbanwi/infraguard",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }

    run = sarif["runs"][0]
    rule_ids: dict[str, int] = {}

    for finding in report.findings:
        if finding.title not in rule_ids:
            rule_ids[finding.title] = len(rule_ids)
            run["tool"]["driver"]["rules"].append(
                {
                    "id": f"IG{rule_ids[finding.title]:03d}",
                    "name": finding.title.replace(" ", ""),
                    "shortDescription": {"text": finding.title},
                    "defaultConfiguration": {
                        "level": _sarif_level(finding.severity),
                    },
                }
            )

        run["results"].append(
            {
                "ruleId": f"IG{rule_ids[finding.title]:03d}",
                "level": _sarif_level(finding.severity),
                "message": {
                    "text": finding.detail or finding.title,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.resource,
                            }
                        }
                    }
                ],
            }
        )

    sys.stdout.write(json.dumps(sarif, indent=2) + "\n")


# ── Helpers ───────────────────────────────────────────────────


def _severity_emoji(severity: Severity) -> str:
    return {
        Severity.CRITICAL: ":red_circle:",
        Severity.HIGH: ":orange_circle:",
        Severity.MEDIUM: ":yellow_circle:",
        Severity.LOW: ":blue_circle:",
        Severity.INFO: ":white_circle:",
    }[severity]


def _sarif_level(severity: Severity) -> str:
    if severity >= Severity.HIGH:
        return "error"
    if severity >= Severity.MEDIUM:
        return "warning"
    return "note"
