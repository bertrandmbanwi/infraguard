"""CLI subcommand for Terraform plan risk scoring."""

from __future__ import annotations

from pathlib import Path

import typer

from infraguard.common.reporter import (
    render_json,
    render_plan_risk_markdown,
    render_plan_risk_table,
    render_sarif,
)
from infraguard.plan_risk.parser import parse_plan
from infraguard.plan_risk.scorer import score_changes

app = typer.Typer(no_args_is_help=False)


@app.callback(invoke_without_command=True)
def plan_risk(
    file: Path | None = typer.Option(
        None,
        "--file",
        "-f",
        help="Path to terraform plan JSON (output of `terraform show -json`). Reads stdin if omitted.",
        exists=True,
        readable=True,
    ),
    threshold: int | None = typer.Option(
        None,
        "--threshold",
        "-t",
        help="Maximum acceptable risk score. Exit 1 if exceeded.",
    ),
    format: str = typer.Option(
        "table",
        "--format",
        "-o",
        help="Output format: table, json, markdown, sarif.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress output — only return exit code.",
    ),
) -> None:
    """Score Terraform plan changes by blast radius.

    Reads the JSON output of `terraform show -json <planfile>` and scores
    each resource change by action severity, resource criticality, and
    detected environment. Use --threshold for CI gating.

    Examples:

        terraform show -json tfplan | infraguard plan-risk

        infraguard plan-risk -f plan.json --threshold 50

        infraguard plan-risk -f plan.json --format markdown > comment.md
    """
    try:
        changes = parse_plan(file)
    except Exception as e:
        if not quiet:
            typer.echo(f"Error parsing plan: {e}", err=True)
        raise typer.Exit(code=2)

    report = score_changes(changes)

    if not quiet:
        if format == "json":
            render_json(report)
        elif format == "markdown":
            render_plan_risk_markdown(report, threshold)
        elif format == "sarif":
            # Convert changes to findings for SARIF output
            from infraguard.common.models import Finding

            for c in report.changes:
                report.findings.append(
                    Finding(
                        title=f"{c.action} {c.criticality.label} resource",
                        severity=c.criticality,
                        resource=c.address,
                        detail=c.detail,
                    )
                )
            render_sarif(report)
        else:
            render_plan_risk_table(report, threshold)

    # Exit code based on threshold
    if threshold is not None and report.total_score > threshold:
        raise typer.Exit(code=1)
