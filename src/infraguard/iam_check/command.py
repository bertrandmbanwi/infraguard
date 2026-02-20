"""CLI subcommand for IAM policy least-privilege analysis."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from infraguard.common.reporter import (
    render_findings_markdown,
    render_findings_table,
    render_json,
    render_sarif,
)
from infraguard.iam_check.analyzer import analyze_aws_role, analyze_policy_file

app = typer.Typer(no_args_is_help=True)
console = Console(stderr=True)


def _parse_max_findings(value: str) -> dict[str, int]:
    """Parse max-findings threshold string like 'critical:0,high:3'."""
    result = {}
    for part in value.split(","):
        parts = part.strip().split(":")
        if len(parts) == 2:
            result[parts[0].strip().upper()] = int(parts[1].strip())
    return result


@app.callback(invoke_without_command=True)
def iam_check(
    file: Path | None = typer.Option(
        None,
        "--file",
        "-f",
        help="Path to IAM policy JSON file. Supports single policy or multi-policy format.",
        exists=True,
        readable=True,
    ),
    role: str | None = typer.Option(
        None,
        "--role",
        "-r",
        help="AWS IAM role name to analyze (requires boto3).",
    ),
    profile: str | None = typer.Option(
        None,
        "--profile",
        "-p",
        help="AWS profile name for live scanning.",
    ),
    max_findings: str | None = typer.Option(
        None,
        "--max-findings",
        help="Severity thresholds for CI gating (e.g., 'critical:0,high:3'). Exit 1 if exceeded.",
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
    """Analyze IAM policies for least-privilege violations.

    Evaluates AWS IAM policies for overpermissive wildcards, dangerous
    actions, missing conditions, and admin access. Works with policy
    JSON files or live AWS role analysis.

    Examples:

        infraguard iam-check --file policy.json

        infraguard iam-check --role my-lambda-role --profile production

        infraguard iam-check --file policy.json --max-findings critical:0,high:3
    """
    if not file and not role:
        console.print("[red]Error: provide --file or --role[/red]")
        raise typer.Exit(code=2)

    try:
        if file:
            report = analyze_policy_file(file)
        else:
            report = analyze_aws_role(role, profile=profile)
    except Exception as e:
        if not quiet:
            console.print(f"[red]Error analyzing policies: {e}[/red]")
        raise typer.Exit(code=2)

    # Check thresholds
    threshold_info = ""
    exceeded = False
    if max_findings:
        thresholds = _parse_max_findings(max_findings)
        counts = report.severity_counts()
        violations = []
        for sev_name, max_count in thresholds.items():
            actual = counts.get(sev_name, 0)
            if actual > max_count:
                violations.append(f"{sev_name}: {actual} > {max_count}")
                exceeded = True

        if exceeded:
            threshold_info = f"[bold red]Verdict: FAIL — thresholds exceeded: {', '.join(violations)}[/bold red]"
        else:
            threshold_info = "[bold green]Verdict: PASS — all findings within thresholds[/bold green]"

    # Print suggestions for high-severity findings
    if not quiet:
        if format == "json":
            render_json(report)
        elif format == "markdown":
            render_findings_markdown(report, "IAM Policy Analysis")
        elif format == "sarif":
            render_sarif(report)
        else:
            render_findings_table(report, "IAM Policy Analysis", threshold_info)

            # Print suggestions for top findings
            high_findings = [f for f in report.findings if f.severity >= 7 and f.suggestion]
            if high_findings:
                console.print("  [bold]Suggestions:[/bold]")
                for f in high_findings[:5]:
                    console.print(f"    [dim]→[/dim] {f.suggestion}")
                console.print()

    if exceeded:
        raise typer.Exit(code=1)
