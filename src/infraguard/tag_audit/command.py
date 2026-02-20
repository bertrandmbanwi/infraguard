"""CLI subcommand for AWS tag compliance auditing."""

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
from infraguard.tag_audit.evaluator import evaluate
from infraguard.tag_audit.scanner import scan_aws, scan_from_file

app = typer.Typer(no_args_is_help=True)
console = Console(stderr=True)

@app.callback(invoke_without_command=True)
def tag_audit(
    file: Path | None = typer.Option(
        None,
        "--file",
        "-f",
        help="Path to resource JSON file (offline mode). If omitted, scans AWS live.",
        exists=True,
        readable=True,
    ),
    services: str | None = typer.Option(
        None,
        "--services",
        "-s",
        help="Comma-separated AWS services to scan (e.g., ec2,rds,s3). Default: all.",
    ),
    profile: str | None = typer.Option(
        None,
        "--profile",
        "-p",
        help="AWS profile name for live scanning.",
    ),
    region: str = typer.Option(
        "us-east-1",
        "--region",
        "-r",
        help="AWS region for live scanning.",
    ),
    rules: Path | None = typer.Option(
        None,
        "--rules",
        help="Path to custom tag policy YAML file.",
        exists=True,
        readable=True,
    ),
    min_compliance: float | None = typer.Option(
        None,
        "--min-compliance",
        help="Minimum compliance percentage. Exit 1 if below.",
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
    """Audit AWS resources for tag compliance.

    Scans AWS resources and checks tags against required tag policies.
    Supports live AWS scanning (boto3) or offline JSON file analysis.

    Examples:

        infraguard tag-audit --file resources.json

        infraguard tag-audit --services ec2,rds --profile production

        infraguard tag-audit --min-compliance 95 --format json
    """
    # Load custom rules if provided
    custom_required_tags = None
    custom_naming_rules = None
    custom_overrides = None
    if rules:
        from infraguard.common.config import load_rules

        rule_data = load_rules(rules)
        custom_required_tags = rule_data.get("required_tags")
        custom_naming_rules = rule_data.get("naming_conventions")
        custom_overrides = rule_data.get("resource_overrides")

    # Scan resources
    try:
        if file:
            resources = scan_from_file(file)
        else:
            svc_list = [s.strip() for s in services.split(",")] if services else None
            resources = scan_aws(services=svc_list, profile=profile, region=region)
    except Exception as e:
        if not quiet:
            console.print(f"[red]Error scanning resources: {e}[/red]")
        raise typer.Exit(code=2)

    if not resources:
        if not quiet:
            console.print("[dim]No resources found to audit.[/dim]")
        raise typer.Exit(code=0)

    # Evaluate
    report = evaluate(
        resources,
        required_tags=custom_required_tags,
        naming_rules=custom_naming_rules,
        resource_overrides=custom_overrides,
    )

    # Output
    compliance_pct = report.summary.get("compliance_percentage", 100.0)
    threshold_info = ""
    if min_compliance is not None:
        if compliance_pct < min_compliance:
            threshold_info = f"[bold red]Verdict: FAIL — compliance {compliance_pct}% below threshold ({min_compliance}%)[/bold red]"
        else:
            threshold_info = f"[bold green]Verdict: PASS — compliance {compliance_pct}% meets threshold ({min_compliance}%)[/bold green]"

    if not quiet:
        if format == "json":
            render_json(report)
        elif format == "markdown":
            render_findings_markdown(report, "Tag Compliance Report")
        elif format == "sarif":
            render_sarif(report)
        else:
            render_findings_table(report, "Tag Compliance Report", threshold_info)
            # Print service breakdown
            by_service = report.summary.get("by_service", {})
            if by_service:
                console.print("  [bold]By Service:[/bold]")
                for svc, stats in by_service.items():
                    pct = stats["percentage"]
                    color = "green" if pct >= 90 else "yellow" if pct >= 70 else "red"
                    console.print(
                        f"    {svc}: [{color}]{pct}% compliant[/{color}] "
                        f"({stats['compliant']}/{stats['total']})"
                    )
                console.print()

    # Exit code based on threshold
    if min_compliance is not None and compliance_pct < min_compliance:
        raise typer.Exit(code=1)
