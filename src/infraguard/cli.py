"""Main CLI entry point — registers all subcommands."""

from __future__ import annotations

import typer

from infraguard import __version__

app = typer.Typer(
    name="infraguard",
    help="Infrastructure guardrails for teams that ship fast.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"infraguard {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        help="Show version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """Infrastructure guardrails for teams that ship fast."""


# Register subcommands — imported here to avoid circular deps
from infraguard.iam_check.command import app as iam_check_app  # noqa: E402
from infraguard.plan_risk.command import app as plan_risk_app  # noqa: E402
from infraguard.tag_audit.command import app as tag_audit_app  # noqa: E402

app.add_typer(plan_risk_app, name="plan-risk", help="Score Terraform plan changes by blast radius.")
app.add_typer(tag_audit_app, name="tag-audit", help="Audit AWS resources for tag compliance.")
app.add_typer(iam_check_app, name="iam-check", help="Analyze IAM policies for least-privilege violations.")
