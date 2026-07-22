"""CLI entry point."""

import sys
from pathlib import Path

import click
from rich.console import Console

from . import stage0, stage1, stage3
from . import trust as _trust_mod
from .trust import _FIRST_SCAN
from .models import Severity

console = Console()  # for rules command

SEVERITY_LEVELS = ["critical", "high", "medium", "requires-review", "info"]


@click.group()
@click.version_option("0.1.0", prog_name="pre-mcp")
def main():
    """pre-mcp : static analysis for MCP server implementation code."""


@main.command()
@click.argument("target")
@click.option("--format", "fmt", type=click.Choice(["terminal", "json", "sarif"]), default="terminal")
@click.option("--output", "-o", type=click.Path(), default=None, help="Write report to file")
@click.option("--fail-on", type=click.Choice(SEVERITY_LEVELS), default=None, help="Exit non-zero if any finding at or above this severity")
@click.option("--no-deps", is_flag=True, default=False, help="Skip dependency vulnerability checks")
@click.option("--rules", "extra_rules", type=click.Path(exists=True), default=None, help="Additional Semgrep rule file")
def scan(target, fmt, output, fail_on, no_deps, extra_rules):
    """Scan an MCP server for malicious or vulnerable implementation patterns.

    TARGET can be a local path, GitHub URL, npm package name, or PyPI package name.
    """
    err = Console(stderr=True)

    err.print(f"[dim]Resolving {target}...[/dim]")

    try:
        scan_target = stage0.resolve(target, skip_deps=no_deps)
    except Exception as e:
        err.print(f"[red]Error resolving target: {e}[/red]")
        sys.exit(1)

    if scan_target.language.value == "compiled":
        err.print("[yellow]Unable to analyse: compiled or unsupported language. Source analysis not possible.[/yellow]")
        sys.exit(0)

    prev_hash = _trust_mod.check(target, scan_target.source_hash)
    if prev_hash is _FIRST_SCAN:
        err.print(f"[dim]First scan of this target. Hash recorded.[/dim]")
    elif prev_hash is not None:
        err.print(f"[bold yellow]Warning: source has changed since last scan.[/bold yellow] Previous hash: {prev_hash[:12]}...")

    err.print(f"[dim]Analysing {scan_target.language.value} source at {scan_target.resolved_path}...[/dim]")
    findings = stage1.analyse(scan_target, extra_rules=extra_rules)

    if fmt == "terminal":
        stage3.report_terminal(scan_target, findings)
        report_str = None
    elif fmt == "json":
        report_str = stage3.report_json(scan_target, findings)
    else:
        report_str = stage3.report_sarif(scan_target, findings)

    if report_str:
        if output:
            Path(output).write_text(report_str)
            err.print(f"Report written to {output}")
        else:
            print(report_str)

    _trust_mod.record(target, scan_target.source_hash)

    if fail_on:
        threshold = Severity(fail_on)
        order = {
            Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
            Severity.REQUIRES_REVIEW: 3, Severity.INFO: 4,
        }
        threshold_order = order[threshold]
        breaches = [f for f in findings if order.get(f.severity, 99) <= threshold_order]
        if breaches:
            sys.exit(1)


@main.command()
def rules():
    """List built-in MCP-specific detection rules."""
    import yaml
    rules_file = Path(__file__).parent.parent.parent / "rules" / "mcp-specific.yml"
    if not rules_file.exists():
        console.print("[red]Rules file not found.[/red]")
        return
    data = yaml.safe_load(rules_file.read_text())
    for rule in data.get("rules", []):
        console.print(f"[bold]{rule['id']}[/bold]  [{rule['severity']}]")
        console.print(f"  {rule['message'][:120].strip()}")
        console.print()
