"""Stage 3: Reporting : terminal (rich), JSON, SARIF."""

import json
from pathlib import Path

from rich.console import Console
from rich.syntax import Syntax

from .models import Finding, Language, ScanTarget, Severity

SEVERITY_COLOURS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.REQUIRES_REVIEW: "cyan",
    Severity.INFO: "dim white",
}

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.REQUIRES_REVIEW: 3,
    Severity.INFO: 4,
}


def _clean(s: str) -> str:
    """Strip control characters that break JSON serialisation."""
    return "".join(c for c in s if c >= " " or c in "\n\t")


def report_terminal(target: ScanTarget, findings: list[Finding]) -> None:
    console = Console(highlight=False)
    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    # Filter INFO from display -- too noisy, available in JSON output
    display = [f for f in sorted_findings if f.severity != Severity.INFO]
    info_count = len(sorted_findings) - len(display)

    console.print()
    console.print(f"[bold]pre-mcp[/bold]  [dim]{target.identifier}[/dim]")
    console.print(
        f"Language: [bold]{target.language.value}[/bold]  "
        f"Tools: [bold]{len(target.tools)}[/bold]  "
        f"Findings: [bold]{len(display)}[/bold]"
        + (f" [dim](+{info_count} info)[/dim]" if info_count else "")
    )

    by_severity: dict[Severity, list[Finding]] = {}
    for f in display:
        by_severity.setdefault(f.severity, []).append(f)

    summary_parts = []
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.REQUIRES_REVIEW]:
        if sev in by_severity:
            c = SEVERITY_COLOURS[sev]
            summary_parts.append(f"[{c}]{len(by_severity[sev])} {sev.value}[/{c}]")
    if summary_parts:
        console.print("  " + "  ".join(summary_parts))
    console.print()

    if not display:
        console.print("[green]✓ No findings.[/green]")
        if info_count:
            console.print(f"[dim]  {info_count} low-severity findings hidden. Use --format json to see all.[/dim]")
        return

    for finding in display:
        colour = SEVERITY_COLOURS[finding.severity]
        # Shorten file path to relative if possible
        fpath = finding.file
        try:
            fpath = str(Path(finding.file).relative_to(target.resolved_path))
        except (ValueError, TypeError):
            pass

        console.print(f"[{colour}][{finding.severity.value.upper()}][/{colour}]  {finding.rule_id}")
        console.print(f"  [dim]{fpath}:{finding.line}[/dim]")
        if finding.tool_name:
            console.print(f"  Tool: [bold]{finding.tool_name}[/bold]")
        # Wrap explanation at 100 chars
        explanation = (finding.explanation or "").strip()
        if len(explanation) > 120:
            explanation = explanation[:117] + "..."
        console.print(f"  {explanation}")
        if finding.snippet and finding.snippet.lower().strip() not in ("requires login", "login required"):
            snippet = finding.snippet[:200].strip()
            if snippet:
                console.print(f"  [dim]{snippet}[/dim]")
        console.print()

    if target.dep_vulns:
        console.print(f"[yellow]Dependency vulnerabilities: {len(target.dep_vulns)}[/yellow]")
        for dv in target.dep_vulns[:5]:
            console.print(f"  {dv.package}@{dv.version}: {dv.vuln_id} ({dv.severity})")
        if len(target.dep_vulns) > 5:
            console.print(f"  ... and {len(target.dep_vulns) - 5} more")

    if target.language == Language.COMPILED:
        console.print("[yellow]Warning: compiled or unsupported language. Source analysis not possible.[/yellow]")

    # Footer summary
    console.rule()
    crit = sum(1 for f in display if f.severity == Severity.CRITICAL)
    high = sum(1 for f in display if f.severity == Severity.HIGH)
    if crit:
        console.print(f"[bold red]{crit} critical finding{'s' if crit != 1 else ''}.[/bold red]")
    elif high:
        console.print(f"[red]{high} high-severity finding{'s' if high != 1 else ''}.[/red]")
    else:
        console.print("[yellow]Review before deploying.[/yellow]")


def report_json(target: ScanTarget, findings: list[Finding]) -> str:
    def _finding_dict(f: Finding) -> dict:
        d = {
            "rule_id": f.rule_id,
            "severity": f.severity.value,
            "file": f.file,
            "line": f.line,
            "snippet": _clean(f.snippet or ""),
            "explanation": _clean(f.explanation or ""),
        }
        if f.tool_name:
            d["tool_name"] = f.tool_name
        return d

    output = {
        "target": {
            "identifier": target.identifier,
            "language": target.language.value,
            "source_hash": target.source_hash,
            "tools": [
                {"name": t.name, "description": t.description, "file": t.file, "line": t.line}
                for t in target.tools
            ],
        },
        "findings": [_finding_dict(f) for f in findings],
        "dep_vulns": [
            {"package": d.package, "version": d.version, "vuln_id": d.vuln_id, "severity": d.severity}
            for d in target.dep_vulns
        ],
        "summary": {
            "total": len(findings),
            "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "requires_review": sum(1 for f in findings if f.severity == Severity.REQUIRES_REVIEW),
            "info": sum(1 for f in findings if f.severity == Severity.INFO),
        },
    }
    return json.dumps(output, indent=2)


def report_sarif(target: ScanTarget, findings: list[Finding]) -> str:
    rules: dict[str, dict] = {}
    for f in findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "shortDescription": {"text": (f.explanation or "")[:100]},
                "fullDescription": {"text": f.explanation or ""},
                "defaultConfiguration": {"level": _sarif_level(f.severity)},
            }

    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule_id,
            "level": _sarif_level(f.severity),
            "message": {"text": _clean(f.explanation or "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file or "unknown"},
                    "region": {"startLine": max(f.line or 1, 1)},
                }
            }],
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "pre-mcp",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/precursorsecurity/pre-mcp",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def _sarif_level(sev: Severity) -> str:
    return {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.REQUIRES_REVIEW: "note",
        Severity.INFO: "none",
    }.get(sev, "none")
