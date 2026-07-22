"""Stage 1: Deterministic static analysis : Bandit + custom MCP Semgrep rules.

No Semgrep registry rules are used (they require login in Semgrep >= 1.50).
Analysis is fully offline: custom rules shipped with the package + Bandit.
"""

import json
import subprocess
import sys
from pathlib import Path

from .models import Finding, Language, ScanTarget, Severity, ToolDeclaration

RULES_DIR = Path(__file__).parent.parent.parent / "rules"


def analyse(target: ScanTarget, extra_rules: str | None = None) -> list[Finding]:
    if target.language == Language.COMPILED:
        return []

    findings: list[Finding] = []
    findings.extend(_run_semgrep_custom(target))
    if extra_rules:
        findings.extend(_run_semgrep(target.resolved_path, extra_rules, timeout=180))
    findings.extend(_run_bandit(target))
    _annotate_tool_names(findings, target.tools, target.resolved_path)
    return _deduplicate(findings)


def _run_semgrep_custom(target: ScanTarget) -> list[Finding]:
    rules_file = RULES_DIR / "mcp-specific.yml"
    if not rules_file.exists():
        print(f"[warn] custom rules file not found: {rules_file}", file=sys.stderr)
        return []

    # Scan identified tool files individually -- faster and avoids scanning test dirs
    tool_files = list({t.file for t in target.tools})
    if tool_files:
        findings = []
        for tf in tool_files:
            full = target.resolved_path / tf
            if full.exists():
                findings.extend(_run_semgrep(full, str(rules_file), timeout=180))
        return findings

    # Fallback: scan the directory with semgrep, excluding noise dirs
    return _run_semgrep(
        target.resolved_path, str(rules_file), timeout=300,
        exclude=["node_modules", "__pycache__", "dist", "build", ".next", ".venv", "venv"],
    )


def _run_semgrep(path: Path, config: str, timeout: int = 120, exclude: list[str] | None = None) -> list[Finding]:
    cmd = ["semgrep", "--config", config, "--json", "--no-autofix"]
    for ex in (exclude or []):
        cmd += ["--exclude", ex]
    cmd.append(str(path))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,)
    except subprocess.TimeoutExpired:
        print(f"[warn] semgrep timed out scanning {path}", file=sys.stderr)
        return []
    except FileNotFoundError:
        print("[warn] semgrep not found : install with: pip install semgrep", file=sys.stderr)
        return []

    if result.returncode not in (0, 1):  # 0=ok, 1=findings found; anything else is an error
        print(f"[warn] semgrep exited {result.returncode} for {path}: {result.stderr[:200]}", file=sys.stderr)

    try:
        data = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        print(f"[warn] semgrep produced unparseable output for {path}", file=sys.stderr)
        return []

    findings = []
    for r in data.get("results", []):
        snippet = r.get("extra", {}).get("lines", "").strip()
        # Filter out Semgrep login-gated snippets
        if snippet.lower().strip() in ("requires login", "login required", ""):
            snippet = ""
        sev = _map_semgrep_severity(r.get("extra", {}).get("severity", "WARNING"))
        findings.append(Finding(
            rule_id=r.get("check_id", "semgrep-unknown"),
            severity=sev,
            file=r.get("path", ""),
            line=r.get("start", {}).get("line", 0),
            snippet=snippet,
            explanation=r.get("extra", {}).get("message", ""),
        ))
    return findings


def _run_bandit(target: ScanTarget) -> list[Finding]:
    if target.language != Language.PYTHON:
        return []
    try:
        result = subprocess.run(
            ["bandit", "-r", str(target.resolved_path), "-f", "json", "-q",
             "--skip", "B101,B311"],  # skip assert and random -- too noisy for MCP context
            capture_output=True, text=True, timeout=120,
        )
        data = json.loads(result.stdout or "{}")
    except subprocess.TimeoutExpired:
        print("[warn] bandit timed out", file=sys.stderr)
        return []
    except (json.JSONDecodeError, FileNotFoundError):
        return []

    findings = []
    for r in data.get("results", []):
        sev = _map_bandit_severity(r.get("issue_severity", "LOW"))
        findings.append(Finding(
            rule_id=f"bandit-{r.get('test_id', 'unknown')}",
            severity=sev,
            file=r.get("filename", ""),
            line=r.get("line_number", 0),
            snippet=r.get("code", "").strip()[:300],
            explanation=r.get("issue_text", ""),
        ))
    return findings


def _map_semgrep_severity(s: str) -> Severity:
    return {
        "ERROR": Severity.CRITICAL,
        "WARNING": Severity.HIGH,
        "INFO": Severity.INFO,
    }.get(s.upper(), Severity.INFO)


def _map_bandit_severity(s: str) -> Severity:
    return {
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.INFO,
    }.get(s.upper(), Severity.INFO)


def _annotate_tool_names(
    findings: list[Finding],
    tools: list[ToolDeclaration],
    base_path: Path,
) -> None:
    for f in findings:
        # Normalise to relative path for comparison -- Semgrep may return absolute
        try:
            f_rel = str(Path(f.file).relative_to(base_path))
        except (ValueError, TypeError):
            f_rel = f.file
        for tool in tools:
            if tool.file == f_rel and abs(tool.line - f.line) < 50:
                f.tool_name = tool.name
                break


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    unique = []
    for f in findings:
        key = (f.rule_id, f.file, f.line)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
