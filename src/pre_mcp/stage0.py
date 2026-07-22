"""Stage 0: Resolve target to source, detect language, inventory MCP tools."""

import ast
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from .models import DependencyVuln, Language, ScanTarget, ToolDeclaration


def resolve(target: str, skip_deps: bool = False) -> ScanTarget:
    path = _resolve_to_path(target)
    lang = _detect_language(path)
    tools = _inventory_tools(path, lang)
    dep_vulns = [] if skip_deps else _dep_audit(path, lang)
    src_hash = _hash_source(path)
    return ScanTarget(
        identifier=target,
        resolved_path=path,
        language=lang,
        tools=tools,
        dep_vulns=dep_vulns,
        source_hash=src_hash,
    )


def _resolve_to_path(target: str) -> Path:
    p = Path(target)
    if p.exists():
        return p.resolve()

    parsed = urlparse(target)
    if parsed.scheme in ("http", "https") and "github.com" in parsed.netloc:
        return _clone_github(target)

    if target.startswith("npm:") or _looks_like_npm(target):
        pkg = target.removeprefix("npm:")
        return _download_npm(pkg)

    if target.startswith("pypi:") or _looks_like_pypi(target):
        pkg = target.removeprefix("pypi:")
        return _download_pypi(pkg)

    raise ValueError(f"Cannot resolve target: {target}")


def _clone_github(url: str) -> Path:
    try:
        import git
    except ImportError:
        raise RuntimeError("gitpython not installed. Run: pip install gitpython")
    tmp = Path(tempfile.mkdtemp(prefix="pms-"))
    try:
        git.Repo.clone_from(url, tmp, depth=1)
    except Exception:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return tmp


def _download_npm(package: str) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="pms-"))
    try:
        subprocess.run(["npm", "pack", package, "--pack-destination", str(tmp)], check=True, capture_output=True)
    except FileNotFoundError:
        raise RuntimeError("npm not found : install Node.js to scan npm packages")
    tarballs = list(tmp.glob("*.tgz"))
    if not tarballs:
        raise RuntimeError(f"npm pack produced no tarball for {package}")
    subprocess.run(["tar", "-xzf", str(tarballs[0]), "-C", str(tmp)], check=True, capture_output=True)
    pkg_dir = tmp / "package"
    return pkg_dir if pkg_dir.exists() else tmp


def _download_pypi(package: str) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="pms-"))
    try:
        subprocess.run(
            ["pip", "download", "--no-deps", "--no-binary=:all:", "-d", str(tmp), package],
            check=True, capture_output=True,
        )
    except FileNotFoundError:
        raise RuntimeError("pip not found : install Python pip to scan PyPI packages")
    tarballs = list(tmp.glob("*.tar.gz"))
    wheels = list(tmp.glob("*.whl"))
    if not tarballs and not wheels:
        raise RuntimeError(f"pip download produced nothing for {package}")
    if tarballs:
        import tarfile
        with tarfile.open(tarballs[0], "r:gz") as tar:
            tar.extractall(tmp)
    else:
        subprocess.run(["python", "-m", "zipfile", "-e", str(wheels[0]), str(tmp)], capture_output=True)
    dirs = [d for d in tmp.iterdir() if d.is_dir()]
    return dirs[0] if dirs else tmp


def _looks_like_npm(target: str) -> bool:
    return bool(re.match(r"^(@[a-z0-9-]+/)?[a-z0-9._-]+(@[\d.]+)?$", target)) and "/" not in target.lstrip("@").split("/")[0] if target.startswith("@") else bool(re.match(r"^[a-z0-9._-]+(@[\d.]+)?$", target))


def _looks_like_pypi(target: str) -> bool:
    return bool(re.match(r"^[a-zA-Z0-9_.-]+$", target))


def _detect_language(path: Path) -> Language:
    py_count = len(list(path.rglob("*.py")))
    js_count = len(list(path.rglob("*.js"))) + len(list(path.rglob("*.ts")))
    bin_count = len([f for f in path.rglob("*") if f.is_file() and _is_binary(f)])

    if py_count == 0 and js_count == 0 and bin_count > 0:
        return Language.COMPILED
    if py_count >= js_count:
        return Language.PYTHON if py_count > 0 else Language.UNKNOWN
    return Language.NODE


def _is_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            chunk = f.read(1024)
        return b"\x00" in chunk
    except Exception:
        return False


def _inventory_tools(path: Path, lang: Language) -> list[ToolDeclaration]:
    tools = []
    if lang == Language.PYTHON:
        tools.extend(_inventory_python_tools(path))
    elif lang == Language.NODE:
        tools.extend(_inventory_node_tools(path))
    return tools


def _inventory_python_tools(path: Path) -> list[ToolDeclaration]:
    tools = []
    # Regex fallback for low-level SDK: Tool(name="...", description="...")
    tool_ctor = re.compile(
        r'Tool\s*\(\s*name\s*=\s*["\']([^"\']+)["\']\s*,\s*description\s*=\s*["\']([^"\']*)["\']',
        re.MULTILINE,
    )
    for pyfile in path.rglob("*.py"):
        try:
            source = pyfile.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source)
        except SyntaxError:
            continue

        # FastMCP / @mcp.tool() / @server.tool() decorator pattern
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            for dec in node.decorator_list:
                if _is_mcp_tool_decorator(dec):
                    desc = ast.get_docstring(node) or ""
                    schema = _extract_schema_from_args(node)
                    tools.append(ToolDeclaration(
                        name=node.name,
                        description=desc,
                        schema=schema,
                        file=str(pyfile.relative_to(path)),
                        line=node.lineno,
                    ))

        # Low-level SDK: Tool(name="...", description="...") constructor
        for m in tool_ctor.finditer(source):
            line = source[: m.start()].count("\n") + 1
            tools.append(ToolDeclaration(
                name=m.group(1),
                description=m.group(2),
                schema={},
                file=str(pyfile.relative_to(path)),
                line=line,
            ))
    return tools


def _is_mcp_tool_decorator(node: ast.expr) -> bool:
    if isinstance(node, ast.Attribute) and node.attr == "tool":
        return True
    if isinstance(node, ast.Call):
        return _is_mcp_tool_decorator(node.func)
    if isinstance(node, ast.Name) and node.id == "tool":
        return True
    return False


def _extract_schema_from_args(node: ast.FunctionDef) -> dict:
    params = {}
    for arg in node.args.args:
        if arg.arg == "self":
            continue
        annotation = ast.unparse(arg.annotation) if arg.annotation else "any"
        params[arg.arg] = {"type": annotation}
    return {"properties": params}


def _inventory_node_tools(path: Path) -> list[ToolDeclaration]:
    tools = []
    # Matches multiple real MCP SDK patterns:
    # server.tool("name", "description", ...) -- newer SDK
    # server.tool("name", { description: "..." }, ...) -- schema-first
    # { name: "name", description: "description" } -- ListToolsResult objects
    patterns = [
        # server.tool("name", "description", ...) or server.tool("name", {description: "..."}, ...)
        re.compile(
            r'(?:server|mcp)\.tool\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']*)["\']',
            re.MULTILINE,
        ),
        # { name: "name", description: "desc" } in ListTools handlers
        re.compile(
            r'\{\s*name:\s*["\']([^"\']+)["\']\s*,\s*description:\s*["\']([^"\']*)["\']',
            re.MULTILINE,
        ),
    ]
    seen: set[tuple] = set()
    for jsfile in list(path.rglob("*.js")) + list(path.rglob("*.ts")) + list(path.rglob("*.mjs")):
        # skip node_modules, dist, build
        if any(p in jsfile.parts for p in ("node_modules", "dist", "build", ".next")):
            continue
        try:
            content = jsfile.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for pattern in patterns:
            for m in pattern.finditer(content):
                name, desc = m.group(1), m.group(2)
                key = (str(jsfile), name)
                if key in seen:
                    continue
                seen.add(key)
                line = content[: m.start()].count("\n") + 1
                tools.append(ToolDeclaration(
                    name=name,
                    description=desc.strip(),
                    schema={},
                    file=str(jsfile.relative_to(path)),
                line=line,
            ))
    return tools


def _dep_audit(path: Path, lang: Language) -> list[DependencyVuln]:
    vulns = []
    if lang == Language.PYTHON:
        req = path / "requirements.txt"
        setup = path / "setup.py"
        pyproject = path / "pyproject.toml"
        if any(f.exists() for f in [req, setup, pyproject]):
            try:
                result = subprocess.run(
                    ["pip-audit", "--format", "json", "-r", str(req)] if req.exists()
                    else ["pip-audit", "--format", "json"],
                    capture_output=True, text=True, cwd=str(path),
                )
                data = json.loads(result.stdout or "[]")
                for item in data:
                    for v in item.get("vulns", []):
                        vulns.append(DependencyVuln(
                            package=item["name"], version=item["version"],
                            vuln_id=v["id"], description=v["description"],
                            severity=v.get("fix_versions", ["unknown"])[0],
                        ))
            except Exception:
                pass

    elif lang == Language.NODE:
        pkg_json = path / "package.json"
        if pkg_json.exists():
            try:
                result = subprocess.run(
                    ["npm", "audit", "--json"],
                    capture_output=True, text=True, cwd=str(path),
                )
                data = json.loads(result.stdout or "{}")
                for name, vuln in data.get("vulnerabilities", {}).items():
                    vulns.append(DependencyVuln(
                        package=name, version=vuln.get("range", "unknown"),
                        vuln_id=vuln.get("via", [{}])[0] if isinstance(vuln.get("via", [{}])[0], str) else "unknown",
                        description=str(vuln.get("via", ["unknown"])[0]),
                        severity=vuln.get("severity", "unknown"),
                    ))
            except Exception:
                pass
    return vulns


def _hash_source(path: Path) -> str:
    h = hashlib.sha256()
    skip = {".git", "node_modules", "__pycache__", ".venv"}
    for f in sorted(path.rglob("*")):
        if any(s in f.parts for s in skip):
            continue
        if f.is_file():
            try:
                h.update(f.read_bytes())
            except Exception:
                pass
    return h.hexdigest()
