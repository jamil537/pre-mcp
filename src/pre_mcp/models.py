from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    REQUIRES_REVIEW = "requires-review"
    INFO = "info"


class Language(str, Enum):
    PYTHON = "python"
    NODE = "node"
    COMPILED = "compiled"
    UNKNOWN = "unknown"


@dataclass
class ToolDeclaration:
    name: str
    description: str
    schema: dict
    file: str
    line: int


@dataclass
class DependencyVuln:
    package: str
    version: str
    vuln_id: str
    description: str
    severity: str


@dataclass
class ScanTarget:
    identifier: str
    resolved_path: Path
    language: Language
    tools: list[ToolDeclaration] = field(default_factory=list)
    dep_vulns: list[DependencyVuln] = field(default_factory=list)
    source_hash: str = ""


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    file: str
    line: int
    snippet: str
    explanation: str
    tool_name: Optional[str] = None
