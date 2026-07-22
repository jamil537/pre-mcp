# pre-mcp

Scans MCP server source code for malicious and vulnerable patterns that description-only scanners miss.

MCP clients (Claude Desktop, Cursor, Claude Code) only ever see a tool's name, description, and input schema. The implementation code never gets inspected. A server can have a perfectly clean description while the Python underneath runs `curl`, reads your SSH keys, or executes attacker-controlled SQL.

## Install

```bash
git clone https://github.com/jamil537/pre-mcp
cd pre-mcp
pip install -e ".[dev]"
```

## Usage

```bash
# Scan a local directory
pre-mcp scan ./my-mcp-server

# Scan a GitHub repo
pre-mcp scan https://github.com/owner/mcp-server

# JSON output for CI
pre-mcp scan ./my-mcp-server --format json --output results.json

# Fail CI on critical or high findings
pre-mcp scan ./my-mcp-server --fail-on high

# Show built-in rules
pre-mcp rules
```

## What it detects

**Python**

| Rule | Severity | What |
|---|---|---|
| `mcp-shell-injection` | CRITICAL | `subprocess.run(..., shell=True)` with LLM-supplied input |
| `mcp-prompt-injection-in-description` | CRITICAL | `<IMPORTANT>` or instruction markers in tool docstrings |
| `mcp-hidden-exfil-helper` | CRITICAL | Helper functions making outbound network or shell calls |
| `mcp-credential-file-access` | CRITICAL | Reads of `~/.ssh`, `~/.aws/credentials`, `.env`, `.mcp.json` |
| `mcp-dynamic-code-loading` | CRITICAL | `eval`, `exec`, dynamic `importlib` calls |
| `mcp-sql-injection` | CRITICAL | SQL built via f-string or string concatenation |
| `mcp-hidden-network-call` | HIGH | Outbound network calls in tool handlers not mentioned in the description |
| `mcp-background-thread-in-tool` | HIGH | Daemon threads spawned inside tool handlers |

**JavaScript / TypeScript**

| Rule | Severity | What |
|---|---|---|
| `mcp-js-shell-injection` | CRITICAL | `exec`/`execSync` with string argument, or `spawn` with `shell: true` |
| `mcp-js-hidden-exfil-helper` | CRITICAL | Helper functions making `fetch`/`axios`/`http.request` calls |
| `mcp-js-credential-file-access` | CRITICAL | `fs.readFile` on `~/.ssh`, `~/.aws/credentials`, `.env` |
| `mcp-js-dynamic-code` | CRITICAL | `eval()` or `new Function()` |
| `mcp-js-sql-injection` | CRITICAL | SQL template literals with interpolated variables |
| `mcp-js-background-exfil` | HIGH | `fetch`/`axios` inside `setTimeout`, `setImmediate`, `process.nextTick` |
| `mcp-prompt-injection-in-description` | CRITICAL | `<IMPORTANT>` or instruction markers in description strings |

Plus Bandit rules for general Python security issues.

## Custom rules

The MCP-specific ruleset is in `rules/mcp-specific.yml`. That's the actual contribution here. Bandit and Semgrep are just the engine.

Add your own:

```bash
pre-mcp scan ./server --rules ./my-rules.yml
```

## Limitations

This is a static analysis tool. It reads source code and matches patterns. It does not run the server.

What it won't catch:

- Payloads decoded at runtime (`base64.b64decode(...)` runs clean through the scanner)
- Dynamic method calls (`getattr(requests, method_name)(url)` looks fine statically)
- URLs or commands loaded from remote config at runtime
- Malicious code inside a dependency the server imports
- Compiled binaries (Go, Rust, C# servers are flagged as unanalysable)
- Time-delayed or conditional exfiltration

A clean scan means no known-bad patterns found. A malicious attacker who knows how to evade static analysis tools can still get through.

The real-world incidents this would have caught: postmark-mcp (exfil helper making outbound requests), Oura/SmartLoader (same pattern), CVE-2026-0755 (shell=True with unsanitised input).
