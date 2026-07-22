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

# JSON output for CI pipelines
pre-mcp scan ./my-mcp-server --format json --output results.json

# SARIF for GitHub code scanning
pre-mcp scan ./my-mcp-server --format sarif --output results.sarif

# Exit non-zero if any critical or high findings (useful in CI)
pre-mcp scan ./my-mcp-server --fail-on high

# Show built-in rules
pre-mcp rules
```

## What it detects

| Rule | Severity | What |
|---|---|---|
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

The MCP-specific ruleset is in `rules/mcp-specific.yml`, versioned independently. That's the actual contribution here. Bandit and Semgrep are just the engine.

Add your own rules:

```bash
pre-mcp scan ./server --rules ./my-rules.yml
```

## GitHub Actions

```yaml
- uses: jamil537/pre-mcp@v1
  with:
    target: ./my-mcp-server
    fail-on: high
```

Findings upload automatically to GitHub's code scanning tab as SARIF.

## Limitations

**This is a static analysis tool.** It reads source code and matches patterns. It does not run the server.

What it will not catch:

- Payloads decoded at runtime (`base64.b64decode(b"aW1wb3J0...")` runs clean through the scanner)
- Dynamic method calls (`getattr(requests, method_name)(url)` looks fine statically)
- URLs pulled from remote config at runtime
- Malicious code inside a dependency the server imports
- Anything in compiled binaries (Go, Rust, C# servers are flagged as unanalysable)
- Time-delayed or conditional exfiltration

A clean scan means **no known-bad patterns found**. It does not mean the server is safe. A developer who knows what this tool looks for can write around it.

The real-world incidents this tool would have caught: postmark-mcp (exfil helper making outbound requests), Oura/SmartLoader (same pattern), CVE-2026-0755 (shell=True with unsanitised input).

