# VulnScan MCP Server

VulnScan speaks the [Model Context Protocol](https://modelcontextprotocol.io), so any
MCP-capable AI can drive the scanner directly: run scans, filter findings, manage
rules, export reports, apply fixes — and triage.

Triage is the part worth understanding. VulnScan does not call a model provider to
decide whether a finding is real. **The AI connected over MCP is the reviewer.** It reads
the findings and the surrounding source, judges each one, and writes verdicts back. Those
verdicts persist, and confirmed false positives stop appearing in later scans.

---

## Setup

### 1. Build it

```bash
cd /path/to/security-scanner
npm install --legacy-peer-deps
npm run build
```

> `--legacy-peer-deps` is required: `tree-sitter-php@0.24.2` declares a peer of
> `tree-sitter@^0.22.4` while the project uses `0.25.1`.

### 2. Confirm the server starts

```bash
node dist/mcp/server.js
# → [vulnscan-mcp] ready on stdio
```

It will sit waiting for protocol frames on stdin. Ctrl-C to exit. If you see that line,
the server is good and the rest is client configuration.

### 3. Add it to your AI

The server runs over **stdio** — your AI client launches it as a subprocess. Every client
below needs the same three things: the command (`node`), the path to
`dist/mcp/server.js`, and ideally a `cwd` set to the project you want scanned.

Replace `/path/to/security-scanner` throughout. On Windows use double backslashes in
JSON (`C:\\Users\\you\\security-scanner`) or forward slashes.

---

#### Claude Code

One command, from inside the project you want to scan:

```bash
claude mcp add vulnscan -- node /path/to/security-scanner/dist/mcp/server.js
```

Then `/mcp` inside Claude Code to confirm it connected. Add `--scope project` to share
it with your team via `.mcp.json`, or `--scope user` to enable it everywhere.

#### Claude Desktop

Edit `claude_desktop_config.json`:

- **macOS** — `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows** — `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux** — `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "vulnscan": {
      "command": "node",
      "args": ["/path/to/security-scanner/dist/mcp/server.js"],
      "cwd": "/path/to/the/project/you/want/scanned"
    }
  }
}
```

Restart Claude Desktop. The tools appear under the connectors icon.

#### Cursor

`.cursor/mcp.json` in your project (or `~/.cursor/mcp.json` for all projects):

```json
{
  "mcpServers": {
    "vulnscan": {
      "command": "node",
      "args": ["/path/to/security-scanner/dist/mcp/server.js"]
    }
  }
}
```

Settings → MCP to verify it shows as connected.

#### Windsurf

`~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "vulnscan": {
      "command": "node",
      "args": ["/path/to/security-scanner/dist/mcp/server.js"]
    }
  }
}
```

#### VS Code (Copilot agent mode)

`.vscode/mcp.json`:

```json
{
  "servers": {
    "vulnscan": {
      "type": "stdio",
      "command": "node",
      "args": ["/path/to/security-scanner/dist/mcp/server.js"]
    }
  }
}
```

#### Cline / Roo Code

`cline_mcp_settings.json` (MCP Servers → Configure):

```json
{
  "mcpServers": {
    "vulnscan": {
      "command": "node",
      "args": ["/path/to/security-scanner/dist/mcp/server.js"],
      "disabled": false
    }
  }
}
```

#### Zed

`settings.json`:

```json
{
  "context_servers": {
    "vulnscan": {
      "command": { "path": "node", "args": ["/path/to/security-scanner/dist/mcp/server.js"] }
    }
  }
}
```

#### Anything else

Any MCP client can launch it. The contract is: run `node dist/mcp/server.js`, speak
JSON-RPC over stdin/stdout. `vulnscan --mcp` is an equivalent entry point, and
`npm link` makes `vulnscan-mcp` available on `PATH`.

To verify a client-independent connection by hand:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}' \
  | node dist/mcp/server.js
```

A JSON response containing `"serverInfo":{"name":"vulnscan"...}` means it works.

---

## Using it

Once connected, just ask:

- *"Scan this project for security vulnerabilities."*
- *"Review the security of my current branch."*
- *"Triage these findings and tell me which are actually exploitable."*
- *"Fix the SQL injection in routes/users.js."*
- *"Write a custom rule that flags our internal `LEGACY_TOKEN_` credentials."*
- *"Export a SARIF report for CI."*

Three prompts are registered as shortcuts: `security_review`, `review_my_changes`, and
`fix_vulnerability` (in Claude Code these are slash commands).

---

## The triage loop

This is what replaces the usual "SAST tool dumps 200 findings, 180 are noise" problem.

```
scan                → findings, each with a findingKey and a codeHash
get_review_queue    → unreviewed findings + surrounding source + a heuristic hint
   ↓ the AI reads the context and decides
submit_triage       → verdicts stored in .vulnscan-cache/triage.json
scan (again)        → confirmed false positives are gone
```

Three properties make this trustworthy rather than just convenient:

**Suppression is never silent.** Every scan reports how many findings were hidden:

```
Files: 214   Findings: 12   Time: 3.41s
Triage: 47 hidden as reviewed false positives — use --no-triage to show all
```

**Verdicts are bound to the code they were made about.** Each verdict stores a hash of
the reviewed line. Edit that line and the verdict is discarded, the finding comes back,
and the scan reports `N verdicts stale (code changed since review)`. A dismissal cannot
outlive the code it was about.

**Bad verdicts are rejected, not defaulted.** A verdict with no reasoning, a missing
`codeHash`, or an invalid severity is refused and reported back. In a batch, only the
malformed verdicts are rejected — the rest still store. Nothing silently becomes
"false positive", because that would hide a real vulnerability.

Inspect the store any time:

```bash
vulnscan --triage-stats     # counts
vulnscan --no-triage .      # scan ignoring all verdicts
```

or read the `vulnscan://triage` resource.

---

## Tools

### Scanning
| Tool | Purpose |
|---|---|
| `scan` | Full scan — AST rules, regex, taint analysis, CPG dataflow, secrets, dependency CVEs |
| `scan_git_diff` | Only files changed between two refs — the right tool for branch/PR review |
| `scan_dependencies` | Manifests against OSV.dev (needs network) |
| `scan_secrets` | Entropy + pattern secret detection |
| `scan_snippet` | Run the engine over a snippet without writing it to disk |

### Triage
| Tool | Purpose |
|---|---|
| `get_review_queue` | Findings needing review, with source context and review instructions |
| `submit_triage` | Record verdicts — drives suppression and severity correction |
| `get_triage` | Read the stored review history |
| `get_finding_context` | Numbered source lines around any file:line |

### Fixes
| Tool | Purpose |
|---|---|
| `suggest_fix` | Current code plus a template patch for the rule |
| `apply_fix` | Exact-match replacement, then re-scan the file |

`apply_fix` refuses ambiguous edits: `oldCode` must match exactly and appear exactly
once, and the optional `expectedLine` guard rejects a match more than three lines away.
Approximate edits to security-relevant code are worse than none.

### Rules & reporting
| Tool | Purpose |
|---|---|
| `list_rules` / `rule_summary` | Rule catalogue and coverage |
| `create_custom_rule` | Write a project rule to `.vulnscan-rules/`, verifying it loads |
| `init_example_rules` | Starter rule templates |
| `export_report` | Write json / sarif / html / pretty to disk |
| `cache_stats` / `clear_cache` | Incremental cache and triage statistics |

### Resources
| URI | Contents |
|---|---|
| `vulnscan://rules` | Full rule catalogue |
| `vulnscan://last-scan` | Complete untruncated findings from the last scan |
| `vulnscan://triage` | All stored verdicts |

Tool responses cap inline findings at 40; read `vulnscan://last-scan` for the rest.

---

## Notes on rule selection

`--rules` / the `rules` argument takes declared rule IDs (`sql-injection`, `xss`, …).
The taint engines emit synthesised IDs — `cpg-precise-sql`, `interproc-taint`,
`entropy-*`, `dep-cve` — and selecting the matching declared rule includes them. Asking
for `sql-injection` gets you `cpg-precise-sql` too.

`severity` and `confidence` are thresholds on **findings**, not on rule declarations. A
rule declared "high" can emit a critical finding, so filtering rule metadata would drop
the wrong things.

---

## Troubleshooting

**Server not connecting.** Run `node dist/mcp/server.js` directly. If you don't see
`[vulnscan-mcp] ready on stdio`, run `npm run build` and check for TypeScript errors.

**"Cannot find module".** Use an absolute path to `dist/mcp/server.js`. Most clients do
not resolve relative paths from where you think they do.

**Scanning the wrong directory.** The server scans relative to its working directory. Set
`cwd` in the client config, or pass absolute `paths` to the scan tools.

**Dependency scanning returns nothing.** It queries `api.osv.dev` over the network. In a
sandboxed client, pass `deps: false` to skip it.

**Verdicts don't suppress.** Check `vulnscan --triage-stats`. If findings show as stale,
the code changed since review — that is the intended behaviour, so review them again.
Triage state lives in `.vulnscan-cache/triage.json`, relative to the working directory,
so a different `cwd` means a different store.
