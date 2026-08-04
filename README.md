<p align="center">
  <img src="docs/banner.png" alt="Throughline" width="100%">
</p>

# Throughline

A production-grade static application security testing (SAST) tool. Multi-engine hybrid analysis combining regex patterns, tree-sitter AST queries, inter-procedural call graphs, code property graphs (CPG), SSA form, points-to analysis, function summaries, entropy-based secret detection, OSV-backed dependency CVE scanning, MCP-driven AI triage, and incremental diff scanning — all in a single Node.js binary.

No external language toolchains needed. Works on any codebase.

---

## Quick Start

```bash
npm install --legacy-peer-deps
npm run build
node dist/index.js ./your-project
```

> Requires **Node 22 or newer** — tree-sitter's native addon does not build
> under Node 20.
>
> `--legacy-peer-deps` is required: `tree-sitter-php@0.24.2` declares a peer of
> `tree-sitter@^0.22.4` while the project uses `0.25.1`.

Driving it from an AI instead? See **[docs/MCP.md](docs/MCP.md)**.

### Global install

```bash
npm install -g .
throughline ./src
```

---

## Usage

```
throughline [options] <paths...>

Options:
  -f, --format <type>     Output format (default: pretty)
                          pretty — colorized terminal output
                          json   — machine-readable JSON
                          sarif  — SARIF 2.1.0 (GitHub/GitLab)
                          html   — interactive dark-theme HTML report
  -o, --output <file>     Write output to file (default: stdout)
  -r, --rules <ids>       Comma-separated rule IDs (default: all 31 rules)
  -s, --severity <level>  Minimum severity: critical, high, medium, low, info
  -c, --confidence <lvl>  Minimum confidence: certain, high, medium, low
  -e, --extensions <exts> Extensions to scan (.js,.ts,.py,.go,...)
  -x, --exclude <dirs>    Extra directories to exclude

  --no-entropy            Disable entropy-based secrets detection
  --no-deps               Disable dependency CVE scanning
  --incremental           Only scan changed files (uses .throughline-cache)
  --clear-cache           Clear incremental cache
  --git-aware             Only scan files changed in git (HEAD~1..HEAD)
  --git-base <ref>        Git base ref for diff (default: HEAD~1)
  --cache-stats           Show cache statistics

  --watch                 Watch files for changes and re-scan continuously
                          (requires: npm install chokidar)
  --diff <refs>           Semantic diff between git refs (e.g. HEAD~5..HEAD)
  --init-rules            Generate example custom rules in .throughline-rules/

  --mcp                   Run as an MCP server on stdio — see docs/MCP.md
  --no-triage             Show findings previously reviewed as false positives
  --triage-stats          Show stored triage verdicts

  --max-size <bytes>      Max file size in bytes (default: 10MB)
  --list-rules            List all rules
  --rule-summary          Show rule coverage (CWEs, severity breakdown)
  -h, --help              Show help
```

### Examples

```bash
# Scan current directory, show critical+high
throughline . -s high

# SARIF output for GitHub Code Scanning
throughline -f sarif -s medium . -o throughline-results.sarif

# HTML report for stakeholders
throughline -f html -o report.html ./src

# Specific rules only
throughline -r sql-injection,xss,ssrf ./app

# Incremental scan — only files changed since last run
throughline --incremental ./src

# Git-aware scan — only files modified in latest commit
throughline --git-aware --git-base HEAD~3 ./src

# Full scan without dependency CVE check
throughline --no-deps ./src

# Watch mode — continuous re-scanning on file changes
throughline --watch ./src

# Semantic diff — what vulns were introduced/fixed between commits
throughline --diff HEAD~5..HEAD ./src

# Generate custom rule templates
throughline --init-rules

# Run as an MCP server so an AI can drive the scanner and triage findings
throughline --mcp
```

---

## Architecture — Four Analysis Engines

Throughline runs four analysis engines in sequence. Each engine catches vulnerabilities the others cannot.

### 1. Tree-sitter AST Engine
**Eliminates false positives.** Parses code into concrete syntax trees using tree-sitter grammars. S-expression queries match vulnerability patterns only in actual code — never in string literals, comments, or dead code. Supports JavaScript, TypeScript, Python, Go, PHP, and Ruby.

```typescript
// This WON'T trigger (inside comment):
// const query = "SELECT * FROM users WHERE id = " + req.params.id

// This WILL trigger (actual code):
const query = "SELECT * FROM users WHERE id = " + req.params.id
```

### 2. Regex Pattern Engine
**Broad coverage.** 31 rules across 42+ file extensions. Intra-file variable tracing follows assignments within the same file to reduce noise. Falls back when tree-sitter grammars aren't available.

### 3. Inter-Procedural Call Graph
**Cross-function taint tracking.** Builds a call graph from Babel AST, extracts function definitions and call sites, performs DFS reachability analysis, and tracks variable chains through assignments. Catches vulnerabilities that span multiple functions:

```
req.params.id → (assign to host) → exec(`ping ${host}`)
```

A regex scanner sees `req.params.id` and `exec(...)` on separate lines and misses the connection. The call graph traces the entire chain.

### 4. Code Property Graph (CPG)
**Unified graph traversal.** Combines AST, control flow, data flow, and call graph into a single labeled property graph. Vulnerability detection becomes graph queries:

- **SSA form**: Static Single Assignment with dominator trees (Cooper-Harvey-Kennedy algorithm), dominance frontiers, φ-node insertion, def-use chains
- **Points-to analysis**: Andersen-style inclusion-based constraint solving, may-alias queries
- **Function summaries**: Cacheable per-function taint behavior (propagates/sanitizes/blocks)
- **Precise taint query**: Variable-aware BFS that only follows DATA_FLOW edges when the tracked variable actually appears in the target node — eliminates cross-route noise

The CPG builder supports JavaScript/TypeScript via Babel and Python/Go/PHP/Ruby via tree-sitter grammars.

---

## Three Advanced Engines

### 5. Entropy-Based Secrets Detection
Shannon entropy scoring on all string literals. Detects secrets regex patterns miss: unknown API key formats, random tokens, base64-encoded credentials, hex cryptographic keys, private key PEM headers. Categorizes findings as AWS keys, GitHub tokens, hex secrets, passwords, and generic high-entropy strings.

```bash
# Entropy scanner is on by default. Disable:
throughline --no-entropy ./src
```

### 6. Dependency CVE Scanning
Parses 14 manifest formats (`package.json`, `package-lock.json`, `requirements.txt`, `go.mod`, `Cargo.toml`, `Gemfile`, `pom.xml`, `composer.json`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `yarn.lock`, `pnpm-lock.yaml`, `Gemfile.lock`, `go.sum`). Cross-references against the OSV.dev vulnerability database with a built-in offline fallback of 15+ known critical CVEs. Results cached for 24 hours.

```bash
# Dep scan is on by default. Disable:
throughline --no-deps ./src
```

### 7. Incremental / Diff Scanning
SHA-256 content-addressed cache (`.throughline-cache/`). Change detection across `added`,
`modified`, `deleted`, and `unchanged` files. Git-aware mode uses `git diff` for file
selection. Sub-second re-scans in CI when only a few files changed.

Findings for unchanged files are served from the cache and merged back in, so an
incremental scan reports exactly what a full scan would — the speed is in what it skips
re-reading, never in what it omits from the report. Every run states the split:

```
Files: 214   Findings: 31   Time: 0.34s
Incremental: 6 re-analysed, 208 from cache
```

The cache invalidates on any change to the rule set or to options that affect which
findings exist. A cache entry that cannot be read causes a re-scan of that file rather
than an assumption that it is clean.

```bash
# First scan — populates cache
throughline --incremental ./src

# Second scan — skips unchanged files, instant
throughline --incremental ./src

# Clear cache
throughline --clear-cache --incremental ./src

# Show cache stats
throughline --cache-stats
```

### 8. Watch Mode
Continuous scanning that re-analyzes files on every save. Shows a delta of new/resolved findings.

```bash
throughline --watch ./src
throughline --watch ./src -s critical     # Only alert on critical
```

- Debounced re-scanning (300ms after last file change)
- Clear-screen display shows new findings since last scan
- Delta indicators: ▲ new, ▼ resolved, • unchanged
- Uses chokidar for efficient file watching

### 9. Semantic Diff
Compare vulnerabilities between git refs to see what was introduced or fixed.

```bash
# Diff: what changed in the last commit
throughline --diff HEAD~1..HEAD ./src

# Diff: what changed between branches
throughline --diff main..feature-branch ./src

# Diff: last 5 commits
throughline --diff HEAD~5..HEAD ./src -s critical
```

Output classifies every finding:
- **Introduced**: new vulnerability in this commit
- **Resolved**: vulnerability fixed in this commit
- **Persisted**: unchanged between commits
- **Worsened**: same finding, severity increased
- **Improved**: same finding, severity decreased

### 10. Custom Rule DSL (JSON)
Drop JSON rule files in `.throughline-rules/` — no TypeScript needed.

```bash
# Generate example custom rules
throughline --init-rules

# Creates:
#   .throughline-rules/check-debug-endpoints.json
#   .throughline-rules/check-unsafe-regex.json
#   .throughline-rules/check-unsafe-eval.json
```

Custom rules support:
- Multiple regex patterns per rule
- Context patterns (must-match / must-not-match combos)
- AND/OR matching modes
- File path include/exclude filters
- Taint source → sink tracking
- Severity/confidence per pattern
- All 42+ file extensions

Example rule:
```json
{
  "id": "my-api-key-check",
  "name": "Custom API Key Pattern Check",
  "severity": "critical",
  "description": "Detects internal API key patterns",
  "patterns": [
    {
      "regex": "API_KEY_[A-Z0-9]{32}",
      "message": "Internal API key found in source",
      "recommendation": "Use a secrets manager instead"
    }
  ],
  "extensions": [".js", ".ts", ".py"],
  "cwe": "CWE-798",
  "owasp": "A02:2021-Cryptographic Failures"
}
```

Rules load automatically at scan time. No rebuild required.

---

## AI Triage (via MCP)

Throughline does not call a model provider to decide whether a finding is real. It exposes
an [MCP](https://modelcontextprotocol.io) server, and **the AI you connect to it is the
reviewer** — Claude Code, Claude Desktop, Cursor, Windsurf, VS Code, Cline, Zed, or
anything else that speaks MCP. No API key of its own, and the reviewer has your whole
repository and the conversation for context instead of one finding at a time.

```bash
npm run build
claude mcp add throughline -- node /path/to/security-scanner/dist/mcp/server.js
```

Then ask: *"Scan this project and tell me which findings are actually exploitable."*

The loop:

```
scan              → findings, each with a findingKey and a codeHash
get_review_queue  → unreviewed findings + surrounding source + review instructions
   ↓ the AI reads the code and judges each one
submit_triage     → verdicts persisted to .throughline-cache/triage.json
scan (again)      → confirmed false positives are gone
```

Verdicts are load-bearing, and safe by construction:

- **Suppression is never silent** — every scan prints `Triage: N hidden as reviewed false positives`.
- **Verdicts expire with the code** — each is bound to a hash of the reviewed line. Edit that line and the verdict is discarded and the finding returns. A dismissal cannot outlive the code it described.
- **Malformed verdicts are rejected, not defaulted** — a verdict with no reasoning or a missing hash is refused and reported. Nothing silently becomes "false positive".

18 tools cover everything the CLI does — scanning, git-diff review, dependency CVEs,
rule authoring, report export, and exact-match fix application. See **[docs/MCP.md](docs/MCP.md)**
for per-client setup and the full tool reference.

```bash
throughline --mcp            # run as an MCP server on stdio
throughline --triage-stats   # what has been reviewed
throughline --no-triage .    # scan ignoring all verdicts
```

---

## Standards Compliance

### CVSS 3.1
Every finding carries a CVSS 3.1 vector string, base score, impact subscore, and exploitability subscore. 32+ vulnerability classes have pre-configured default vectors compliant with the FIRST CVSS v3.1 specification.

### MITRE ATT&CK
Rules map to ATT&CK tactics (TA0001-TA0043) and techniques (T1059, T1190, T1505, etc.) for threat-informed defense workflows.

### SARIF 2.1.0
Native SARIF 2.1.0 output. Drop-in compatible with GitHub Code Scanning, GitLab SAST, Azure DevOps, and any SARIF-consuming tool.

### OWASP Top 10 2021
All findings mapped to OWASP categories (A01-A10). Coverage summary printed after every scan.

---

## Vulnerability Rules — 31 Rules, 29 CWEs, 42+ Extensions

| Category | Rules | Examples |
|----------|-------|----------|
| **Injection** (9) | SQL, command, code, NoSQL, SSTI, LDAP, GraphQL, XXE, HPP | `SELECT * FROM users WHERE id = ${input}` |
| **Crypto** (5) | MD5, SHA1, DES/3DES, RC4, ECB | `crypto.createHash('md5')` |
| **Secrets** (2) | Hardcoded credentials, AWS/API keys | `const password = 'admin123'` |
| **Auth** (4) | Weak JWT, CSRF, mass assignment, missing auth | `jwt.sign(payload, 'secret')` |
| **Web** (4) | XSS, SSRF, open redirect, CORS | `res.redirect(req.query.url)` |
| **File** (3) | Path traversal, arbitrary write, ReDoS | `fs.readFile('./files/' + req.query.file)` |
| **Infra** (2) | Docker misconfigs, K8s insecure | `RUN chmod 777 /app` |
| **Deps** (1) | Known CVE matching | `lodash@4.17.15` |
| **Code Quality** (1) | Prototype pollution | `Object.assign(target, req.body)` |

View all rules: `throughline --list-rules`
View coverage: `throughline --rule-summary`

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Throughline
  run: |
    npm install -g throughline
    throughline -f sarif -s medium ./src -o throughline-results.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: throughline-results.sarif
```

### GitLab CI

```yaml
throughline:
  script:
    - npm install -g throughline
    - throughline -f sarif -s medium ./src -o gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
  allow_failure: true
```

### Generic CI

```bash
throughline -f json -s high ./src -o scan.json
# Exit code 1 if findings found → pipeline fails
```

### Pre-commit Hook

```bash
# .git/hooks/pre-commit
throughline --git-aware --incremental -s critical
```

---

## Output Formats

### Pretty (default)
Colorized terminal output with severity bars, confidence indicators, code snippets, fix recommendations, and OWASP coverage summary.

### HTML Report
Interactive dark-theme dashboard with collapsible findings, severity filters, search, and statistics. Open in any browser.

### JSON
Machine-readable output. Suitable for ingestion into dashboards, databases, or custom tooling.

### SARIF 2.1.0
GitHub Code Scanning, GitLab SAST, and Azure DevOps compatible. Includes regions, rule metadata, and full SARIF taxonomy.

---

## Supported Languages

| Language | Extensions | AST Engine | CPG |
|----------|-----------|------------|-----|
| JavaScript | `.js` `.mjs` `.cjs` | tree-sitter + Babel | Babel |
| TypeScript | `.ts` `.tsx` | tree-sitter + Babel | Babel |
| Python | `.py` `.pyw` | tree-sitter | tree-sitter |
| Go | `.go` | tree-sitter | tree-sitter |
| PHP | `.php` `.phtml` | tree-sitter | tree-sitter |
| Ruby | `.rb` `.rake` | tree-sitter | tree-sitter |
| Java | `.java` | regex | — |
| C# | `.cs` | regex | — |
| C/C++ | `.c` `.cpp` `.h` | regex | — |
| Rust | `.rs` | regex | — |
| Swift | `.swift` | regex | — |
| Kotlin | `.kt` `.kts` | regex | — |
| Scala | `.scala` | regex | — |
| Dart | `.dart` | regex | — |
| Lua | `.lua` | regex | — |
| Shell | `.sh` `.bash` | regex | — |
| Perl | `.pl` `.pm` | regex | — |
| R | `.r` `.R` | regex | — |
| SQL | `.sql` | regex | — |
| YAML | `.yaml` `.yml` | regex | — |
| Docker | `Dockerfile` `.dockerfile` | regex | — |
| Terraform | `.tf` `.tfvars` | regex | — |
| Kubernetes | `.yaml` `.yml` (k8s patterns) | regex | — |

Regex engine covers all languages with pattern-based rules. Tree-sitter AST eliminates false positives in 6 languages. CPG provides deep taint analysis in 6 languages.

---

## Configuration

### .throughlinerc.json (project root)

```json
{
  "exclude": ["test", "vendor", "generated"],
  "severity": "high",
  "extensions": [".js", ".ts", ".py"],
  "maxFileSize": 5242880,
  "rules": ["sql-injection", "xss", "command-injection"]
}
```

### Environment Variables

```bash
THROUGHLINE_CACHE_DIR=.throughline-cache  # Incremental cache location
```

AI triage needs no keys or endpoints — the reviewing model connects over MCP and brings
its own. See [docs/MCP.md](docs/MCP.md).

---

## Project Structure

```
src/
├── index.ts                   CLI entry point
├── scanner.ts                 Scan orchestrator (7 phases)
├── types.ts                   Type definitions, CVSS, MITRE
├── cvss.ts                    CVSS 3.1 calculator (FIRST spec)
├── rules/                     Rule modules (31 rules, 7 categories)
│   ├── index.ts               Rule registry, filtering, summaries
│   ├── injection/             SQL, command, code, NoSQL, GraphQL...
│   ├── crypto/                MD5, SHA1, DES, RC4, ECB, secrets
│   ├── auth/                  JWT, CSRF, mass assignment, authz
│   ├── web/                   XSS, SSRF, redirect, CORS
│   ├── file/                  Path traversal, ReDoS
│   ├── infra/                 Docker, K8s
│   ├── deps/                  CVE matching
│   └── code-quality/          Prototype pollution, deserialization
├── engine/                    Analysis engines
│   ├── tree-sitter-engine.ts  Semantic AST queries (6 languages)
│   ├── ast-analyzer.ts        Babel-based AST analysis
│   ├── pattern-engine.ts      Enhanced regex with variable tracing
│   ├── call-graph.ts          Inter-procedural call graph
│   ├── ai-analyzer.ts         Review packets, heuristic prefilter, verdict validation
│   ├── triage.ts              Persistent triage verdicts (hash-bound, expiring)
│   ├── entropy-scanner.ts     Shannon entropy secrets detection
│   ├── dep-scanner.ts         OSV-backed dependency CVE scanning
│   ├── incremental.ts         Diff/cache/incremental scanning
│   ├── watcher.ts             Continuous file watch mode
│   ├── semantic-diff.ts       Git-aware semantic diff analysis
│   ├── rule-loader.ts         Custom rule DSL (JSON)
│   └── cpg/                   Code Property Graph engine
│       ├── index.ts           CPG exports
│       ├── types.ts           Graph schema, taint configs
│       ├── graph.ts           In-memory property graph with indexes
│       ├── builder.ts         5-pass CPG builder (Babel JS/TS)
│       ├── multi-lang-builder.ts Tree-sitter CPG (Python/Go/PHP/Ruby)
│       ├── ir.ts              Unified IR (three-address code)
│       ├── ssa.ts             SSA construction (dominators, φ-nodes)
│       ├── points-to.ts       Andersen-style points-to analysis
│       ├── summaries.ts       Function taint summaries with caching
│       └── query.ts           Variable-aware precise taint tracking
└── formatters/
    ├── pretty.ts              Colorized terminal output
    ├── json.ts                JSON + SARIF 2.1.0
    └── html.ts                Interactive HTML report
```

---

## Precision

Most SAST tools fail by crying wolf. Three structural rules keep the noise down, each
one conservative enough that a real vulnerability still reports.

**Parameterized queries are not injection.** When a query's text is a fully static
literal, tainted data can only be reaching a bind parameter — the driver sends those
out of band, so they are not injectable. `db.query('… WHERE id = ?', [id])` is the
recommended form and stays silent. Concatenation, template interpolation, a dynamic
query variable, or one unsafe query alongside a safe one all still report.

**Non-shell process execution is not command injection.** `execFile`/`spawn` hand argv
straight to the OS, so shell metacharacters in an argument are inert data. Three
conditions are all required: a non-shell API, no `shell: true`, and a literal command
name — a tainted *program name* still reports, because then the attacker chooses the
binary.

**Patterns match code, not prose.** A rule firing inside a string literal, regex
literal, or comment is nearly always documentation, a test string, or — as happened
here — a scanner rule whose own pattern text matched itself. Secret-detection rules opt
out, since a credential *is* string content. Unknown file types (YAML, Dockerfile,
Terraform) are scanned verbatim rather than guessed at.

Measured on this repository: **59 findings → 10**, with no real detection lost. On the
reference vulnerable fixture, 25 → 24 — the one removed was a comment reading
`// VULN: Insecure Crypto — MD5 hash`, while the actual `createHash('md5')` two lines
below still reports.

**Findings are classified by the sink they reach**, not stamped with a generic label.
An inter-procedural flow into an HTTP client is CWE-918 / A10 SSRF; into a database,
CWE-89 / A03; into a shell, CWE-78. Previously every taint path reported as CWE-20
Injection regardless of where it landed, and `.get(`/`.all(`/`.run(` matched with no
receiver restriction — so `http.get`, `map.get`, and every Express route registration
were classified as SQL sinks.

Chasing a finding you expected to see? `THROUGHLINE_NO_MASK=1` disables the code/data
masking so you can tell whether it was suppressed.

---

## Performance

| Corpus | Time | Peak RSS |
|---|---|---|
| 43 files (this repo) | 0.8s | — |
| 200 files | 2.2s | ~250MB |
| 721 files | 5.1s | 431MB |

Four bottlenecks, none of them where you would first look. Findings were byte-identical
before and after every one of these.

**Scan cost was quadratic in graph size.** The CPG taint query resolved every edge with
`graph.edges.find(e => e.id === eid)` — a linear scan of the whole edge array, run inside
the BFS inner loop. Invisible at 100 files, 13× the cost at 200, and 840 files never
finished at all. `graph.ts` had always advertised "indexes for sub-millisecond queries";
the edge-by-id index was simply never built.

**Taint annotation ran once per file over the whole graph.** `annotateTaint()` scans every
node, and it was called at the end of each file's parse — so file 840 re-annotated all 840
files, adding a duplicate self-edge each time. That produced **1.9M `SANITIZES` edges where
~4.6k were meaningful**, 93% of the entire graph, and left nodes with an out-degree in the
thousands for the taint BFS to walk. Running it once after parsing cut the graph from 2.08M
edges to 38k and heap from 456MB to 45MB.

**Every file was parsed once per semantic rule.** Six rules carry tree-sitter patterns, and
`analyze()` was called per rule — six full parses and six native parse trees per file.
`analyze()` already accepted a pattern array; the caller just never used it. Parsing once
and mapping matches back to their owning rule halved peak RSS.

**Parsers and compiled queries were allocated per file.** Both hold native memory that V8
reclaims only via finalizers, so the JS heap stayed small (18MB) while RSS climbed past a
gigabyte. Caching them by grammar and query text is what took the 721-file scan from 31s
to 7.5s — compiling tree-sitter queries turns out to be expensive.

Two smaller ones: masks are memoised per line rather than per pattern (rules apply ~150
patterns per file, and recomputing per pattern cost 87% of the pattern phase), and source
files are cached per scan — though that last one was **not** a speedup. File I/O is 3ms of
a 3300ms scan; the OS page cache was already absorbing the repeats. It stays because
collapsing 485 reads to 43 is right, not because it made anything faster.

`test/scale.test.js` guards all of this structurally — cache occupancy must not grow with
file count, a file must be parsed exactly once, the edge index must cover every edge —
rather than by timing assertions that would be flaky on shared CI runners.

---

## Language coverage

Injection detection is verified end to end for JavaScript/TypeScript, Python, Go, PHP and
Ruby, each with a vulnerable fixture and a matching *safe* fixture that must stay silent.

This was the least honest part of the tool. Rules declared support for a dozen extensions,
but the tree-sitter patterns behind them were written for JavaScript and Python — and
`scanFilePatterns` skipped the regex fallback for any rule that had AST patterns *at all*,
regardless of language. On Go, PHP and Ruby that meant neither path ran: the AST queries
could not match those grammars, and the regex rules that would have caught the bugs were
skipped anyway. Measured against fixtures containing a deliberate SQL injection and command
injection each:

| | Before | After |
|---|---|---|
| Python | secrets, crypto | + SQL injection, command injection |
| Go | **nothing at all** | SQL injection, command injection |
| PHP | crypto | + SQL injection, command injection, secrets |
| Ruby | secrets | + SQL injection, command injection |

The fix is per-language: a rule skips the regex fallback only when one of its AST queries
actually compiles against that file's grammar. Language-specific patterns were then added
for Go concatenation, Ruby `#{}` interpolation and PHP `.` concatenation, none of which the
JavaScript-shaped patterns understood.

`.php` was also silently broken — `tree-sitter-php` exports `{ php, php_only }` rather than
a bare grammar, so `setLanguage` threw, `init()` returned false, and PHP had no AST path
despite being advertised. A test now asserts that every extension listed as supported
actually initialises.

Sanitizers are respected: `escapeshellarg`, parameterized queries, argument-list process
calls and allowlists all read as the fixed form, not the vulnerable one.

---

## Testing

```bash
npm test          # builds, then runs the suite against dist/
npm run test:only # skip the rebuild
```

196 tests on Node's built-in runner — no test framework dependency. They execute against
`dist/`, so a build that doesn't compile fails the suite rather than passing against
TypeScript nobody ran.

| File | Covers |
|---|---|
| `test/regression.test.js` | One test per shipped bug, plus the precision rules above: the non-global-regex hang, filter composition, finding-level thresholds, diff match-claiming, triage staleness, verdict validation |
| `test/coverage.test.js` | Every vulnerability the reference fixture declares must be found, near the right line, classified as the right CWE — plus a check that adding a `// VULN:` marker without a matching assertion fails |
| `test/incremental.test.js` | Cache lifecycle — the invariant is that an incremental scan reports *exactly* what a full scan would, through edits, fixes, deletions, rule changes, and a corrupted cache |
| `test/mcp.test.js` | Real MCP client over stdio — tool schemas, scanning, the triage round-trip, `apply_fix` guard rails |
| `test/languages.test.js` | Python, Go, PHP and Ruby each detect SQL and command injection, stay silent on idiomatic safe code, and cover every `VULN:` marker in their fixture |
| `test/formats.test.js` | SARIF/JSON/HTML validity — repo-relative URIs, 1-based regions, stable fingerprints, and that the HTML report escapes untrusted scanned content |
| `test/scale.test.js` | Cost stays roughly linear in corpus size; parser/query caches and parse counts do not grow with file count; a file yields the same findings alone as in a large tree |
| `test/diff.test.js` | Throwaway git repos: introduced/resolved/persisted classification, exit codes, and that `--diff` leaves HEAD, the index, and uncommitted work untouched |

Fixtures live in `test/fixtures/`. `safe-app.js` is the negative fixture — idiomatic
safe code that must produce no critical findings, which is what keeps rule precision
from drifting.

CI runs the suite on Linux, Windows, and macOS against Node 20 and 22. Windows is not
optional: two shipped bugs were Windows-only (`^` as cmd.exe's escape character, and
MSYS tar reading `C:` as a remote host) and both passed on Linux.

---

## Comparison

| Feature | Throughline | ESLint | SonarQube | Semgrep | CodeQL |
|---------|-------------|--------|-----------|---------|--------|
| Zero-config | ✓ | ✗ | ✗ | ✗ | ✗ |
| No toolchain deps | ✓ | — | ✗ | — | ✗ |
| Entropy secrets | ✓ | ✗ | ✗ | ✗ | ✗ |
| Dependency CVE | ✓ | ✗ | ✗ | — | ✗ |
| Incremental scans | ✓ | ✓ | ✓ | ✓ | ✓ |
| CPG taint analysis | ✓ | ✗ | ✗ | ✗ | ✓ |
| Points-to analysis | ✓ | ✗ | ✗ | ✗ | ✓ |
| SSA form | ✓ | ✗ | ✗ | ✗ | ✓ |
| SARIF 2.1.0 | ✓ | ✓ | ✓ | ✓ | ✓ |
| CVSS 3.1 | ✓ | ✗ | ✗ | ✗ | ✗ |
| MITRE ATT&CK | ✓ | ✗ | ✗ | ✗ | ✗ |
| HTML reports | ✓ | ✗ | ✓ | ✗ | ✗ |
| AI triage (via MCP) | ✓ | ✗ | ✗ | ✗ | ✗ |
| Multi-language CPG | ✓ | ✗ | ✗ | ✗ | ✗ |
| Free / OSS | ✓ | ✓ | — | ✓ | ✓ |
| npm install | ✓ | ✓ | ✗ | ✓ | ✗ |
| 31 rules | ✓ | — | — | — | — |

---

## License

MIT
