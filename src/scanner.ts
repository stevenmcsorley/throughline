import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { Finding, Rule, ScanOptions, ScanResult, ScanSummary, Severity, Confidence } from './types';
import { allRules } from './rules';
import { calculateCvss, DEFAULT_CVSS } from './cvss';
import { TreeSitterEngine, SEMANTIC_RULES, SemanticPattern } from './engine/tree-sitter-engine';
import { CallGraphEngine, TaintPath } from './engine/call-graph';
import { CpgBuilder, runAllCpgQueries, MultiLangBuilder } from './engine/cpg';
import { scanEntropy, entropyFindingsToFindings } from './engine/entropy-scanner';
import { scanDependencies } from './engine/dep-scanner';
import { detectChanges, updateCache, clearCache, loadCachedFindings } from './engine/incremental';
import type { ChangeSet } from './engine/incremental';
import { loadUserRules } from './engine/rule-loader';
import { loadTriageStore, applyTriage } from './engine/triage';
import { beginScanSession, endScanSession, readSource, sourceCacheStats } from './engine/source-cache';

const DEFAULT_EXCLUDE = [
  'node_modules', '.git', '.svn', 'dist', 'build', '__pycache__', '.next', '.nuxt',
  'vendor', 'target', 'bin', 'obj', '.tox', 'venv', '.venv', 'env', '.env', 'coverage',
  '.cache', '.idea', '.vscode', '*.min.js', '*.bundle.js', '*.generated.*', '.nyc_output',
  'tmp', 'temp', '.gradle', '.mvn', 'bower_components', '.pytest_cache', '.mypy_cache',
  '.turbo', '.parcel-cache', '.svelte-kit', '.angular', 'out', '.serverless',
  // The scanner's own state. Without these an incremental run scans the cache
  // it just wrote, counting its own JSON as newly added source every time.
  '.throughline-cache', '.throughline-rules',
];

const DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

// ─── File Collection ───────────────────────────────────────────────────

/**
 * @param relativeTo when set, only the portion of the path below this root is
 *   considered. The root itself was explicitly requested, so directory names
 *   above it — `/tmp`, a checkout inside `build/` — must not veto the scan.
 */
function shouldExclude(filePath: string, excludePatterns: string[], relativeTo?: string | null): boolean {
  let candidate = filePath;
  if (relativeTo) {
    const rel = path.relative(relativeTo, filePath);
    if (rel && !rel.startsWith('..')) candidate = rel;
  }
  const normalized = candidate.replace(/\\/g, '/');
  for (const pattern of excludePatterns) {
    if (pattern.includes('*')) {
      const regex = new RegExp(
        pattern.replace(/\./g, '\\.').replace(/\*/g, '.*').replace(/\?/g, '.')
      );
      if (regex.test(path.basename(normalized))) return true;
    } else {
      if (normalized.includes(`/${pattern}/`) || normalized.includes(`\\${pattern}\\`) ||
          normalized.startsWith(`${pattern}/`) || normalized.startsWith(`${pattern}\\`)) {
        return true;
      }
    }
  }
  return false;
}

/**
 * @param isExplicitRoot true when this directory is one the user named on the
 *   command line. Its own path is then exempt from exclusion checks — only the
 *   parts of the tree discovered beneath it are filtered.
 */
function walkDirectory(
  dir: string,
  extensions: string[],
  excludePatterns: string[],
  maxSize: number,
  isExplicitRoot = false
): string[] {
  const files: string[] = [];
  // Match exclusions against the path *relative to* an explicitly named root,
  // so a project living in /tmp or under build/ is not rejected wholesale.
  const relativeTo = isExplicitRoot ? dir : null;

  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!shouldExclude(fullPath, excludePatterns, relativeTo)) {
          files.push(...walkDirectory(fullPath, extensions, excludePatterns, maxSize));
        }
      } else if (entry.isFile()) {
        if (shouldExclude(fullPath, excludePatterns, relativeTo)) continue;
        try {
          const stat = fs.statSync(fullPath);
          if (stat.size > maxSize) continue;
        } catch { continue; }

        const ext = path.extname(entry.name).toLowerCase();
        const basename = path.basename(entry.name);
        const specialNames = ['Dockerfile', '.dockerfile', '.dockerignore', 'Makefile', 'Gemfile', 'Rakefile'];
        if (extensions.length === 0 || extensions.includes(ext) || specialNames.includes(basename)) {
          files.push(fullPath);
        }
      }
    }
  } catch {
    // Permission denied — skip
  }
  return files;
}

// ─── Scanning ──────────────────────────────────────────────────────────

/**
 * Phase 1: Tree-sitter semantic analysis.
 * For files with a tree-sitter grammar, use AST-level pattern matching.
 * This eliminates false positives from pattern strings in source code.
 */
function scanFileAst(filePath: string, content: string, lines: string[], tsEngine: TreeSitterEngine, rules: Rule[]): Finding[] {
  const findings: Finding[] = [];
  const ext = path.extname(filePath).toLowerCase();

  if (!tsEngine.init(ext)) return findings;

  // Gather every semantic pattern for the active rule set first, so the file is
  // parsed once. Calling analyze() per rule re-parsed the same source for each
  // of the six semantic rules, allocating six native tree-sitter trees per file
  // — the dominant source of resident memory on a large scan.
  const patternOwner = new Map<SemanticPattern, Rule>();
  const allPatterns: SemanticPattern[] = [];
  for (const rule of rules) {
    const semanticPatterns = SEMANTIC_RULES[rule.id];
    if (!semanticPatterns || !semanticPatterns.length) continue;
    // Only patterns whose query compiles against this file's grammar.
    for (const pattern of tsEngine.applicablePatterns(semanticPatterns)) {
      patternOwner.set(pattern, rule);
      allPatterns.push(pattern);
    }
  }
  if (allPatterns.length === 0) return findings;

  {
    const astMatches = tsEngine.analyze(content, allPatterns);

    for (const match of astMatches) {
      const rule = patternOwner.get(match.pattern);
      if (!rule) continue;
      findings.push({
        ruleId: rule.id,
        title: rule.name,
        severity: match.pattern.severity as Severity || rule.severity,
        confidence: match.pattern.confidence,
        message: match.pattern.message,
        file: filePath,
        line: match.line,
        column: match.column,
        endLine: match.endLine,
        endColumn: match.endColumn,
        snippet: match.snippet,
        recommendation: match.pattern.recommendation || rule.description,
        fixExample: match.pattern.fixExample,
        cwe: rule.cwe,
        owasp: rule.owasp,
        mitreAttack: rule.mitreAttack,
        references: rule.references,
        falsePositiveRisk: match.pattern.falsePositiveRisk,
      });
    }
  }

  return findings;
}

/**
 * Phase 2: Regex-based pattern analysis (for languages without tree-sitter).
 */
function scanFilePatterns(
  filePath: string,
  content: string,
  lines: string[],
  rules: Rule[],
  astCoveredRuleIds: Set<string>
): Finding[] {
  const findings: Finding[] = [];
  const ext = path.extname(filePath).toLowerCase();
  const basename = path.basename(filePath);

  for (const rule of rules) {
    // Deliberately no longer skips rules the AST pass handled.
    //
    // A rule's AST patterns usually cover only part of what its regex patterns
    // do — `xss` has tree-sitter queries for innerHTML and
    // dangerouslySetInnerHTML, but the DOM-redirect and template-escaping
    // patterns are regex only. Treating AST coverage as exclusive silently
    // dropped every one of those. The two engines are complementary; anything
    // both find at the same place is collapsed afterwards.
    void astCoveredRuleIds;

    const ruleExts = rule.extensions.map(e => e.toLowerCase());
    const matches = ruleExts.includes(ext) ||
      ruleExts.includes(basename) ||
      ruleExts.includes('*');

    if (matches) {
      findings.push(...dedupeSamePosition(rule.scan(filePath, content, lines)));
    }
  }

  return findings;
}

/**
 * Collapse findings from the same rule that matched the same text.
 *
 * Rules often carry several patterns for one weakness, and more than one can
 * hit the same call. DVWA reported all 31 of its `MD5(...)` calls twice — once
 * as "MD5/MD4 hash used" and once as "PHP weak hash function" — which is the
 * same problem described twice, not two problems.
 *
 * Keyed on position, so two genuinely distinct issues on one line (a JWT with
 * both a literal secret and a weak algorithm, matched at different offsets)
 * both survive. The highest-confidence message wins.
 */
/**
 * Merge the AST and regex results for one file.
 *
 * Both engines legitimately report the same weakness — the AST pass with more
 * precision, the regex pass with broader coverage. Where they land on the same
 * rule and line, the AST finding wins; everything else is kept, so a rule whose
 * AST patterns cover only part of its surface still contributes its regex
 * findings.
 */
function dedupeAcrossEngines(astFindings: Finding[], patternFindings: Finding[]): Finding[] {
  if (astFindings.length === 0) return patternFindings;

  const claimed = new Set(astFindings.map(f => `${f.file}:${f.line}:${f.ruleId}`));
  return [
    ...astFindings,
    ...patternFindings.filter(f => !claimed.has(`${f.file}:${f.line}:${f.ruleId}`)),
  ];
}

function dedupeSamePosition(findings: Finding[]): Finding[] {
  if (findings.length < 2) return findings;
  const rank: Record<string, number> = { certain: 3, high: 2, medium: 1, low: 0 };
  const best = new Map<string, Finding>();

  for (const f of findings) {
    const key = `${f.line}:${f.column}`;
    const held = best.get(key);
    if (!held || (rank[f.confidence] ?? 0) > (rank[held.confidence] ?? 0)) {
      best.set(key, f);
    }
  }
  return [...best.values()];
}

/**
 * Phase 3: Inter-procedural taint analysis.
 * Builds call graph and traces taint across function boundaries.
 */
function scanInterprocedural(files: string[], rules: Rule[]): TaintPath[] {
  const cgEngine = new CallGraphEngine();
  const graph = cgEngine.build(files);
  const taintPaths = cgEngine.traceTaint(graph, files);

  return taintPaths;
}

// ─── Helpers ───────────────────────────────────────────────────────────

/**
 * CWE → OWASP Top 10 2021.
 *
 * The unmapped fallback used to be A03 Injection, which mislabelled every
 * unrecognised CWE as an injection flaw. A04 Insecure Design is the honest
 * bucket for "categorised, but not into a specific one".
 */
function mapCweToOwasp(cwe: string): string {
  const map: Record<string, string> = {
    'CWE-89': 'A03:2021-Injection',
    'CWE-78': 'A03:2021-Injection',
    'CWE-79': 'A03:2021-Injection',
    'CWE-91': 'A03:2021-Injection',
    'CWE-94': 'A03:2021-Injection',
    'CWE-95': 'A03:2021-Injection',
    'CWE-564': 'A03:2021-Injection',
    'CWE-643': 'A03:2021-Injection',
    'CWE-1336': 'A03:2021-Injection',
    'CWE-20': 'A03:2021-Injection',
    'CWE-22': 'A01:2021-Broken Access Control',
    'CWE-23': 'A01:2021-Broken Access Control',
    'CWE-284': 'A01:2021-Broken Access Control',
    'CWE-285': 'A01:2021-Broken Access Control',
    'CWE-639': 'A01:2021-Broken Access Control',
    'CWE-601': 'A01:2021-Broken Access Control',
    'CWE-352': 'A01:2021-Broken Access Control',
    'CWE-918': 'A10:2021-SSRF',
    'CWE-327': 'A02:2021-Cryptographic Failures',
    'CWE-328': 'A02:2021-Cryptographic Failures',
    'CWE-330': 'A02:2021-Cryptographic Failures',
    'CWE-798': 'A02:2021-Cryptographic Failures',
    'CWE-916': 'A02:2021-Cryptographic Failures',
    'CWE-502': 'A08:2021-Software & Data Integrity',
    'CWE-611': 'A05:2021-Security Misconfiguration',
    'CWE-16': 'A05:2021-Security Misconfiguration',
    'CWE-1004': 'A05:2021-Security Misconfiguration',
    'CWE-1021': 'A05:2021-Security Misconfiguration',
    'CWE-287': 'A07:2021-Auth Failures',
    'CWE-306': 'A07:2021-Auth Failures',
    'CWE-384': 'A07:2021-Auth Failures',
    'CWE-1395': 'A06:2021-Vulnerable Components',
    'CWE-1104': 'A06:2021-Vulnerable Components',
    'CWE-117': 'A09:2021-Logging & Monitoring',
    'CWE-778': 'A09:2021-Logging & Monitoring',
    'CWE-400': 'A04:2021-Insecure Design',
    'CWE-1333': 'A04:2021-Insecure Design',
    'CWE-362': 'A04:2021-Insecure Design',
    'CWE-434': 'A04:2021-Insecure Design',
  };
  return map[cwe] || 'A04:2021-Insecure Design';
}

/**
 * How the call graph's sink categories map onto reportable classifications.
 *
 * The taint engine knows precisely which kind of sink it reached, but every
 * finding was previously stamped CWE-20 / Injection regardless — so an SSRF and
 * a path traversal both showed up as generic injection flaws.
 */
const TAINT_SINK_CLASSIFICATION: Record<string, { severity: Severity; cwe: string; title: string }> = {
  sql:      { severity: 'critical', cwe: 'CWE-89',  title: 'SQL Injection via Untrusted Data Flow' },
  command:  { severity: 'critical', cwe: 'CWE-78',  title: 'Command Injection via Untrusted Data Flow' },
  eval:     { severity: 'critical', cwe: 'CWE-95',  title: 'Code Execution via Untrusted Data Flow' },
  file:     { severity: 'high',     cwe: 'CWE-22',  title: 'Path Traversal via Untrusted Data Flow' },
  ssrf:     { severity: 'high',     cwe: 'CWE-918', title: 'SSRF via Untrusted Data Flow' },
  xss:      { severity: 'medium',   cwe: 'CWE-79',  title: 'Cross-Site Scripting via Untrusted Data Flow' },
  redirect: { severity: 'medium',   cwe: 'CWE-601', title: 'Open Redirect via Untrusted Data Flow' },
};

/**
 * Read the sink category from a call-graph sink string, which is formatted
 * `"<category>: <code>"`. Matching on substring presence instead would let code
 * containing the word "sql" reclassify a command-execution finding.
 */
function taintSinkCategory(sink: string): string | null {
  const m = /^([a-z-]+):/.exec(sink);
  return m ? m[1] : null;
}

/** Identity used to suppress the same issue reported by two engines. */
function dedupKey(f: { file: string; line: number; ruleId: string }): string {
  return `${f.file}:${f.line}:${f.ruleId}`;
}

/** Synthetic taint-engine rule IDs mapped back to the declared rule they mirror. */
const SYNTHETIC_TO_DECLARED: Record<string, string> = {
  sql: 'sql-injection',
  'command-exec': 'command-injection',
  command: 'command-injection',
  eval: 'command-injection',
  'code-exec': 'insecure-deserialization',
  'file-write': 'path-traversal',
  'file-op': 'path-traversal',
  file: 'path-traversal',
  'network-req': 'ssrf',
  ssrf: 'ssrf',
  'html-render': 'xss',
  xss: 'xss',
  redirect: 'open-redirect',
  crypto: 'insecure-crypto',
  deserialize: 'insecure-deserialization',
};

function declaredEquivalent(ruleId: string): string | null {
  const m = /^cpg-(?:precise|direct)-(.+)$/.exec(ruleId);
  return m ? SYNTHETIC_TO_DECLARED[m[1]] ?? null : null;
}

/**
 * True when a declared rule already reported this weakness nearby.
 *
 * The taint engines emit synthetic IDs (`cpg-precise-sql`), so an exact
 * file:line:ruleId comparison never matches the pattern rule's finding
 * (`sql-injection`) for the same bug — one concatenated query was reported
 * twice, once at the enclosing function and once at the call. The CPG node
 * spans the function, so the two land on different lines; the window absorbs
 * that.
 */
function alreadyReportedByRule(
  vuln: { file: string; line: number; ruleId: string },
  existing: Finding[]
): boolean {
  const declared = declaredEquivalent(vuln.ruleId);
  if (!declared) return false;
  return existing.some(
    f => f.ruleId === declared && f.file === vuln.file && Math.abs(f.line - vuln.line) <= 25
  );
}

// ─── Cache invalidation ────────────────────────────────────────────────

/**
 * Fingerprint the inputs that determine what a scan produces, so the
 * incremental cache invalidates when they change.
 *
 * Options that only affect *presentation* are excluded deliberately — changing
 * an output format should not force a full re-scan. Options that change which
 * findings exist (rules, thresholds, file selection, engine toggles) are all in.
 */
function computeScanHashes(options: ScanOptions, rules: Rule[]): { configHash: string; rulesHash: string } {
  const sha = (value: unknown) =>
    crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex').slice(0, 16);

  // Rule identity includes the pattern sources, so editing a custom rule in
  // .throughline-rules/ invalidates the cache the way editing source does.
  const ruleFingerprints = rules
    .map(r => [
      r.id, r.severity, r.confidence, r.cwe,
      (r.patterns || []).map(p => `${p.regex.source}/${p.regex.flags}`).join('|'),
    ].join(':'))
    .sort();

  return {
    rulesHash: sha(ruleFingerprints),
    configHash: sha({
      rules: ruleFingerprints,
      severity: options.severity ?? null,
      confidence: options.confidence ?? null,
      extensions: [...(options.extensions ?? [])].sort(),
      exclude: [...(options.exclude ?? [])].sort(),
      maxFileSize: options.maxFileSize ?? null,
      entropy: options.entropy !== false,
      deps: options.deps !== false,
    }),
  };
}

// ─── Test-code weighting ───────────────────────────────────────────────

/** Paths that hold test, fixture or example code rather than shipped code. */
const NON_PRODUCTION_PATH =
  /(?:^|[\\/])(?:tests?|__tests?__|spec|specs|fixtures?|examples?|samples?|mocks?|__mocks__|testdata|e2e|cypress|benchmarks?)[\\/]|\.(?:test|spec|e2e)\.[cm]?[jt]sx?$/i;

/**
 * Lower the severity of findings in test and fixture code by one step.
 *
 * A credential in `test/api/user.test.ts` is worth knowing about — it may be a
 * real key someone pasted in — but it is not the same risk as one in a shipped
 * request handler, and it should not fail a `--severity critical` gate. Juice
 * Shop put 27 such findings in a single test file, all reported critical, which
 * buries the genuine ones.
 *
 * Deliberately a downgrade, not a suppression: the finding still appears, one
 * level down, and says why.
 */
function weightNonProductionCode(findings: Finding[]): Finding[] {
  const step: Record<Severity, Severity> = {
    critical: 'high', high: 'medium', medium: 'low', low: 'info', info: 'info',
  };

  for (const f of findings) {
    if (!NON_PRODUCTION_PATH.test(f.file)) continue;
    const lowered = step[f.severity];
    if (lowered !== f.severity) {
      f.severity = lowered;
      f.message = `${f.message} (in test or fixture code — severity reduced one step)`;
    }
    if (f.falsePositiveRisk === 'low') f.falsePositiveRisk = 'medium';
  }
  return findings;
}

// ─── Filtering ─────────────────────────────────────────────────────────

const SEVERITY_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
const CONFIDENCE_ORDER: Confidence[] = ['low', 'medium', 'high', 'certain'];

/**
 * Findings produced by the taint engines (CPG, call graph) carry synthesised
 * rule IDs rather than a declared Rule, so `--rules` has to map a declared rule
 * back to the sink categories that represent it. The CPG and call-graph engines
 * use different vocabularies for the same concept, so both appear here.
 */
const RULE_TO_SINK_CATEGORIES: Record<string, string[]> = {
  'sql-injection':            ['sql'],
  'command-injection':        ['command', 'code-exec', 'eval'],
  'path-traversal':           ['file-op', 'file'],
  'arbitrary-file-write':     ['file-op', 'file'],
  'ssrf':                     ['network-req', 'ssrf'],
  'xss':                      ['html-render', 'xss'],
  'open-redirect':            ['redirect'],
  'insecure-crypto':          ['crypto'],
  'insecure-deserialization': ['deserialize'],
  'missing-authz':            ['auth'],
  'ssti':                     ['template'],
};

function normalizeRuleIds(ids?: string[]): Set<string> | null {
  if (!ids || ids.length === 0) return null;
  const set = new Set(ids.map(id => id.trim().toLowerCase()).filter(Boolean));
  return set.size > 0 ? set : null;
}

/** Sink categories reachable from the requested rule set. */
function requestedSinkCategories(requested: Set<string>): Set<string> {
  const cats = new Set<string>();
  for (const [ruleId, categories] of Object.entries(RULE_TO_SINK_CATEGORIES)) {
    if (requested.has(ruleId)) for (const c of categories) cats.add(c);
  }
  return cats;
}

function severityFloor(value?: string): number {
  if (!value) return -1;
  const idx = SEVERITY_ORDER.indexOf(value.trim().toLowerCase() as Severity);
  if (idx === -1) {
    throw new Error(`Invalid severity "${value}". Expected one of: ${SEVERITY_ORDER.join(', ')}`);
  }
  return idx;
}

function confidenceFloor(value?: string): number {
  if (!value) return -1;
  const idx = CONFIDENCE_ORDER.indexOf(value.trim().toLowerCase() as Confidence);
  if (idx === -1) {
    throw new Error(`Invalid confidence "${value}". Expected one of: ${CONFIDENCE_ORDER.join(', ')}`);
  }
  return idx;
}

function findingMatchesRules(f: Finding, requested: Set<string>, sinkCats: Set<string>): boolean {
  const id = f.ruleId.toLowerCase();
  if (requested.has(id)) return true;

  // cpg-precise-<category> / cpg-direct-<category>
  const cpg = /^cpg-(?:precise|direct)-(.+)$/.exec(id);
  if (cpg) return sinkCats.has(cpg[1]);

  // entropy-<category> is the engine-side form of hardcoded-secrets
  if (id.startsWith('entropy-')) return requested.has('hardcoded-secrets');

  // dep-cve is the engine-side form of the declared dependency rule
  if (id === 'dep-cve') return requested.has('dependency-vuln');

  // interproc-taint encodes its sink category as a "<category>: ..." prefix
  if (id === 'interproc-taint') {
    const cat = /^([a-z-]+):/.exec((f.taintFlow?.sinks[0] || '').toLowerCase());
    return cat ? sinkCats.has(cat[1]) : false;
  }

  return false;
}

/**
 * Apply reporting filters to findings.
 *
 * `--severity` and `--confidence` are minimum thresholds on the *finding*, not
 * on the declaring rule: a rule declared "high" can emit a critical finding and
 * vice versa, so filtering rule declarations drops and keeps the wrong things.
 *
 * Idempotent — safe to re-apply after a later phase appends more findings.
 */
export function applyFindingFilters(findings: Finding[], options: ScanOptions): Finding[] {
  let out = findings;

  const requested = normalizeRuleIds(options.rules);
  if (requested) {
    const sinkCats = requestedSinkCategories(requested);
    out = out.filter(f => findingMatchesRules(f, requested, sinkCats));
  }

  const minSeverity = severityFloor(options.severity);
  if (minSeverity >= 0) {
    out = out.filter(f => SEVERITY_ORDER.indexOf(f.severity) >= minSeverity);
  }

  const minConfidence = confidenceFloor(options.confidence);
  if (minConfidence >= 0) {
    out = out.filter(f => CONFIDENCE_ORDER.indexOf(f.confidence) >= minConfidence);
  }

  return out;
}

// ─── Summary ───────────────────────────────────────────────────────────

function buildSummary(findings: Finding[]): ScanSummary {
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byConfidence: Record<Confidence, number> = { certain: 0, high: 0, medium: 0, low: 0 };
  const byOwasp: Record<string, number> = {};
  const byCwe: Record<string, number> = {};
  let fpEstimate = { low: 0, medium: 0, high: 0 };

  // Every increment is guarded. An engine that omits a field — or emits a
  // severity outside the enum — would otherwise increment `undefined` into NaN
  // and poison the whole report, including the CI-facing counts.
  for (const f of findings) {
    if (f.severity in bySeverity) bySeverity[f.severity]++;
    if (f.confidence in byConfidence) byConfidence[f.confidence]++;
    if (f.owasp) byOwasp[f.owasp] = (byOwasp[f.owasp] || 0) + 1;
    if (f.cwe) byCwe[f.cwe] = (byCwe[f.cwe] || 0) + 1;
    if (f.falsePositiveRisk in fpEstimate) fpEstimate[f.falsePositiveRisk]++;
  }

  return {
    bySeverity,
    byConfidence,
    byOwasp,
    byCwe,
    totalFindings: findings.length,
    falsePositiveEstimate: fpEstimate,
  };
}

/** Exposed for tests that need to exercise summary edge cases directly. */
export function buildSummaryForTest(findings: Finding[]): ScanSummary {
  return buildSummary(findings);
}

// ─── Main Scan Orchestrator ────────────────────────────────────────────

export function scan(options: ScanOptions): ScanResult {
  // The five analysis phases each read the files they analyse. Cache reads for
  // the duration of this scan only — holding contents across scans would make
  // watch mode blind to edits, so the session is always torn down in `finally`.
  beginScanSession();
  try {
    return runScan(options);
  } finally {
    endScanSession();
  }
}

function runScan(options: ScanOptions): ScanResult {
  const startTime = Date.now();

  // Validate thresholds up front so a typo fails before any scanning work.
  severityFloor(options.severity);
  confidenceFloor(options.confidence);

  // ─── Rule selection ──────────────────────────────────────────────────
  // Only --rules decides *which* rules run. Severity/confidence are reporting
  // thresholds applied to findings at the end (see applyFindingFilters).
  const availableRules = [...allRules, ...loadUserRules()];
  const requestedRuleIds = normalizeRuleIds(options.rules);
  const rules = requestedRuleIds
    ? availableRules.filter(r => requestedRuleIds.has(r.id.toLowerCase()))
    : availableRules;

  // Phases 3-5 emit synthesised rule IDs; skip them outright when --rules
  // selects nothing they could produce, rather than building a CPG for nothing.
  const requestedSinks = requestedRuleIds ? requestedSinkCategories(requestedRuleIds) : null;
  const wantsTaintAnalysis = !requestedSinks || requestedSinks.size > 0;
  const wantsEntropy = options.entropy !== false &&
    (!requestedRuleIds || requestedRuleIds.has('hardcoded-secrets'));

  const excludePatterns = options.exclude || DEFAULT_EXCLUDE;
  const extensions = (options.extensions && options.extensions.length > 0)
    ? options.extensions.map(e => e.startsWith('.') ? e.toLowerCase() : `.${e.toLowerCase()}`)
    : [];
  const maxSize = options.maxFileSize || DEFAULT_MAX_FILE_SIZE;

  // Collect files. Shared with the incremental path rather than duplicated —
  // the two copies had already drifted, and a fix applied to one silently
  // missed the other.
  const allFiles = collectAllFiles(options);

  // ─── Phase 1+2: Per-file analysis (AST first, then pattern fallback) ───
  const tsEngine = new TreeSitterEngine();
  const allFindings: Finding[] = [];

  for (const file of allFiles) {
    try {
      const content = readSource(file);
      const lines = content.split('\n');
      const ext = path.extname(file).toLowerCase();

      // Tree-sitter AST analysis, where a grammar is available.
      const astCoveredRuleIds = new Set<string>();
      const astFindings: Finding[] = [];
      if (tsEngine.supports(ext) && tsEngine.init(ext)) {
        astFindings.push(...scanFileAst(file, content, lines, tsEngine, rules));
      }

      // Regex rules run alongside the AST pass rather than instead of it;
      // overlapping results are collapsed, preferring the AST finding.
      allFindings.push(...dedupeAcrossEngines(
        astFindings,
        scanFilePatterns(file, content, lines, rules, astCoveredRuleIds)
      ));
    } catch {
      // Binary or unreadable — skip
    }
  }

  // ─── Phase 3: Inter-procedural analysis ──────────────────────────────
  const taintPaths = wantsTaintAnalysis ? scanInterprocedural(allFiles, rules) : [];
  for (const tp of taintPaths) {
    // Classify by the sink the flow actually reached, rather than stamping
    // every taint path as a generic injection flaw.
    const category = taintSinkCategory(tp.sink);
    const cls = (category && TAINT_SINK_CLASSIFICATION[category]) || {
      severity: 'high' as Severity, cwe: 'CWE-20', title: 'Inter-procedural Taint Flow',
    };
    const owasp = mapCweToOwasp(cls.cwe);

    allFindings.push({
      ruleId: 'interproc-taint',
      title: cls.title,
      severity: cls.severity,
      confidence: 'high',
      message: `Tainted data from "${tp.source}" reaches sink: ${tp.sink}`,
      file: tp.file,
      line: tp.line,
      column: 0,
      snippet: `${tp.source} → ${tp.path.map(p => p.function).join(' → ')} → ${tp.sink}`,
      recommendation: 'Validate and sanitize user input at the entry point. Data flows through multiple functions before reaching a dangerous sink.',
      cwe: cls.cwe as any,
      owasp: owasp as any,
      references: [`https://cwe.mitre.org/data/definitions/${cls.cwe.replace('CWE-', '')}.html`],
      falsePositiveRisk: 'medium',
      taintFlow: {
        source: tp.source,
        sinks: [tp.sink],
        variableChain: tp.path.map(p => p.function),
        sanitizers: [],
        confidence: 'high',
      },
    });
  }

  // ─── Phase 4: Code Property Graph (CPG) analysis ─────────────────────
  // Dedup against everything found so far. A Set, not a linear scan per
  // candidate — on a large repo the quadratic version dominated the scan.
  const seenKeys = new Set(allFindings.map(dedupKey));
  try {
    // JS/TS: Use Babel-based builder for deep analysis
    const jsTsFiles = allFiles.filter(f => /\.(?:js|ts|jsx|tsx)$/i.test(path.extname(f)));
    if (wantsTaintAnalysis && jsTsFiles.length > 0) {
      const cpgBuilder = new CpgBuilder();
      const cpg = cpgBuilder.build(jsTsFiles);
      const cpgVulns = runAllCpgQueries(cpg);

      for (const vuln of cpgVulns) {
        const key = dedupKey(vuln);
        if (seenKeys.has(key)) continue;
        // A pattern rule may already have reported this same weakness.
        if (alreadyReportedByRule(vuln, allFindings)) continue;
        seenKeys.add(key);

        allFindings.push({
          ruleId: vuln.ruleId,
          title: vuln.title,
          severity: vuln.severity,
          confidence: vuln.confidence,
          message: vuln.message,
          file: vuln.file,
          line: vuln.line,
          column: 0,
          snippet: vuln.path.map(p => p.node.code?.substring(0, 60) || p.node.label).join(' → '),
          recommendation: vuln.recommendation,
          references: [`https://cwe.mitre.org/data/definitions/${vuln.cwe.replace('CWE-', '')}.html`],
          cwe: vuln.cwe as any,
          owasp: mapCweToOwasp(vuln.cwe) as any,
          falsePositiveRisk: vuln.sanitizersEncountered.length > 0 ? 'low' :
            vuln.path.length > 3 ? 'medium' : 'low',
          taintFlow: {
            source: vuln.sourceNode.code?.substring(0, 80) || '',
            sinks: [vuln.sinkNode.code?.substring(0, 80) || ''],
            variableChain: vuln.path.map(p => p.variable || p.node.label),
            sanitizers: vuln.sanitizersEncountered.map(s => s.code),
            confidence: vuln.confidence,
          },
        });
      }
    }

    // Multi-language: Python, Go, PHP, Ruby via tree-sitter
    const multiFiles = allFiles.filter(f => {
      const ext = path.extname(f).toLowerCase();
      return ['.py', '.pyw', '.go', '.php', '.rb', '.phtml'].includes(ext);
    });
    if (wantsTaintAnalysis && multiFiles.length > 0) {
      const mlBuilder = new MultiLangBuilder();
      const mlCpg = mlBuilder.buildAll(multiFiles);
      const mlVulns = runAllCpgQueries(mlCpg);

      for (const vuln of mlVulns) {
        const key = dedupKey(vuln);
        if (seenKeys.has(key)) continue;
        // A pattern rule may already have reported this same weakness.
        if (alreadyReportedByRule(vuln, allFindings)) continue;
        seenKeys.add(key);

        allFindings.push({
          ruleId: vuln.ruleId,
          title: vuln.title,
          severity: vuln.severity,
          confidence: vuln.confidence,
          message: vuln.message,
          file: vuln.file,
          line: vuln.line,
          column: 0,
          snippet: vuln.path.map(p => p.node.code?.substring(0, 60) || p.node.label).join(' → '),
          recommendation: vuln.recommendation,
          references: [`https://cwe.mitre.org/data/definitions/${vuln.cwe.replace('CWE-', '')}.html`],
          cwe: vuln.cwe as any,
          owasp: mapCweToOwasp(vuln.cwe) as any,
          falsePositiveRisk: 'low',
          taintFlow: {
            source: vuln.sourceNode.code?.substring(0, 80) || '',
            sinks: [vuln.sinkNode.code?.substring(0, 80) || ''],
            variableChain: vuln.path.map(p => p.variable || p.node.label),
            sanitizers: [],
            confidence: vuln.confidence,
          },
        });
      }
    }
  } catch {
    // CPG analysis is best-effort
  }

  // ─── Phase 5: Entropy-based secrets detection ──────────────────────
  if (wantsEntropy) {
    for (const file of allFiles) {
      // Per-file guard: one unreadable file must not abort the whole phase.
      try {
        const content = readSource(file);
        const eFindings = scanEntropy(content, file);
        if (eFindings.length > 0) {
          allFindings.push(...entropyFindingsToFindings(eFindings, file));
        }
      } catch {
        // Binary or unreadable — skip this file only
      }
    }
  }

  // ─── Reporting filters ───────────────────────────────────────────────
  // Weight before filtering, so a downgraded test finding is judged against the
  // severity threshold at its adjusted level rather than its original one.
  let findings = applyFindingFilters(weightNonProductionCode(allFindings), options);

  // Reviewed false positives are dropped here. The count is always reported so
  // suppression is visible rather than silent.
  let triageOutcome: ScanResult['triage'];
  if (options.applyTriage !== false) {
    const applied = applyTriage(findings, loadTriageStore());
    findings = applied.findings;
    const { suppressed, severityAdjusted, stale } = applied.outcome;
    if (suppressed || severityAdjusted || stale) triageOutcome = applied.outcome;
  }

  for (const finding of findings) {
    if (DEFAULT_CVSS[finding.ruleId]) {
      finding.cvss = calculateCvss(DEFAULT_CVSS[finding.ruleId]);
    }
  }

  // ─── Sort by severity ────────────────────────────────────────────────
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => {
    const s = severityOrder[a.severity] - severityOrder[b.severity];
    if (s !== 0) return s;
    return a.file.localeCompare(b.file) || a.line - b.line;
  });

  const durationMs = Date.now() - startTime;

  return {
    filesScanned: allFiles.length,
    findings,
    durationMs,
    summary: buildSummary(findings),
    triage: triageOutcome,
  };
}

// ─── Async Scan (includes dependency CVE + incremental) ────────────────

function collectAllFiles(options: ScanOptions): string[] {
  const excludePatterns = options.exclude || DEFAULT_EXCLUDE;
  const extensions = (options.extensions && options.extensions.length > 0)
    ? options.extensions.map(e => e.startsWith('.') ? e.toLowerCase() : `.${e.toLowerCase()}`)
    : [];
  const maxSize = options.maxFileSize || DEFAULT_MAX_FILE_SIZE;
  const files: string[] = [];

  for (const scanPath of options.paths) {
    const resolved = path.resolve(scanPath);
    try {
      const stat = fs.statSync(resolved);
      if (stat.isDirectory()) {
        // Exclusions prune what the walk *discovers*; they must not reject the
        // root the user explicitly named. Otherwise `throughline /tmp/myproject`
        // or a checkout under build/ silently scans nothing — the default list
        // contains tmp, temp, out, bin, target and env.
        files.push(...walkDirectory(resolved, extensions, excludePatterns, maxSize, true));
      } else if (stat.isFile()) {
        // An explicitly named file is always scanned. Asking for a specific
        // file and receiving silence is never the right answer.
        if (stat.size <= maxSize) files.push(resolved);
      }
    } catch { /* skip */ }
  }
  return files;
}

export async function scanAsync(options: ScanOptions): Promise<ScanResult> {
  const startTime = Date.now();

  // Handle cache clearing
  if (options.clearCache) {
    clearCache();
  }

  // Handle incremental: only scan files that changed since last run
  if (options.incremental) {
    // Collect candidate files
    const candidateFiles = collectAllFiles(options);

    // Real hashes over the active rules and result-affecting options. These were
    // string literals, so the cache never invalidated when rules changed.
    const activeRules = options.rules && options.rules.length > 0
      ? [...allRules, ...loadUserRules()].filter(r =>
          new Set(options.rules!.map(id => id.trim().toLowerCase())).has(r.id.toLowerCase()))
      : [...allRules, ...loadUserRules()];
    const { configHash, rulesHash } = computeScanHashes(options, activeRules);

    const cs = detectChanges(candidateFiles, configHash, rulesHash);

    // Findings for unchanged files come from the cache. Without this an
    // incremental run reported only the files that changed, so a repository
    // full of known vulnerabilities looked clean the moment nobody touched it.
    const { findings: cachedFindings, missing } = loadCachedFindings(cs.unchanged);

    // Anything the cache could not serve gets re-analysed rather than assumed
    // clean — a missing cache entry must never read as "no vulnerabilities".
    const toScan = [...cs.added, ...cs.modified, ...missing];

    let freshFindings: Finding[] = [];
    if (toScan.length > 0) {
      // Triage is applied once below over the merged set, so the cached half is
      // not exempt from it. Filters are baked into configHash, so caching
      // post-filter findings is safe.
      freshFindings = scan({
        ...options,
        paths: toScan,
        incremental: false,
        applyTriage: false,
      }).findings;
    }

    updateCache(toScan, freshFindings, cs, configHash, rulesHash);

    let merged = [...freshFindings, ...cachedFindings];

    let incrementalTriage: ScanResult['triage'];
    if (options.applyTriage !== false) {
      const applied = applyTriage(merged, loadTriageStore());
      merged = applied.findings;
      const { suppressed, severityAdjusted, stale } = applied.outcome;
      if (suppressed || severityAdjusted || stale) incrementalTriage = applied.outcome;
    }

    const severityRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    merged.sort((a, b) => {
      const s = severityRank[a.severity] - severityRank[b.severity];
      if (s !== 0) return s;
      return a.file.localeCompare(b.file) || a.line - b.line;
    });

    return {
      filesScanned: candidateFiles.length,
      findings: merged,
      durationMs: Date.now() - startTime,
      summary: buildSummary(merged),
      triage: incrementalTriage,
      incremental: {
        analysed: toScan.length,
        fromCache: cs.unchanged.length - missing.length,
        cacheMisses: missing.length,
        deleted: cs.deleted.length,
      },
    };
  }

  // Full scan path
  const result = scan(options);

  // ─── Phase 6: Dependency CVE scanning ────────────────────────────────
  const requestedRuleIds = normalizeRuleIds(options.rules);
  const wantsDeps = options.deps !== false &&
    (!requestedRuleIds || requestedRuleIds.has('dependency-vuln'));
  if (wantsDeps) {
    try {
      const allFiles = [...new Set(result.findings.map(f => f.file).filter(Boolean))];
      // Also pass the scanned file paths from the result
      const scanPaths = options.paths.map(p => path.resolve(p));
      const depFindings = await scanDependencies([...allFiles, ...scanPaths]);
      const depSeen = new Set(result.findings.map(dedupKey));
      depFindings.forEach(f => {
        // Avoid duplicates
        const key = dedupKey(f);
        if (!depSeen.has(key)) {
          depSeen.add(key);
          result.findings.push(f);
        }
      });
    } catch {
      // Dep scanning is best-effort
    }
  }

  // Dependency findings are appended after scan() filtered, so re-apply.
  result.findings = applyFindingFilters(result.findings, options);
  if (options.applyTriage !== false && wantsDeps) {
    const applied = applyTriage(result.findings, loadTriageStore());
    result.findings = applied.findings;
    result.triage = {
      suppressed: (result.triage?.suppressed || 0) + applied.outcome.suppressed,
      severityAdjusted: (result.triage?.severityAdjusted || 0) + applied.outcome.severityAdjusted,
      stale: (result.triage?.stale || 0) + applied.outcome.stale,
    };
  }

  // Re-sort and re-summarize
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  result.findings.sort((a, b) => {
    const s = severityOrder[a.severity] - severityOrder[b.severity];
    if (s !== 0) return s;
    return a.file.localeCompare(b.file) || a.line - b.line;
  });

  result.summary = buildSummary(result.findings);
  result.durationMs = Date.now() - startTime;

  return result;
}
