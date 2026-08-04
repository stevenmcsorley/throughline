/**
 * MCP tool implementations.
 *
 * Thin adapters over the scanner's public API. Everything the `throughline` CLI
 * can do is reachable from here; nothing in this file re-implements analysis.
 */

import * as fs from 'fs';
import * as path from 'path';
import { scan, scanAsync } from '../scanner';
import { allRules, getRuleSummary } from '../rules';
import { Finding, ScanOptions, ScanResult, Severity } from '../types';
import { jsonFormat, sarifFormat } from '../formatters/json';
import { htmlFormat } from '../formatters/html';
import { prettyFormat } from '../formatters/pretty';
import { cacheStats, clearCache } from '../engine/incremental';
import { getGitDiffFiles, getGitDiffStat } from '../engine/semantic-diff';
import { loadUserRules, generateExampleRules } from '../engine/rule-loader';
import { scanDependencies } from '../engine/dep-scanner';
import { scanEntropy, entropyFindingsToFindings } from '../engine/entropy-scanner';
import {
  loadTriageStore, recordVerdicts, clearTriage, triageStats, findingKey, codeHashOf,
  TriageVerdict,
} from '../engine/triage';
import {
  buildReviewPacket, prioritizeForReview, validateVerdict, readFindingContext,
  suggestFixTemplate, RawVerdict, TRIAGE_INSTRUCTIONS,
} from '../engine/ai-analyzer';

/** Findings inlined in a tool response before truncation kicks in. */
const MAX_INLINE_FINDINGS = 40;

/** Most recent scan, exposed as the throughline://last-scan resource. */
let lastScan: { result: ScanResult; at: string; paths: string[] } | null = null;

export function getLastScan() {
  return lastScan;
}

// ─── Shared shapes ─────────────────────────────────────────────────────

export interface ScanArgs {
  paths?: string[];
  rules?: string[];
  severity?: Severity;
  confidence?: 'certain' | 'high' | 'medium' | 'low';
  extensions?: string[];
  exclude?: string[];
  maxFileSize?: number;
  entropy?: boolean;
  deps?: boolean;
  incremental?: boolean;
  applyTriage?: boolean;
}

function toScanOptions(args: ScanArgs): ScanOptions {
  return {
    paths: args.paths && args.paths.length > 0 ? args.paths : ['.'],
    rules: args.rules,
    severity: args.severity,
    confidence: args.confidence,
    extensions: args.extensions,
    exclude: args.exclude,
    maxFileSize: args.maxFileSize,
    entropy: args.entropy,
    deps: args.deps,
    incremental: args.incremental,
    applyTriage: args.applyTriage,
  };
}

function summarizeFinding(f: Finding) {
  return {
    findingKey: findingKey(f),
    codeHash: codeHashOf(f.snippet),
    ruleId: f.ruleId,
    title: f.title,
    severity: f.severity,
    confidence: f.confidence,
    file: f.file,
    line: f.line,
    cwe: f.cwe,
    owasp: f.owasp,
    message: f.message,
    snippet: f.snippet,
    recommendation: f.recommendation,
    falsePositiveRisk: f.falsePositiveRisk,
    cvss: f.cvss?.baseScore,
    taintFlow: f.taintFlow
      ? { source: f.taintFlow.source, sinks: f.taintFlow.sinks, sanitizers: f.taintFlow.sanitizers }
      : undefined,
  };
}

function renderScanResult(result: ScanResult, paths: string[]) {
  const shown = result.findings.slice(0, MAX_INLINE_FINDINGS);
  return {
    filesScanned: result.filesScanned,
    durationMs: result.durationMs,
    totalFindings: result.findings.length,
    summary: result.summary,
    triage: result.triage,
    findings: shown.map(summarizeFinding),
    truncated: result.findings.length > shown.length
      ? `Showing ${shown.length} of ${result.findings.length}. Narrow with severity/rules, or read the throughline://last-scan resource for the full set.`
      : undefined,
    scannedPaths: paths,
  };
}

// ─── Scanning ──────────────────────────────────────────────────────────

export async function runScan(args: ScanArgs) {
  const options = toScanOptions(args);
  const result = await scanAsync(options);
  lastScan = { result, at: new Date().toISOString(), paths: options.paths };
  return renderScanResult(result, options.paths);
}

export async function runGitDiffScan(args: ScanArgs & { baseRef?: string; targetRef?: string }) {
  const baseRef = args.baseRef || 'HEAD~1';
  const targetRef = args.targetRef || 'HEAD';
  const changed = getGitDiffFiles(baseRef, targetRef).filter(f => fs.existsSync(f));

  if (changed.length === 0) {
    return { baseRef, targetRef, changedFiles: 0, findings: [], note: 'No existing changed files between these refs.' };
  }

  const options = toScanOptions({ ...args, paths: changed });
  const result = await scanAsync(options);
  lastScan = { result, at: new Date().toISOString(), paths: changed };
  return {
    baseRef,
    targetRef,
    changedFiles: changed.length,
    diffStat: getGitDiffStat(baseRef, targetRef),
    ...renderScanResult(result, changed),
  };
}

export async function runDependencyScan(args: { paths?: string[] }) {
  const paths = (args.paths && args.paths.length > 0 ? args.paths : ['.']).map(p => path.resolve(p));
  const findings = await scanDependencies(paths);
  return {
    scannedPaths: paths,
    totalFindings: findings.length,
    findings: findings.slice(0, MAX_INLINE_FINDINGS).map(summarizeFinding),
    note: 'Versions are resolved against the OSV.dev database, which requires network access.',
  };
}

export function runEntropyScan(args: { paths?: string[] }) {
  const targets = args.paths && args.paths.length > 0 ? args.paths : ['.'];
  // Reuse the scanner's traversal by running an entropy-only scan.
  const result = scan({
    paths: targets,
    rules: ['hardcoded-secrets'],
    entropy: true,
    deps: false,
  });
  return {
    scannedPaths: targets,
    filesScanned: result.filesScanned,
    totalFindings: result.findings.length,
    findings: result.findings.slice(0, MAX_INLINE_FINDINGS).map(summarizeFinding),
  };
}

export function scanSnippet(args: { code: string; filename: string }) {
  // Write to a temp file so the full engine stack (tree-sitter, CPG) applies.
  const dir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'throughline-'));
  const file = path.join(dir, path.basename(args.filename));
  try {
    fs.writeFileSync(file, args.code, 'utf-8');
    const result = scan({ paths: [file], entropy: true, deps: false, applyTriage: false });
    return {
      filename: args.filename,
      totalFindings: result.findings.length,
      findings: result.findings.map(f => ({ ...summarizeFinding(f), file: args.filename })),
    };
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* temp cleanup */ }
  }
}

// ─── Rules ─────────────────────────────────────────────────────────────

export function listRules(args: { severity?: string }) {
  const userRules = loadUserRules();
  const pool = [...allRules, ...userRules];
  const userIds = new Set(userRules.map(r => r.id));
  const wantSeverity = args.severity?.toLowerCase();
  const filtered = wantSeverity ? pool.filter(r => r.severity === wantSeverity) : pool;

  return {
    totalRules: filtered.length,
    builtIn: filtered.length - filtered.filter(r => userIds.has(r.id)).length,
    custom: filtered.filter(r => userIds.has(r.id)).length,
    rules: filtered.map(r => ({
      id: r.id,
      name: r.name,
      severity: r.severity,
      confidence: r.confidence,
      cwe: r.cwe,
      owasp: r.owasp,
      extensions: r.extensions,
      source: userIds.has(r.id) ? 'custom' : 'built-in',
      description: r.description,
    })),
    note: 'Taint-engine findings use synthesised IDs (cpg-precise-*, cpg-direct-*, interproc-taint, entropy-*, dep-cve). Selecting the matching declared rule — e.g. sql-injection — includes them.',
  };
}

export function ruleSummary() {
  return getRuleSummary();
}

export function createCustomRule(args: {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  cwe?: string;
  owasp?: string;
  patterns: { regex: string; message: string; recommendation?: string }[];
  extensions?: string[];
  confidence?: 'certain' | 'high' | 'medium' | 'low';
  contextPatterns?: { regex: string; message: string }[];
  excludeContextPatterns?: { regex: string; message: string }[];
  matchAll?: boolean;
}) {
  if (!/^[a-z0-9][a-z0-9-]*$/.test(args.id)) {
    throw new Error(`Rule id "${args.id}" must be kebab-case (lowercase letters, digits, hyphens).`);
  }
  if (!args.patterns || args.patterns.length === 0) {
    throw new Error('At least one pattern is required.');
  }

  // The loader compiles every pattern with 'gi'; validate under the same flags
  // so an invalid regex is rejected here rather than skipped at load time.
  const all = [...args.patterns, ...(args.contextPatterns || []), ...(args.excludeContextPatterns || [])];
  for (const p of all) {
    try {
      new RegExp(p.regex, 'gi');
    } catch (err) {
      throw new Error(`Pattern "${p.regex}" is not a valid regex: ${(err as Error).message}`);
    }
  }

  const dir = path.resolve('.throughline-rules');
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `${args.id}.json`);
  const existed = fs.existsSync(file);

  const rule = {
    id: args.id,
    name: args.name,
    description: args.description,
    severity: args.severity,
    confidence: args.confidence || 'medium',
    cwe: args.cwe,
    owasp: args.owasp,
    extensions: args.extensions && args.extensions.length > 0 ? args.extensions : ['*'],
    patterns: args.patterns.map(p => ({
      regex: p.regex,
      message: p.message,
      recommendation: p.recommendation,
    })),
    contextPatterns: args.contextPatterns,
    excludeContextPatterns: args.excludeContextPatterns,
    matchAll: args.matchAll,
  };
  fs.writeFileSync(file, JSON.stringify(rule, null, 2), 'utf-8');

  // Confirm the loader actually accepts it rather than trusting the write.
  const loaded = loadUserRules().some(r => r.id === args.id);
  return {
    created: file,
    overwrote: existed,
    loadable: loaded,
    rule,
    note: loaded
      ? 'Rule validated by the loader and active on the next scan.'
      : 'WARNING: written, but the loader did not pick it up — check the scanner output for a skip warning.',
  };
}

export function initExampleRules() {
  const created = generateExampleRules();
  return created.length > 0
    ? { created, note: 'Edit these and re-scan; custom rules load automatically.' }
    : { created: [], note: 'Example rules already exist in .throughline-rules/' };
}

// ─── Reporting ─────────────────────────────────────────────────────────

export async function exportReport(args: ScanArgs & { format: 'json' | 'sarif' | 'html' | 'pretty'; outputPath: string }) {
  const options = toScanOptions(args);
  const result = await scanAsync(options);
  lastScan = { result, at: new Date().toISOString(), paths: options.paths };

  const output =
    args.format === 'sarif' ? sarifFormat(result) :
    args.format === 'html' ? htmlFormat(result) :
    args.format === 'pretty' ? prettyFormat(result) :
    jsonFormat(result);

  const outPath = path.resolve(args.outputPath);
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, output, 'utf-8');

  return {
    written: outPath,
    format: args.format,
    bytes: Buffer.byteLength(output, 'utf8'),
    totalFindings: result.findings.length,
    summary: result.summary,
  };
}

// ─── Cache ─────────────────────────────────────────────────────────────

export function getCacheStats() {
  const stats = cacheStats();
  return {
    cachedFiles: stats.totalFiles,
    totalSizeMb: +(stats.totalSize / 1024 / 1024).toFixed(2),
    oldestEntry: stats.oldestEntry ? new Date(stats.oldestEntry).toISOString() : null,
    newestEntry: stats.newestEntry ? new Date(stats.newestEntry).toISOString() : null,
    triage: triageStats(loadTriageStore()),
  };
}

export function resetCache(args: { includeTriage?: boolean }) {
  clearCache();
  const triageCleared = args.includeTriage ? clearTriage() : 0;
  return {
    cacheCleared: true,
    triageVerdictsCleared: triageCleared,
    note: args.includeTriage
      ? 'Incremental cache and all triage verdicts removed.'
      : 'Incremental cache removed. Triage verdicts kept — pass includeTriage to drop them too.',
  };
}

// ─── Triage: the AI review loop ────────────────────────────────────────

function findingsFromLastScanOrScan(paths?: string[]): Finding[] {
  if (lastScan) return lastScan.result.findings;
  const result = scan({ paths: paths && paths.length ? paths : ['.'], deps: false, applyTriage: false });
  lastScan = { result, at: new Date().toISOString(), paths: result.findings.map(f => f.file) };
  return result.findings;
}

export function getReviewQueue(args: { limit?: number; severity?: Severity; contextRadius?: number; paths?: string[] }) {
  const limit = Math.min(args.limit ?? 10, 25);
  const store = loadTriageStore();

  let findings = findingsFromLastScanOrScan(args.paths);
  if (args.severity) findings = findings.filter(f => f.severity === args.severity);

  // Skip anything already reviewed against the current code
  const pending = findings.filter(f => {
    const existing = store.verdicts[findingKey(f)];
    return !existing || existing.codeHash !== codeHashOf(f.snippet);
  });

  const queue = prioritizeForReview(pending).slice(0, limit);
  return {
    instructions: TRIAGE_INSTRUCTIONS,
    pendingTotal: pending.length,
    alreadyReviewed: findings.length - pending.length,
    returned: queue.length,
    packets: queue.map(f => buildReviewPacket(f, args.contextRadius ?? 12)),
    nextStep: 'Judge each packet, then call submit_triage with one verdict per finding.',
  };
}

export function getFindingContext(args: { file: string; line: number; radius?: number }) {
  const stub = {
    ruleId: '', title: '', severity: 'info', confidence: 'low', message: '',
    file: args.file, line: args.line, column: 0, snippet: '', recommendation: '',
    cwe: 'CWE-0', owasp: '', references: [], falsePositiveRisk: 'low',
  } as unknown as Finding;
  return {
    file: args.file,
    line: args.line,
    context: readFindingContext(stub, args.radius ?? 20),
  };
}

export function submitTriage(args: { verdicts: RawVerdict[]; triagedBy?: string }) {
  const now = new Date().toISOString();
  const triagedBy = args.triagedBy || 'mcp-client';
  const accepted: TriageVerdict[] = [];
  const rejected: { findingKey: string; error: string }[] = [];

  for (const raw of args.verdicts) {
    const validated = validateVerdict(raw, triagedBy, now);
    if (validated.ok) accepted.push(validated.verdict);
    else rejected.push({ findingKey: raw?.findingKey ?? '(missing)', error: validated.error });
  }

  const stored = accepted.length > 0 ? recordVerdicts(accepted) : Object.keys(loadTriageStore().verdicts).length;

  return {
    accepted: accepted.length,
    rejected,
    totalStoredVerdicts: stored,
    falsePositivesRecorded: accepted.filter(v => !v.isRealVulnerability).length,
    note: rejected.length > 0
      ? 'Rejected verdicts were not stored. Fix the listed errors and resubmit those findings.'
      : 'Verdicts stored. Future scans hide confirmed false positives and report the suppression count.',
  };
}

export function getTriage(args: { onlyFalsePositives?: boolean }) {
  const store = loadTriageStore();
  let verdicts = Object.values(store.verdicts);
  if (args.onlyFalsePositives) verdicts = verdicts.filter(v => !v.isRealVulnerability);
  return { stats: triageStats(store), verdicts };
}

// ─── Fixes ─────────────────────────────────────────────────────────────

export function suggestFix(args: { findingKey: string }) {
  const findings = findingsFromLastScanOrScan();
  const finding = findings.find(f => findingKey(f) === args.findingKey);
  if (!finding) {
    throw new Error(`No finding "${args.findingKey}" in the last scan. Run scan first, or check get_review_queue for valid keys.`);
  }
  return {
    findingKey: args.findingKey,
    file: finding.file,
    line: finding.line,
    currentCode: readFindingContext(finding, 8),
    templateFix: suggestFixTemplate(finding),
    note: 'This is a generic template. Write the actual patch against the code above and apply it with apply_fix.',
  };
}

/**
 * Apply a patch by exact-match replacement. Deliberately not a fuzzy patcher —
 * an approximate edit to security-relevant code is worse than no edit.
 */
export function applyFix(args: { file: string; oldCode: string; newCode: string; expectedLine?: number }) {
  const file = path.resolve(args.file);
  if (!fs.existsSync(file)) throw new Error(`File not found: ${file}`);

  const original = fs.readFileSync(file, 'utf-8');
  const occurrences = original.split(args.oldCode).length - 1;

  if (occurrences === 0) {
    throw new Error(`oldCode not found in ${args.file}. It must match the file exactly, including indentation.`);
  }
  if (occurrences > 1) {
    throw new Error(`oldCode appears ${occurrences} times in ${args.file}. Include more surrounding context to make it unique.`);
  }

  if (args.expectedLine !== undefined) {
    const actualLine = original.slice(0, original.indexOf(args.oldCode)).split('\n').length;
    if (Math.abs(actualLine - args.expectedLine) > 3) {
      throw new Error(`oldCode matched at line ${actualLine} but line ${args.expectedLine} was expected — refusing to edit the wrong site.`);
    }
  }

  const updated = original.replace(args.oldCode, args.newCode);
  fs.writeFileSync(file, updated, 'utf-8');

  // Re-scan just this file so the caller sees the effect immediately.
  const after = scan({ paths: [file], deps: false, applyTriage: false });
  return {
    file,
    applied: true,
    findingsRemainingInFile: after.findings.length,
    remaining: after.findings.slice(0, 10).map(summarizeFinding),
    note: 'Re-scanned this file after the edit. Verify the change compiles and tests pass.',
  };
}
