/**
 * Triage Store
 *
 * Persistent record of which findings a reviewer (human or AI) has judged real
 * or false-positive, with the reasoning and any generated fix.
 *
 * This is the storage half of the AI triage feature. The *analysis* half is not
 * performed here and is not performed by an HTTP call to a model provider — it
 * is performed by whatever AI is driving the MCP server (see src/mcp/), which
 * reads findings, requests source context, and writes verdicts back through the
 * `submit_triage` tool. That keeps a single model in the loop with the user's
 * full project context instead of a blind one-finding-at-a-time API call.
 *
 * Verdicts are bound to a hash of the code they were made about, so editing the
 * offending line invalidates the verdict rather than silently suppressing a
 * finding about code the reviewer never saw.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { Finding, Severity, Confidence } from '../types';

const CACHE_DIR = '.throughline-cache';
const TRIAGE_FILE = 'triage.json';
const STORE_VERSION = 1;

export interface TriageVerdict {
  /** `ruleId:file:line` — see findingKey() */
  findingKey: string;
  /** Hash of the code this verdict was made about; mismatch ⇒ stale */
  codeHash: string;
  isRealVulnerability: boolean;
  /** The reviewer's confidence in their own verdict */
  reviewConfidence: Confidence;
  analysis: string;
  riskAssessment?: string;
  exploitScenario?: string;
  /** Overrides the scanner's severity when present */
  adjustedSeverity?: Severity;
  fix?: string;
  fixIsAutoApplicable?: boolean;
  caveats?: string;
  /** Model or person that produced this verdict, e.g. "claude-opus-5" */
  triagedBy: string;
  /** ISO 8601 */
  triagedAt: string;
}

export interface TriageStore {
  version: number;
  verdicts: Record<string, TriageVerdict>;
}

export interface TriageOutcome {
  /** Findings dropped because a fresh verdict marked them false-positive */
  suppressed: number;
  /** Findings whose severity a verdict overrode */
  severityAdjusted: number;
  /** Verdicts skipped because the code they described has since changed */
  stale: number;
}

// ─── Keys & hashing ────────────────────────────────────────────────────

/**
 * Paths are stored relative to the working directory with forward slashes so a
 * store stays valid across machines and shells.
 */
export function normalizeFilePath(file: string): string {
  const abs = path.resolve(file);
  const rel = path.relative(process.cwd(), abs);
  const chosen = rel && !rel.startsWith('..') ? rel : abs;
  return chosen.replace(/\\/g, '/');
}

export function findingKey(finding: Pick<Finding, 'ruleId' | 'file' | 'line'>): string {
  return `${finding.ruleId}:${normalizeFilePath(finding.file)}:${finding.line}`;
}

/**
 * Hash the code a verdict is about. Whitespace is collapsed so reformatting
 * does not invalidate a verdict, but any real edit does.
 */
export function codeHashOf(snippet: string): string {
  const normalized = snippet.replace(/\s+/g, ' ').trim();
  return crypto.createHash('sha256').update(normalized).digest('hex').slice(0, 16);
}

// ─── Persistence ───────────────────────────────────────────────────────

function storePath(baseDir: string = process.cwd()): string {
  return path.join(baseDir, CACHE_DIR, TRIAGE_FILE);
}

export function loadTriageStore(baseDir?: string): TriageStore {
  const file = storePath(baseDir);
  try {
    const raw = fs.readFileSync(file, 'utf-8');
    const parsed = JSON.parse(raw) as TriageStore;
    if (parsed.version !== STORE_VERSION || typeof parsed.verdicts !== 'object' || !parsed.verdicts) {
      return { version: STORE_VERSION, verdicts: {} };
    }
    return parsed;
  } catch {
    // Missing or corrupt — start clean rather than failing the scan
    return { version: STORE_VERSION, verdicts: {} };
  }
}

export function saveTriageStore(store: TriageStore, baseDir?: string): void {
  const file = storePath(baseDir);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(store, null, 2), 'utf-8');
}

export function recordVerdicts(verdicts: TriageVerdict[], baseDir?: string): number {
  const store = loadTriageStore(baseDir);
  for (const v of verdicts) {
    store.verdicts[v.findingKey] = v;
  }
  saveTriageStore(store, baseDir);
  return Object.keys(store.verdicts).length;
}

export function clearTriage(baseDir?: string): number {
  const store = loadTriageStore(baseDir);
  const count = Object.keys(store.verdicts).length;
  saveTriageStore({ version: STORE_VERSION, verdicts: {} }, baseDir);
  return count;
}

// ─── Application ───────────────────────────────────────────────────────

/**
 * Look up a verdict for a finding, returning it only if it still describes the
 * current code.
 */
export function verdictFor(
  finding: Finding,
  store: TriageStore
): { verdict: TriageVerdict; stale: boolean } | null {
  const verdict = store.verdicts[findingKey(finding)];
  if (!verdict) return null;
  return { verdict, stale: verdict.codeHash !== codeHashOf(finding.snippet) };
}

/**
 * Apply stored verdicts to a finding list: drop confirmed false positives and
 * override severity where a reviewer corrected it.
 *
 * Suppression is always reported back through TriageOutcome — a security tool
 * must never quietly hide a finding.
 */
export function applyTriage(
  findings: Finding[],
  store: TriageStore
): { findings: Finding[]; outcome: TriageOutcome } {
  const outcome: TriageOutcome = { suppressed: 0, severityAdjusted: 0, stale: 0 };
  const kept: Finding[] = [];

  for (const finding of findings) {
    const hit = verdictFor(finding, store);
    if (!hit) {
      kept.push(finding);
      continue;
    }

    if (hit.stale) {
      // Code changed since review — the verdict no longer applies
      outcome.stale++;
      kept.push(finding);
      continue;
    }

    if (!hit.verdict.isRealVulnerability) {
      outcome.suppressed++;
      continue;
    }

    if (hit.verdict.adjustedSeverity && hit.verdict.adjustedSeverity !== finding.severity) {
      finding.severity = hit.verdict.adjustedSeverity;
      outcome.severityAdjusted++;
    }
    if (hit.verdict.fix) {
      finding.fixExample = hit.verdict.fix;
    }
    kept.push(finding);
  }

  return { findings: kept, outcome };
}

export function triageStats(store: TriageStore): {
  total: number;
  confirmedReal: number;
  falsePositives: number;
  withFixes: number;
} {
  const all = Object.values(store.verdicts);
  return {
    total: all.length,
    confirmedReal: all.filter(v => v.isRealVulnerability).length,
    falsePositives: all.filter(v => !v.isRealVulnerability).length,
    withFixes: all.filter(v => v.fix && v.fix.trim().length > 0).length,
  };
}
