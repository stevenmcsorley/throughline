/**
 * Semantic Diff Analysis
 *
 * Compares two scan snapshots and classifies findings as:
 *   - Introduced: new vulnerabilities in this commit
 *   - Resolved: vulnerabilities fixed in this commit  
 *   - Persisted: vulnerabilities unchanged between commits
 *   - Worsened: same finding, severity increased
 *   - Improved: same finding, severity decreased
 *
 * Usage:
 *   throughline --diff HEAD~5..HEAD ./src
 *   throughline --diff main..feature ./src --format html -o diff-report.html
 */

import { Finding, Severity, ScanResult } from '../types';

// ─── Types ─────────────────────────────────────────────────────────────

export type DiffClassification =
  | 'introduced'
  | 'resolved'
  | 'persisted'
  | 'worsened'
  | 'improved';

export interface DiffFinding extends Finding {
  classification: DiffClassification;
  previousSeverity?: Severity;
}

export interface DiffResult {
  baseRef: string;
  targetRef: string;
  introduced: DiffFinding[];
  resolved: DiffFinding[];
  persisted: DiffFinding[];
  worsened: DiffFinding[];
  improved: DiffFinding[];
  summary: {
    totalBefore: number;
    totalAfter: number;
    delta: number;
    introducedCount: number;
    resolvedCount: number;
    worsenedCount: number;
    improvedCount: number;
    netChange: string;
  };
}

// ─── Finding Fingerprint ───────────────────────────────────────────────

/**
 * Create a stable fingerprint for a finding.
 * Uses file path + rule ID + location + a fuzzy match on the title.
 * This allows tracking findings across refactors where line numbers shift.
 */
function fingerprint(finding: Finding): string {
  const normalizedFile = finding.file.replace(/\\/g, '/');
  // Extract the core rule + file combo. Line number is secondary.
  return `${normalizedFile}::${finding.ruleId}`;
}

function fingerprintWithLocation(finding: Finding): string {
  const normalizedFile = finding.file.replace(/\\/g, '/');
  // Within a file, same rule near the same area is likely the same finding
  const lineBucket = Math.floor(finding.line / 10) * 10;
  return `${normalizedFile}:${lineBucket}:${finding.ruleId}`;
}

// ─── Diff Engine ───────────────────────────────────────────────────────

/**
 * Compute the semantic diff between two sets of findings.
 */
export function diffFindings(
  before: Finding[],
  after: Finding[]
): DiffResult {
  // Build lookup maps
  const beforeMap = new Map<string, Finding[]>();
  const afterMap = new Map<string, Finding[]>();

  for (const f of before) {
    const fp = fingerprint(f);
    if (!beforeMap.has(fp)) beforeMap.set(fp, []);
    beforeMap.get(fp)!.push(f);
  }

  for (const f of after) {
    const fp = fingerprint(f);
    if (!afterMap.has(fp)) afterMap.set(fp, []);
    afterMap.get(fp)!.push(f);
  }

  const introduced: DiffFinding[] = [];
  const resolved: DiffFinding[] = [];
  const persisted: DiffFinding[] = [];
  const worsened: DiffFinding[] = [];
  const improved: DiffFinding[] = [];

  // Find introduced and worsened
  for (const [fp, afterFindings] of afterMap) {
    const beforeFindings = beforeMap.get(fp) || [];

    if (beforeFindings.length === 0) {
      // New rule+file combination — introduced
      for (const f of afterFindings) {
        introduced.push({ ...f, classification: 'introduced' });
      }
      continue;
    }

    // Same rule+file: try to match individual findings
    const matched = new Set<number>();
    for (const af of afterFindings) {
      let bestMatch: Finding | null = null;
      let bestIndex = -1;
      let bestDist = Infinity;

      for (let i = 0; i < beforeFindings.length; i++) {
        if (matched.has(i)) continue;
        const bf = beforeFindings[i];
        const dist = Math.abs(af.line - bf.line);
        if (dist < bestDist && dist < 20) {
          bestDist = dist;
          bestMatch = bf;
          bestIndex = i;
        }
      }

      // Claim the match so it is not reused by another finding and is not
      // reported as resolved below.
      if (bestIndex >= 0) matched.add(bestIndex);

      if (bestMatch) {
        // Compare severity
        const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        const prevSev = sevOrder[bestMatch.severity];
        const currSev = sevOrder[af.severity];

        if (currSev < prevSev) {
          worsened.push({ ...af, classification: 'worsened', previousSeverity: bestMatch.severity });
        } else if (currSev > prevSev) {
          improved.push({ ...af, classification: 'improved', previousSeverity: bestMatch.severity });
        } else {
          persisted.push({ ...af, classification: 'persisted' });
        }
      } else {
        // Same rule+file but no nearby match — treat as introduced
        introduced.push({ ...af, classification: 'introduced' });
      }
    }

    // Mark matched before findings
    for (let i = 0; i < beforeFindings.length; i++) {
      if (!matched.has(i)) {
        resolved.push({ ...beforeFindings[i], classification: 'resolved' });
      }
    }
  }

  // Find resolved (in before but not in after)
  for (const [fp, beforeFindings] of beforeMap) {
    if (!afterMap.has(fp)) {
      for (const f of beforeFindings) {
        resolved.push({ ...f, classification: 'resolved' });
      }
    }
  }

  // Deduplicate resolved
  const resolvedUnique = resolved.filter(
    (r, i, arr) => arr.findIndex(x =>
      `${x.file}:${x.line}:${x.ruleId}` === `${r.file}:${r.line}:${r.ruleId}`
    ) === i
  );

  const delta = after.length - before.length;
  const netChange = delta > 0 ? `+${delta} worse` :
                    delta < 0 ? `${delta} better` :
                    'unchanged';

  return {
    baseRef: 'before',
    targetRef: 'after',
    introduced,
    resolved: resolvedUnique,
    persisted,
    worsened,
    improved,
    summary: {
      totalBefore: before.length,
      totalAfter: after.length,
      delta,
      introducedCount: introduced.length,
      resolvedCount: resolvedUnique.length,
      worsenedCount: worsened.length,
      improvedCount: improved.length,
      netChange,
    },
  };
}

// ─── Git Diff Integration ──────────────────────────────────────────────

/**
 * Get the list of files changed between two git refs.
 */
/**
 * Run git without a shell.
 *
 * execSync would route through cmd.exe on Windows, where `^` is the escape
 * character — so `HEAD~1^{commit}` silently loses its peel and every ref lookup
 * fails. execFileSync passes argv straight to the process, which also means ref
 * names cannot be misread as shell syntax.
 */
function git(args: string[], timeout = 30000): string {
  const { execFileSync } = require('child_process');
  return execFileSync('git', args, { encoding: 'utf-8', timeout, stdio: 'pipe' });
}

export function getGitDiffFiles(baseRef: string, targetRef: string = 'HEAD'): string[] {
  try {
    return git(['diff', '--name-only', baseRef, targetRef]).split('\n').filter(Boolean);
  } catch {
    return [];
  }
}

/**
 * Get the diff stat summary between two git refs.
 */
export function getGitDiffStat(baseRef: string, targetRef: string = 'HEAD'): string {
  try {
    return git(['diff', '--stat', baseRef, targetRef]);
  } catch {
    return '';
  }
}

/** True when the working directory is inside a git repository. */
export function isGitRepository(): boolean {
  try {
    git(['rev-parse', '--git-dir']);
    return true;
  } catch {
    return false;
  }
}

/** Resolve a ref to a commit SHA, or null if it does not exist. */
export function resolveRef(ref: string): string | null {
  try {
    return git(['rev-parse', '--verify', `${ref}^{commit}`]).trim();
  } catch {
    return null;
  }
}

export interface MaterializedRef {
  /** Directory containing the tree at that revision */
  dir: string;
  /** Must be called when finished, in success and failure alike */
  cleanup: () => void;
}

/**
 * Materialise a git ref into a temporary directory.
 *
 * Uses `git worktree`, which checks the revision out somewhere else entirely —
 * the current working copy, index, and HEAD are all untouched, so scanning a
 * historical revision can never disturb uncommitted work.
 *
 * `git archive` piped through tar was the obvious alternative and does not
 * survive contact with Windows: the tar on PATH there is often GNU tar from
 * MSYS, which reads `C:\...` as a remote host spec and refuses. Worktrees need
 * nothing but git.
 */
export function materializeRef(ref: string): MaterializedRef {
  const fs = require('fs');
  const os = require('os');
  const pathMod = require('path');

  const parent = fs.mkdtempSync(pathMod.join(os.tmpdir(), 'throughline-ref-'));
  // git worktree requires a path that does not already exist.
  const dir = pathMod.join(parent, 'tree');

  const cleanup = () => {
    try { git(['worktree', 'remove', '--force', dir], 60000); } catch { /* fall through */ }
    try { fs.rmSync(parent, { recursive: true, force: true }); } catch { /* best effort */ }
    try { git(['worktree', 'prune'], 30000); } catch { /* best effort */ }
  };

  try {
    git(['worktree', 'add', '--detach', '--quiet', dir, ref], 180000);
    return { dir, cleanup };
  } catch (err) {
    cleanup();
    const detail = ((err as any)?.stderr?.toString() || (err as Error).message || '')
      .split('\n').filter(Boolean)[0] || 'unknown error';
    throw new Error(`Could not check out ref "${ref}": ${detail}`);
  }
}

/**
 * Rewrite finding paths from a materialised checkout back to repo-relative
 * form, so before/after findings share a coordinate system and can be matched.
 */
export function relativizeFindings(findings: Finding[], rootDir: string): Finding[] {
  const pathMod = require('path');
  const root = pathMod.resolve(rootDir);
  return findings.map(f => {
    const abs = pathMod.resolve(f.file);
    const rel = pathMod.relative(root, abs);
    return {
      ...f,
      file: (rel && !rel.startsWith('..') ? rel : abs).replace(/\\/g, '/'),
    };
  });
}

// ─── Diff Formatter ────────────────────────────────────────────────────

/**
 * Format a diff result as a pretty terminal string.
 */
export function formatDiffResult(diff: DiffResult, baseRef: string, targetRef: string): string {
  const lines: string[] = [];
  const s = diff.summary;

  lines.push('');
  lines.push('╔══════════════════════════════════════════════════════════╗');
  lines.push('║     Throughline — Semantic Diff Analysis               ║');
  lines.push('╚══════════════════════════════════════════════════════════╝');
  lines.push('');
  lines.push(`  Range:  ${baseRef} → ${targetRef}`);
  lines.push(`  Before: ${s.totalBefore} findings  |  After: ${s.totalAfter} findings`);
  lines.push(`  Δ:      ${s.netChange}`);
  lines.push('');
  lines.push(`  ┌──────────────────────────────────────┐`);
  lines.push(`  │  🔴 Introduced:   ${String(s.introducedCount).padStart(4)}               │`);
  lines.push(`  │  🟢 Resolved:     ${String(s.resolvedCount).padStart(4)}               │`);
  lines.push(`  │  🔶 Worsened:     ${String(s.worsenedCount).padStart(4)}               │`);
  lines.push(`  │  🔷 Improved:     ${String(s.improvedCount).padStart(4)}               │`);
  lines.push(`  │  ⚪ Persisted:    ${String(diff.persisted.length).padStart(4)}               │`);
  lines.push(`  └──────────────────────────────────────┘`);

  // Show introduced findings in detail
  if (diff.introduced.length > 0) {
    lines.push('');
    lines.push('  ── 🟡 NEW VULNERABILITIES ──');
    for (const f of diff.introduced) {
      const icon = f.severity === 'critical' ? '◉' :
                   f.severity === 'high' ? '▲' :
                   f.severity === 'medium' ? '●' : '○';
      lines.push(`  ${icon} [${f.ruleId}] ${f.file}:${f.line}`);
      lines.push(`    ${f.title}`);
      if (f.recommendation) lines.push(`    → ${f.recommendation}`);
      lines.push('');
    }
  }

  // Show resolved findings
  if (diff.resolved.length > 0) {
    lines.push('');
    lines.push(`  ── 🟢 FIXED (${diff.resolved.length}) ──`);
    for (const f of diff.resolved.slice(0, 10)) {
      lines.push(`  ✓ ${f.ruleId} @ ${f.file}:${f.line} — ${f.title}`);
    }
    if (diff.resolved.length > 10) {
      lines.push(`  ... and ${diff.resolved.length - 10} more`);
    }
  }

  // Show worsened
  if (diff.worsened.length > 0) {
    lines.push('');
    lines.push(`  ── 🔶 SEVERITY INCREASED (${diff.worsened.length}) ──`);
    for (const f of diff.worsened) {
      lines.push(`  ⬆ ${f.previousSeverity} → ${f.severity}  [${f.ruleId}] ${f.file}:${f.line}`);
    }
  }

  // Show improved
  if (diff.improved.length > 0) {
    lines.push('');
    lines.push(`  ── 🔷 SEVERITY DECREASED (${diff.improved.length}) ──`);
    for (const f of diff.improved) {
      lines.push(`  ⬇ ${f.previousSeverity} → ${f.severity}  [${f.ruleId}] ${f.file}:${f.line}`);
    }
  }

  lines.push('');
  return lines.join('\n');
}

// ─── Snapshot-Based Diff ───────────────────────────────────────────────
//
// `diffSnapshotsById` used to live here. Snapshots only record per-rule finding
// *counts*, so it reconstructed synthetic findings — every one at line 0 with a
// hardcoded 'high' severity — and diffed those. The output looked like a real
// comparison and was not one. Nothing called it, and the honest version of that
// feature is `--diff`, which checks the base revision out and scans it for real
// (see materializeRef above).
