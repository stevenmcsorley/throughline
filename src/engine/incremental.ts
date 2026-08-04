/**
 * Incremental / Diff Scanning Engine
 *
 * Caches per-file scan hashes so subsequent scans only re-analyze
 * files that changed. Dramatically improves CI performance.
 *
 * Cache structure:
 *   .throughline-cache/
 *   ├── manifest.json          # Global cache manifest
 *   ├── hashes/                # SHA-256 per file keyed by path+salt
 *   │   ├── a1b2c3d4...json
 *   │   └── e5f6g7h8...json
 *   └── snapshots/             # Scan snapshots for diff comparison
 *       └── snapshot-N.json    # Full scan snapshots by timestamp
 *
 * Features:
 *   - Content-addressed file hashing (SHA-256)
 *   - Change detection: modified, added, deleted, renamed
 *   - Git-aware: integrates with git diff for intelligent file selection
 *   - Snapshot comparison: diff two scan runs for trending
 *   - Cache invalidation on config/rule changes
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { Finding } from '../types';

// ─── Types ─────────────────────────────────────────────────────────────

interface FileEntry {
  /** Relative file path */
  path: string;
  /** SHA-256 hash of file contents */
  hash: string;
  /** File size in bytes */
  size: number;
  /** Last scan timestamp */
  lastScan: number;
  /** Number of findings in last scan */
  findingCount: number;
  /** Finding severity counts */
  severityCounts: Record<string, number>;
}

interface CacheManifest {
  version: number;
  created: number;
  configHash: string;
  rulesHash: string;
  fileCount: number;
  files: Record<string, FileEntry>;
  snapshots: string[];
}

interface ScanSnapshot {
  timestamp: number;
  totalFiles: number;
  scannedFiles: number;
  skippedFiles: number;
  newFiles: string[];
  changedFiles: string[];
  deletedFiles: string[];
  unchangedFiles: string[];
  totalFindings: number;
  findingsBySeverity: Record<string, number>;
  findingsByRule: Record<string, number>;
  files: Record<string, { hash: string; findings: number }>;
}

interface DiffResult {
  added: Finding[];
  removed: Finding[];
  unchanged: number;
  summary: string;
}

export interface ChangeSet {
  added: string[];
  modified: string[];
  deleted: string[];
  unchanged: string[];
}

// ─── Defaults ──────────────────────────────────────────────────────────

const CACHE_DIR = '.throughline-cache';
const MANIFEST_FILE = 'manifest.json';
const HASHES_DIR = 'hashes';
const SNAPSHOTS_DIR = 'snapshots';
const CACHE_VERSION = 2;

// ─── Hash Computation ──────────────────────────────────────────────────

function computeFileHash(filePath: string): string {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

function computeConfigHash(options: any, rules: any): string {
  const data = JSON.stringify({ options, ruleIds: Object.keys(rules || {}) });
  return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
}

// ─── Cache Management ──────────────────────────────────────────────────

function cachePath(subdir: string): string {
  return path.join(CACHE_DIR, subdir);
}

function ensureCacheDir(): void {
  const dirs = [CACHE_DIR, cachePath(HASHES_DIR), cachePath(SNAPSHOTS_DIR)];
  for (const dir of dirs) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }
}

export function loadManifest(): CacheManifest {
  const manifestPath = cachePath(MANIFEST_FILE);
  if (!fs.existsSync(manifestPath)) {
    return {
      version: CACHE_VERSION,
      created: Date.now(),
      configHash: '',
      rulesHash: '',
      fileCount: 0,
      files: {},
      snapshots: [],
    };
  }
  try {
    return JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
  } catch {
    return {
      version: CACHE_VERSION,
      created: Date.now(),
      configHash: '',
      rulesHash: '',
      fileCount: 0,
      files: {},
      snapshots: [],
    };
  }
}

function saveManifest(manifest: CacheManifest): void {
  ensureCacheDir();
  fs.writeFileSync(cachePath(MANIFEST_FILE), JSON.stringify(manifest, null, 2));
}

function getCachedFileEntry(filePath: string): FileEntry | null {
  const manifest = loadManifest();
  return manifest.files[filePath] || null;
}

function updateFileEntry(filePath: string, findings: Finding[]): FileEntry {
  const hash = computeFileHash(filePath);
  const stats = fs.statSync(filePath);

  const severityCounts: Record<string, number> = {};
  for (const f of findings) {
    severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1;
  }

  const entry: FileEntry = {
    path: filePath,
    hash,
    size: stats.size,
    lastScan: Date.now(),
    findingCount: findings.length,
    severityCounts,
  };

  return entry;
}

// ─── Change Detection ──────────────────────────────────────────────────

/**
 * Compare current file set to cached manifest.
 * Returns categorized change sets.
 */
export function detectChanges(
  files: string[],
  configHash: string,
  rulesHash: string
): ChangeSet {
  const normalizedFiles = files.map(f => f.replace(/\\/g, '/'));
  const manifest = loadManifest();

  // If config or rules changed, invalidate everything
  if (manifest.configHash !== configHash || manifest.rulesHash !== rulesHash) {
    return {
      added: normalizedFiles,
      modified: [],
      deleted: Object.keys(manifest.files),
      unchanged: [],
    };
  }

  const fileSet = new Set(normalizedFiles);
  const cachedSet = new Set(Object.keys(manifest.files));

  const added: string[] = [];
  const modified: string[] = [];
  const unchanged: string[] = [];
  const deleted: string[] = [];

  for (const file of normalizedFiles) {
    if (!cachedSet.has(file)) {
      added.push(file);
    } else {
      const cached = manifest.files[file];
      try {
        const currentHash = computeFileHash(file);
        if (currentHash !== cached.hash) {
          modified.push(file);
        } else {
          unchanged.push(file);
        }
      } catch {
        // File may have been deleted since scan started
        deleted.push(file);
      }
    }
  }

  for (const file of cachedSet) {
    if (!fileSet.has(file)) {
      deleted.push(file);
    }
  }

  return { added, modified, deleted, unchanged };
}

// ─── Snapshot Management ───────────────────────────────────────────────

/**
 * Create a full scan snapshot for later comparison.
 */
export function createSnapshot(
  findings: Finding[],
  files: string[],
  changeSet: ChangeSet
): ScanSnapshot {
  const severityCounts: Record<string, number> = {};
  const ruleCounts: Record<string, number> = {};
  const fileMap: Record<string, { hash: string; findings: number }> = {};

  for (const f of findings) {
    severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1;
    ruleCounts[f.ruleId] = (ruleCounts[f.ruleId] || 0) + 1;
  }

  for (const file of files) {
    const fileFindings = findings.filter(f => f.file.replace(/\\/g, '/') === file.replace(/\\/g, '/'));
    try {
      const hash = computeFileHash(file);
      fileMap[file.replace(/\\/g, '/')] = { hash, findings: fileFindings.length };
    } catch {
      fileMap[file.replace(/\\/g, '/')] = { hash: 'ERROR', findings: 0 };
    }
  }

  return {
    timestamp: Date.now(),
    totalFiles: files.length,
    scannedFiles: changeSet.added.length + changeSet.modified.length + changeSet.unchanged.length,
    skippedFiles: changeSet.unchanged.length,
    newFiles: changeSet.added,
    changedFiles: changeSet.modified,
    deletedFiles: changeSet.deleted,
    unchangedFiles: changeSet.unchanged,
    totalFindings: findings.length,
    findingsBySeverity: severityCounts,
    findingsByRule: ruleCounts,
    files: fileMap,
  };
}

function saveSnapshot(snapshot: ScanSnapshot): string {
  ensureCacheDir();
  const id = `snapshot-${Date.now()}-${Math.random().toString(36).substring(2, 8)}.json`;
  const filePath = cachePath(path.join(SNAPSHOTS_DIR, id));
  fs.writeFileSync(filePath, JSON.stringify(snapshot, null, 2));

  const manifest = loadManifest();
  manifest.snapshots.push(id);
  // Keep last 50 snapshots
  if (manifest.snapshots.length > 50) {
    const removed = manifest.snapshots.shift()!;
    const oldPath = cachePath(path.join(SNAPSHOTS_DIR, removed));
    try { fs.unlinkSync(oldPath); } catch { /* ok */ }
  }
  saveManifest(manifest);

  return id;
}

export function loadSnapshot(snapshotId: string): ScanSnapshot | null {
  try {
    return JSON.parse(fs.readFileSync(cachePath(path.join(SNAPSHOTS_DIR, snapshotId)), 'utf-8'));
  } catch {
    return null;
  }
}

// ─── Diff Comparison ───────────────────────────────────────────────────

/**
 * Diff two snapshots (current vs previous) to show trend.
 */
export function diffSnapshots(
  currentFindings: Finding[],
  previousSnapshotId?: string
): DiffResult | null {
  if (!previousSnapshotId) return null;

  const prev = loadSnapshot(previousSnapshotId);
  if (!prev) return null;

  // Get findings from previous snapshot
  const prevFindings = prev.findingsByRule;
  const currFindings: Record<string, number> = {};
  for (const f of currentFindings) {
    currFindings[f.ruleId] = (currFindings[f.ruleId] || 0) + 1;
  }

  const added: Finding[] = [];
  const removed: Finding[] = [];

  // Rules that have new findings
  for (const [ruleId, count] of Object.entries(currFindings)) {
    const prevCount = prevFindings[ruleId] || 0;
    if (count > prevCount) {
      // Create placeholder findings
      for (let i = prevCount; i < count; i++) {
        added.push(currentFindings.find(f => f.ruleId === ruleId) || currentFindings[0]);
      }
    }
  }

  // Rules that had findings removed
  for (const [ruleId, count] of Object.entries(prevFindings)) {
    const currCount = currFindings[ruleId] || 0;
    if (count > currCount) {
      for (let i = currCount; i < count; i++) {
        removed.push({
          ruleId,
          title: `Removed: ${ruleId}`,
          severity: 'medium' as any,
          confidence: 'high' as any,
          message: `Previously reported finding for ${ruleId} is no longer detected`,
          file: '',
          line: 0,
          column: 0,
          snippet: '',
          recommendation: '',
          references: [],
          cwe: 'CWE-937' as any,
          owasp: 'A06:2021-Vulnerable Components' as any,
          falsePositiveRisk: 'medium',
        } as Finding);
      }
    }
  }

  return {
    added,
    removed,
    unchanged: Object.keys(currFindings).filter(k => prevFindings[k] === currFindings[k]).length,
    summary: `${added.length} new, ${removed.length} fixed, ${Object.keys(currFindings).length - added.length - removed.length} unchanged`,
  };
}

// ─── Smart File Selection (Git-Aware) ──────────────────────────────────

/**
 * Use git diff to determine which files to scan.
 * Focuses on the files most likely to have changed.
 */
export function getGitChangedFiles(
  baseRef: string = 'HEAD~1',
  extensions: string[] = []
): string[] {
  try {
    const { execSync } = require('child_process');
    const output = execSync(
      `git diff --name-only --diff-filter=ACMR ${baseRef} HEAD`,
      { encoding: 'utf-8', timeout: 10000 }
    );

    const files = output.split('\n').filter(Boolean);

    if (extensions.length > 0) {
      return (files as string[]).filter((f: string) => extensions.some((ext: string) => f.endsWith(ext)));
    }
    return files;
  } catch {
    return []; // Not a git repo or git not available
  }
}

/**
 * Get files changed in the working tree (uncommitted).
 */
export function getGitStagedFiles(extensions: string[] = []): string[] {
  try {
    const { execSync } = require('child_process');
    const output = execSync(
      'git diff --name-only --cached',
      { encoding: 'utf-8', timeout: 10000 }
    );

    const files = output.split('\n').filter(Boolean);

    if (extensions.length > 0) {
      return (files as string[]).filter((f: string) => extensions.some((ext: string) => f.endsWith(ext)));
    }
    return files;
  } catch {
    return [];
  }
}

// ─── Per-file finding storage ──────────────────────────────────────────

/**
 * Findings are stored per file rather than in the manifest.
 *
 * An incremental scan only re-analyses what changed, so the findings for
 * unchanged files have to come from somewhere — previously they came from
 * nowhere and those files silently reported clean. Keeping them in side files
 * means the manifest stays small enough to parse on every run, and only the
 * unchanged files actually needed get loaded.
 */
const FINDINGS_DIR = 'findings';

function findingsFileFor(normalizedPath: string): string {
  const key = crypto.createHash('sha256').update(normalizedPath).digest('hex').slice(0, 32);
  return path.join(cachePath(FINDINGS_DIR), `${key}.json`);
}

function saveFileFindings(normalizedPath: string, findings: Finding[]): void {
  const target = findingsFileFor(normalizedPath);
  try {
    if (findings.length === 0) {
      // Nothing to remember; drop any stale file rather than leaving old
      // findings that a later scan would resurrect.
      if (fs.existsSync(target)) fs.unlinkSync(target);
      return;
    }
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, JSON.stringify({ path: normalizedPath, findings }), 'utf-8');
  } catch {
    // A cache write failure must not fail the scan — worst case the file is
    // re-analysed next run.
  }
}

function loadFileFindings(normalizedPath: string): Finding[] | null {
  try {
    const raw = fs.readFileSync(findingsFileFor(normalizedPath), 'utf-8');
    const parsed = JSON.parse(raw);
    // Guard against a hash collision handing back another file's findings.
    if (parsed.path !== normalizedPath || !Array.isArray(parsed.findings)) return null;
    return parsed.findings as Finding[];
  } catch {
    return null;
  }
}

/**
 * Findings recorded for files that have not changed since the last scan.
 *
 * Returns which files could not be served from cache, so the caller can
 * re-scan them instead of silently reporting them clean.
 */
export function loadCachedFindings(
  unchangedFiles: string[]
): { findings: Finding[]; missing: string[] } {
  const findings: Finding[] = [];
  const missing: string[] = [];

  for (const file of unchangedFiles) {
    const normalized = file.replace(/\\/g, '/');
    const cached = loadFileFindings(normalized);
    if (cached === null) {
      // No side file. Either the file genuinely had no findings, or the entry
      // was lost. The manifest's count distinguishes the two.
      const entry = loadManifest().files[normalized];
      if (entry && entry.findingCount === 0) continue; // legitimately clean
      missing.push(file);
      continue;
    }
    findings.push(...cached);
  }

  return { findings, missing };
}

// ─── Cache Maintenance ─────────────────────────────────────────────────

/**
 * Update the cache after a scan.
 *
 * `findings` must contain only results for files that were actually analysed.
 * Unchanged files are deliberately left alone: they were not re-scanned, so
 * writing an entry for them would record zero findings and erase what the
 * previous scan learned.
 */
export function updateCache(
  scannedFiles: string[],
  findings: Finding[],
  changeSet: ChangeSet,
  configHash: string,
  rulesHash: string
): void {
  ensureCacheDir();
  const manifest = loadManifest();

  manifest.configHash = configHash;
  manifest.rulesHash = rulesHash;
  manifest.version = CACHE_VERSION;

  // Group findings by file once, rather than filtering the whole list per file.
  const byFile = new Map<string, Finding[]>();
  for (const f of findings) {
    const key = f.file.replace(/\\/g, '/');
    const bucket = byFile.get(key);
    if (bucket) bucket.push(f);
    else byFile.set(key, [f]);
  }

  const analysed = new Set([
    ...changeSet.added.map(f => f.replace(/\\/g, '/')),
    ...changeSet.modified.map(f => f.replace(/\\/g, '/')),
    ...scannedFiles.map(f => f.replace(/\\/g, '/')),
  ]);

  for (const file of analysed) {
    const fileFindings = byFile.get(file) || [];
    try {
      manifest.files[file] = updateFileEntry(file, fileFindings);
      saveFileFindings(file, fileFindings);
    } catch {
      // File vanished mid-scan — drop it rather than caching a broken entry.
      delete manifest.files[file];
    }
  }

  for (const file of changeSet.deleted) {
    const normalized = file.replace(/\\/g, '/');
    delete manifest.files[normalized];
    try {
      const target = findingsFileFor(normalized);
      if (fs.existsSync(target)) fs.unlinkSync(target);
    } catch { /* best effort */ }
  }

  manifest.fileCount = Object.keys(manifest.files).length;
  saveManifest(manifest);
}

/**
 * Clear entire cache.
 */
export function clearCache(): void {
  try {
    if (fs.existsSync(CACHE_DIR)) {
      fs.rmSync(CACHE_DIR, { recursive: true, force: true });
    }
  } catch {
    // Might fail if permissions issue — that's ok
  }
}

/**
 * Get cache statistics.
 */
export function cacheStats(): {
  totalFiles: number;
  totalSize: number;
  oldestEntry: number;
  newestEntry: number;
} {
  const manifest = loadManifest();
  let totalSize = 0;
  let oldestEntry = Date.now();
  let newestEntry = 0;

  for (const entry of Object.values(manifest.files)) {
    totalSize += entry.size;
    if (entry.lastScan < oldestEntry) oldestEntry = entry.lastScan;
    if (entry.lastScan > newestEntry) newestEntry = entry.lastScan;
  }

  return {
    totalFiles: manifest.fileCount,
    totalSize,
    oldestEntry: oldestEntry === Date.now() ? 0 : oldestEntry,
    newestEntry,
  };
}

// ─── Incremental Scan Orchestrator ─────────────────────────────────────
//
// There used to be a second, parallel incremental implementation here
// (`incrementalScan`). It was never wired to anything, and its merge step read
// `const allFindings = [...newFindings]` — i.e. it dropped the findings for
// unchanged files, exactly the bug that made `--incremental` under-report.
// Keeping a dead copy of a fixed bug invites someone to wire it back up, so it
// is gone. The live implementation is `scanAsync`'s incremental branch in
// src/scanner.ts, which merges via `loadCachedFindings` above.
