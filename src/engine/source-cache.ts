/**
 * Source Cache
 *
 * Every analysis phase reads the files it analyses, and there are five of them:
 * pattern/AST scanning, the call graph, the JS/TS CPG builder, the multi-language
 * CPG builder, and entropy scanning. The call graph read the same file once per
 * function it contained. On a large repository the same bytes were pulled off
 * disk and decoded from UTF-8 several times over.
 *
 * This caches file contents for the duration of one scan. Files cannot change
 * mid-scan, so within a session the cache is always correct; between sessions it
 * is dropped, which is what makes watch mode see edits.
 *
 * The cache is bounded. An unbounded one would hold an entire monorepo in memory
 * — the point is to avoid repeat reads, not to buy speed with unbounded RSS.
 * Past the budget, reads still succeed; they just go to disk.
 */

import * as fs from 'fs';

/** Default ceiling on cached source, in bytes. */
const DEFAULT_BUDGET = 192 * 1024 * 1024;

interface Session {
  contents: Map<string, string>;
  /** Split-lines memo — most callers want lines, and splitting is not free. */
  lines: Map<string, string[]>;
  bytes: number;
  budget: number;
  hits: number;
  misses: number;
  skipped: number;
}

let session: Session | null = null;

export function beginScanSession(budgetBytes?: number): void {
  const envBudget = Number(process.env.THROUGHLINE_SOURCE_CACHE_BYTES);
  session = {
    contents: new Map(),
    lines: new Map(),
    bytes: 0,
    budget: budgetBytes ?? (Number.isFinite(envBudget) && envBudget > 0 ? envBudget : DEFAULT_BUDGET),
    hits: 0,
    misses: 0,
    skipped: 0,
  };
}

export function endScanSession(): void {
  session = null;
}

/**
 * Read a source file, serving it from the session cache when possible.
 * Throws exactly as `fs.readFileSync` does, so callers keep their existing
 * error handling for unreadable or binary files.
 */
export function readSource(file: string): string {
  if (!session) return fs.readFileSync(file, 'utf-8');

  const cached = session.contents.get(file);
  if (cached !== undefined) {
    session.hits++;
    return cached;
  }

  const content = fs.readFileSync(file, 'utf-8');
  session.misses++;

  const size = Buffer.byteLength(content, 'utf8');
  if (session.bytes + size <= session.budget) {
    session.contents.set(file, content);
    session.bytes += size;
  } else {
    session.skipped++;
  }
  return content;
}

/** Read a source file split into lines, memoised alongside the content. */
export function readSourceLines(file: string): string[] {
  if (!session) return fs.readFileSync(file, 'utf-8').split('\n');

  const cached = session.lines.get(file);
  if (cached !== undefined) return cached;

  const split = readSource(file).split('\n');
  // Only memoise the split if the content itself was worth caching.
  if (session.contents.has(file)) session.lines.set(file, split);
  return split;
}

export function sourceCacheStats(): { hits: number; misses: number; skipped: number; bytes: number } | null {
  if (!session) return null;
  const { hits, misses, skipped, bytes } = session;
  return { hits, misses, skipped, bytes };
}
