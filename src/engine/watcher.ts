/**
 * File Watcher Mode — Continuous Security Scanning
 *
 * Watches source files and re-scans on every change.
 * Like a security-focused linter that runs in the background.
 *
 * Usage:
 *   vulnscan --watch ./src
 *   vulnscan --watch ./src -s critical   # Only alert on critical
 *
 * Features:
 *   - Debounced re-scanning (300ms default)
 *   - Only re-scans changed files + CPG re-analysis
 *   - Shows delta: new findings since last scan
 *   - Colored terminal output with change indicators
 *   - Optionally beeps/sends notification on new critical finding
 */

import * as fs from 'fs';
import * as path from 'path';
import { Finding, ScanResult } from '../types';
import { prettyFormat } from '../formatters/pretty';

interface WatchOptions {
  /** Paths to watch */
  paths: string[];
  /** Minimum severity to report */
  severity?: string;
  /** Debounce time in ms (default: 300) */
  debounceMs: number;
  /** Whether to clear screen on each scan */
  clearScreen: boolean;
  /** Callback for each scan result */
  onScan: (result: ScanResult) => void;
  /** Callback when watcher is ready */
  onReady: () => void;
}

const DEFAULT_WATCH_OPTIONS: WatchOptions = {
  paths: [],
  debounceMs: 300,
  clearScreen: true,
  onScan: () => {},
  onReady: () => {},
};

// ─── File Watcher ──────────────────────────────────────────────────────

export class FileWatcher {
  private options: WatchOptions;
  private watcher: any = null;
  private scanFn: ((files: string[]) => Promise<ScanResult>) | null = null;
  private lastFindings: Finding[] = [];
  private pendingScan: NodeJS.Timeout | null = null;
  private changedFiles: Set<string> = new Set();
  private scanCount: number = 0;
  private running: boolean = false;

  constructor(options: Partial<WatchOptions> = {}) {
    this.options = { ...DEFAULT_WATCH_OPTIONS, ...options };
  }

  /**
   * Start watching. Requires a scan function that takes file paths
   * and returns a ScanResult.
   */
  async start(scanFn: (files: string[]) => Promise<ScanResult>): Promise<void> {
    this.scanFn = scanFn;
    this.running = true;

    // Require chokidar dynamically (optional dependency)
    let chokidar: any;
    try {
      chokidar = require('chokidar');
    } catch {
      console.error('Watch mode requires chokidar. Install with:');
      console.error('  npm install chokidar');
      console.error('\nFalling back to polling mode using fs.watch...');
      this.startPolling();
      return;
    }

    // Watch directories directly, not globs: chokidar 4 dropped glob support and
    // would treat "dir/**/*.{js,ts}" as a literal path that never exists, so the
    // watcher would silently observe nothing. Extension filtering happens in
    // onChange() instead, which also keeps the two lists from drifting apart.
    const targets = this.options.paths.map(p => path.resolve(p));

    this.watcher = chokidar.watch(targets, {
      ignored: [
        /(^|[/\\])\./,
        /node_modules/,
        /\.git/,
        /dist/,
        /build/,
        /__pycache__/,
        /vendor/,
        /\.vulnscan-cache/,
        /\.min\./,
        /\.bundle\./,
        /coverage/,
      ],
      persistent: true,
      ignoreInitial: true,
      awaitWriteFinish: {
        stabilityThreshold: 200,
        pollInterval: 50,
      },
    });

    this.watcher
      .on('add', (file: string) => this.onChange(file))
      .on('change', (file: string) => this.onChange(file))
      .on('unlink', (file: string) => this.onChange(file))
      .on('ready', () => {
        this.options.onReady();
        // Do initial scan
        this.scheduleScan();
      })
      .on('error', (err: Error) => {
        console.error('[vulnscan] Watcher error:', err.message);
      });
  }

  /**
   * Stop the watcher.
   */
  async stop(): Promise<void> {
    this.running = false;
    if (this.pendingScan) {
      clearTimeout(this.pendingScan);
      this.pendingScan = null;
    }
    if (this.watcher) {
      await this.watcher.close();
      this.watcher = null;
    }
  }

  /**
   * Get scan statistics.
   */
  stats(): { scanCount: number; lastFindings: number; watching: boolean } {
    return {
      scanCount: this.scanCount,
      lastFindings: this.lastFindings.length,
      watching: this.running,
    };
  }

  // ─── Internals ──────────────────────────────────────────────────────

  private onChange(file: string): void {
    // Filter by extension
    const validExts = ['.js', '.ts', '.jsx', '.tsx', '.py', '.pyw', '.go', '.php',
      '.rb', '.java', '.cs', '.swift', '.kt', '.kts', '.sql', '.yaml', '.yml',
      '.json', '.tf', '.hcl', '.sh', '.bash', '.pl', '.pm', '.r', '.lua', '.dart',
      '.rs', '.scala', '.c', '.cpp', '.h', '.hpp', '.m', '.mm'];

    const ext = path.extname(file).toLowerCase();
    const basename = path.basename(file).toLowerCase();
    const isValid = validExts.includes(ext) ||
      basename === 'dockerfile' ||
      basename === 'makefile' ||
      basename.endsWith('rc');

    if (!isValid) return;

    this.changedFiles.add(file);
    this.scheduleScan();
  }

  private scheduleScan(): void {
    if (!this.running) return;

    if (this.pendingScan) {
      clearTimeout(this.pendingScan);
    }

    this.pendingScan = setTimeout(() => {
      this.pendingScan = null;
      this.runScan();
    }, this.options.debounceMs);
  }

  private async runScan(): Promise<void> {
    if (!this.scanFn || this.changedFiles.size === 0) return;

    const files = Array.from(this.changedFiles);
    this.changedFiles.clear();
    this.scanCount++;

    try {
      const result = await this.scanFn(files);

      // Clear screen for fresh output
      if (this.options.clearScreen) {
        process.stdout.write('\x1b[2J\x1b[H');
      }

      // Show scan header
      const now = new Date().toLocaleTimeString();
      console.log(`\n${'─'.repeat(60)}`);
      console.log(`  VulnScan Watch — ${now} — Scan #${this.scanCount}`);
      console.log(`  Files: ${result.filesScanned}  |  Findings: ${result.findings.length}`);
      console.log(`${'─'.repeat(60)}`);

      // Show delta from last scan
      if (this.lastFindings.length > 0 && result.findings.length > 0) {
        this.showDelta(this.lastFindings, result.findings);
      } else if (result.findings.length > 0) {
        console.log(prettyFormat(result));
      } else {
        console.log('\n  \x1b[32m✓ No vulnerabilities detected.\x1b[0m');
      }

      console.log(`\n  Watching ${this.options.paths.join(', ')}... (Ctrl+C to stop)\n`);

      this.lastFindings = result.findings;
      this.options.onScan(result);
    } catch (err: any) {
      console.error('[vulnscan] Scan error:', err.message);
    }
  }

  private showDelta(prev: Finding[], curr: Finding[]): void {
    const prevKeys = new Set(prev.map(f => `${f.file}:${f.line}:${f.ruleId}`));
    const currKeys = new Set(curr.map(f => `${f.file}:${f.line}:${f.ruleId}`));

    const newFindings = curr.filter(f => !prevKeys.has(`${f.file}:${f.line}:${f.ruleId}`));
    const resolvedFindings = prev.filter(f => !currKeys.has(`${f.file}:${f.line}:${f.ruleId}`));
    const unchanged = curr.filter(f => prevKeys.has(`${f.file}:${f.line}:${f.ruleId}`));

    if (newFindings.length > 0) {
      console.log(`\n  \x1b[31m▲ ${newFindings.length} NEW FINDINGS\x1b[0m`);
      const criticalNew = newFindings.filter(f => f.severity === 'critical');
      for (const f of criticalNew.slice(0, 3)) {
        console.log(`    \x1b[41m  CRITICAL  \x1b[0m ${f.file}:${f.line} — ${f.title}`);
      }
      for (const f of newFindings.filter(f => f.severity === 'high').slice(0, 3)) {
        console.log(`    \x1b[31m  HIGH      \x1b[0m ${f.file}:${f.line} — ${f.title}`);
      }
      const remaining = newFindings.length - criticalNew.length - 3;
      if (remaining > 0) {
        console.log(`    ... and ${remaining} more`);
      }
    }

    if (resolvedFindings.length > 0) {
      console.log(`\n  \x1b[32m▼ ${resolvedFindings.length} RESOLVED\x1b[0m`);
      for (const f of resolvedFindings.slice(0, 3)) {
        console.log(`    \x1b[32m  ✓          \x1b[0m ${f.file}:${f.line} — ${f.title}`);
      }
      if (resolvedFindings.length > 3) {
        console.log(`    ... and ${resolvedFindings.length - 3} more`);
      }
    }

    if (unchanged.length > 0) {
      console.log(`\n  • ${unchanged.length} unchanged findings`);
    }

    // Show full details for new high/critical findings
    if (newFindings.length > 0 && newFindings.length <= 5) {
      console.log(`\n${'─'.repeat(60)}`);
      console.log(prettyFormat({ ...createEmptyResult(), findings: newFindings }));
    }
  }

  private startPolling(): void {
    // Fallback: poll using fs.watch on directories
    console.log('[vulnscan] Using polling fallback (check every 2 seconds)');
    console.log('[vulnscan] Press Ctrl+C to stop\n');

    // Do initial scan
    this.scanCount++;
    const checkAndScan = async () => {
      if (!this.running) return;
      this.changedFiles.add(this.options.paths[0]);
      await this.runScan();
      if (this.running) {
        setTimeout(checkAndScan, 2000);
      }
    };
    checkAndScan();
    this.options.onReady();
  }
}

function createEmptyResult(): ScanResult {
  return {
    filesScanned: 0,
    findings: [],
    durationMs: 0,
    summary: {
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      byConfidence: { certain: 0, high: 0, medium: 0, low: 0 },
      byOwasp: {},
      byCwe: {},
      totalFindings: 0,
      falsePositiveEstimate: { low: 0, medium: 0, high: 0 },
    },
  };
}
