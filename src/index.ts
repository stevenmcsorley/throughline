#!/usr/bin/env node

import { scan, scanAsync } from './scanner';
import { prettyFormat } from './formatters/pretty';
import { jsonFormat, sarifFormat } from './formatters/json';
import { htmlFormat } from './formatters/html';
import { getRuleSummary } from './rules';
import { cacheStats } from './engine/incremental';
import { FileWatcher } from './engine/watcher';
import {
  getGitDiffFiles, getGitDiffStat, diffFindings, formatDiffResult,
  isGitRepository, resolveRef, materializeRef, relativizeFindings,
} from './engine/semantic-diff';
import { loadUserRules, generateExampleRules } from './engine/rule-loader';
import * as path from 'path';
import * as fs from 'fs';

function printHelp(): void {
  console.log(`
Throughline — Advanced Static Security Vulnerability Scanner
============================================================

Usage: throughline [options] <paths...>

Options:
  -f, --format <type>     Output format (default: pretty)
                          ─ pretty    Colorized terminal output
                          ─ json      Machine-readable JSON
                          ─ sarif     SARIF 2.1.0 (GitHub/GitLab compatible)
                          ─ html      Interactive HTML report

  -o, --output <file>     Write output to file (default: stdout)

  -r, --rules <ids>       Comma-separated rule IDs to run (default: all)
  -s, --severity <level>  Minimum severity: critical, high, medium, low, info
  -c, --confidence <lvl>  Minimum confidence: certain, high, medium, low
  -e, --extensions <exts> Comma-separated extensions to scan (.js,.ts,.py)
  -x, --exclude <dirs>    Extra directories to exclude (comma-separated)
  --max-size <bytes>      Max file size to scan (default: 10MB)

  --no-entropy            Disable entropy-based secrets detection
  --no-deps               Disable dependency CVE scanning
  --incremental           Only scan changed files (uses .throughline-cache)
  --clear-cache           Clear incremental cache before scanning
  --git-aware             Only scan files changed in git (HEAD~1..HEAD)
  --git-base <ref>        Git base ref for diff (default: HEAD~1)
  --cache-stats           Show incremental cache statistics

  --watch                 Watch files for changes and re-scan continuously
  --diff <refs>           Semantic diff: show vulns introduced/resolved between refs
                          e.g. --diff HEAD~5..HEAD or --diff main..feature
  --init-rules            Generate example custom rules in .throughline-rules/

  --no-triage             Show findings previously reviewed as false positives
  --triage-stats          Show stored AI/human triage verdicts

  --mcp                   Run as an MCP server on stdio, so an AI (Claude,
                          Cursor, …) can drive the scanner and triage findings.
                          See docs/MCP.md for client setup.

  --list-rules            List all available rules and exit
  --rule-summary          Show rule coverage summary
  -h, --help              Show this help

Examples:
  throughline .                                    Scan current directory
  throughline -s high -f json -o report.json src/  JSON report for high+ findings
  throughline -r sql-injection,xss,ssrf ./app       Specific rules only
  throughline -f html -o report.html ./src          Interactive HTML report
  throughline -f sarif -s medium . > results.sarif   For GitHub Code Scanning

CI/CD Integration:
  throughline -f sarif -s medium . > throughline-results.sarif
  # Exit code 1 when findings found — fails pipeline automatically
`);
}

function printRules(): void {
  const { allRules } = require('./rules');
  // Custom rules from .throughline-rules/ are part of the active rule set, so
  // they belong in the listing — omitting them made `--list-rules` disagree
  // with what a scan actually runs.
  const userRules = loadUserRules();
  const userIds = new Set(userRules.map((r: any) => r.id));
  const bySev: Record<string, any[]> = {};
  for (const rule of [...allRules, ...userRules]) {
    if (!bySev[rule.severity]) bySev[rule.severity] = [];
    bySev[rule.severity].push(rule);
  }

  const order = ['critical', 'high', 'medium', 'low', 'info'];
  console.log('\nThroughline Rules');
  console.log('═'.repeat(90));

  for (const sev of order) {
    const rules = bySev[sev];
    if (!rules) continue;
    for (const rule of rules) {
      const sevLabel = sev.toUpperCase().padEnd(8);
      const mitigation = rule.mitreAttack ? `${rule.mitreAttack.tactic}/${rule.mitreAttack.technique}` : '';
      const origin = userIds.has(rule.id) ? ' [custom]' : '';
      console.log(`  ${sevLabel} ${rule.id.padEnd(30)} ${rule.cwe.padEnd(12)} ${rule.owasp.substring(0, 25).padEnd(25)} ${mitigation}${origin}`);
    }
  }
  if (userRules.length > 0) {
    console.log(`\n  ${userRules.length} custom rule(s) loaded from .throughline-rules/`);
  }
  console.log('');
}

function printRuleSummary(): void {
  const summary = getRuleSummary();
  console.log('\nThroughline — Rule Coverage Summary');
  console.log('═'.repeat(50));
  console.log(`  Total rules:       ${summary.totalRules}`);
  console.log(`  Unique CWEs:       ${summary.cwes.length}`);
  console.log(`  Languages covered:  ${summary.languages.length}`);
  console.log('\n  By severity:');
  for (const [sev, rules] of Object.entries(summary.bySeverity)) {
    const ruleList = (rules as string[]).join(', ');
    console.log(`    ${sev.toUpperCase().padEnd(8)} ${(rules as string[]).length} rules: ${ruleList}`);
  }
  console.log('');
}

function parseArgs(argv: string[]): { options: Record<string, string>; paths: string[] } {
  const options: Record<string, string> = {};
  const paths: string[] = [];
  let i = 0;
  while (i < argv.length) {
    const arg = argv[i];
    switch (arg) {
      case '-f': case '--format': options.format = argv[++i]; break;
      case '-o': case '--output': options.output = argv[++i]; break;
      case '-r': case '--rules': options.rules = argv[++i]; break;
      case '-s': case '--severity': options.severity = argv[++i]; break;
      case '-c': case '--confidence': options.confidence = argv[++i]; break;
      case '-e': case '--extensions': options.extensions = argv[++i]; break;
      case '-x': case '--exclude': options.exclude = argv[++i]; break;
      case '--max-size': options.maxSize = argv[++i]; break;
      case '--no-entropy': options.noEntropy = 'true'; break;
      case '--no-deps': options.noDeps = 'true'; break;
      case '--incremental': options.incremental = 'true'; break;
      case '--clear-cache': options.clearCache = 'true'; break;
      case '--git-aware': options.gitAware = 'true'; break;
      case '--git-base': options.gitBase = argv[++i]; break;
      case '--cache-stats': options.cacheStats = 'true'; break;
      case '--watch': options.watch = 'true'; break;
      case '--diff': options.diff = argv[++i]; break;
      case '--init-rules': options.initRules = 'true'; break;
      case '--no-triage': options.noTriage = 'true'; break;
      case '--triage-stats': options.triageStats = 'true'; break;
      case '--mcp': options.mcp = 'true'; break;
      case '--list-rules': options.listRules = 'true'; break;
      case '--rule-summary': options.ruleSummary = 'true'; break;
      case '-h': case '--help': options.help = 'true'; break;
      default:
        if (!arg.startsWith('-')) paths.push(arg);
        break;
    }
    i++;
  }
  return { options, paths };
}

// ─── Watch Mode ────────────────────────────────────────────────────────

async function handleWatchMode(options: Record<string, string>, paths: string[]): Promise<void> {
  const scanPaths = paths.length > 0 ? paths : ['.'];
  console.log('\nThroughline — Watch Mode');
  console.log('═'.repeat(50));
  console.log(`Watching: ${scanPaths.join(', ')}`);
  console.log('Press Ctrl+C to stop\n');

  const watcher = new FileWatcher({
    paths: scanPaths,
    debounceMs: 300,
    clearScreen: true,
    onReady: () => console.log('[throughline] Watcher ready, waiting for changes...\n'),
    onScan: () => {},
  });

  const executeAndWatch = async () => {
    const scanOptions: any = {
      paths: scanPaths,
      rules: options.rules ? options.rules.split(',').map((r: string) => r.trim()).filter(Boolean) : undefined,
      severity: options.severity as any,
      confidence: options.confidence as any,
      extensions: options.extensions ? options.extensions.split(',').map((e: string) => e.trim()).filter(Boolean) : undefined,
      exclude: options.exclude ? options.exclude.split(',').map((e: string) => e.trim()).filter(Boolean) : undefined,
      maxFileSize: options.maxSize ? parseInt(options.maxSize) : undefined,
      entropy: options.noEntropy ? false : true,
      deps: false,
    };

    await watcher.start(async (changedFiles: string[]) => {
      const opts = { ...scanOptions, paths: changedFiles };
      return await scanAsync(opts);
    });
  };

  await executeAndWatch();
}

// ─── Diff Mode ─────────────────────────────────────────────────────────

/**
 * Semantic diff: scan the base ref and the target ref for real, then compare.
 *
 * The base revision is materialised into a temp directory with `git archive`,
 * so nothing touches the working copy, the index, or HEAD. Both sides are
 * scanned with identical options and their paths normalised to repo-relative
 * form before matching, or the comparison would be meaningless.
 */
function handleDiffMode(options: Record<string, string>, paths: string[]): void {
  const parts = options.diff.split('..');
  const baseRef = parts[0] || 'HEAD~1';
  const targetRef = parts[1] || 'HEAD';

  console.log(`\nThroughline — Semantic Diff: ${baseRef} → ${targetRef}`);
  console.log('═'.repeat(50));

  if (!isGitRepository()) {
    console.error('\nError: --diff needs a git repository. Not inside one.\n');
    process.exit(2);
  }
  for (const ref of [baseRef, targetRef]) {
    if (!resolveRef(ref)) {
      console.error(`\nError: git ref "${ref}" does not resolve to a commit.\n`);
      process.exit(2);
    }
  }

  const changedFiles = getGitDiffFiles(baseRef, targetRef);
  if (changedFiles.length === 0) {
    console.log('No files changed between these refs.\n');
    process.exit(0);
  }
  console.log(`\nChanged files (${changedFiles.length}):`);
  console.log(getGitDiffStat(baseRef, targetRef));

  const scanPaths = paths.length > 0 ? paths : ['.'];
  const shared = {
    rules: options.rules ? options.rules.split(',').map((r: string) => r.trim()).filter(Boolean) : undefined,
    severity: options.severity as any,
    confidence: options.confidence as any,
    extensions: options.extensions ? options.extensions.split(',').map((e: string) => e.trim()).filter(Boolean) : undefined,
    exclude: options.exclude ? options.exclude.split(',').map((e: string) => e.trim()).filter(Boolean) : undefined,
    maxFileSize: options.maxSize ? parseInt(options.maxSize) : undefined,
    entropy: false,
    deps: false,
    // Triage verdicts are keyed to current paths; applying them to a historical
    // checkout would skew the "before" side.
    applyTriage: false,
  };

  let base: { dir: string; cleanup: () => void } | null = null;
  const cleanup = () => {
    if (base) { base.cleanup(); base = null; }
  };

  (async () => {
    console.log(`Scanning ${targetRef} (working tree)...`);
    const afterResult = await scanAsync({ ...shared, paths: scanPaths });
    const after = relativizeFindings(afterResult.findings, process.cwd());

    console.log(`Checking out and scanning ${baseRef}...`);
    base = materializeRef(baseRef);
    // Map the requested paths into the historical checkout; skip any that did
    // not exist at that revision.
    const basePaths = scanPaths
      .map(p => path.join(base!.dir, path.relative(process.cwd(), path.resolve(p)) || '.'))
      .filter(p => fs.existsSync(p));

    const before = basePaths.length > 0
      ? relativizeFindings((await scanAsync({ ...shared, paths: basePaths })).findings, base.dir)
      : [];

    console.log('Computing diff...\n');
    const diff = diffFindings(before, after);
    console.log(formatDiffResult(diff, baseRef, targetRef));
    return diff;
  })()
    .then(diff => {
      cleanup();
      // Non-zero only for newly introduced issues — pre-existing ones are not
      // this change's fault and must not fail the build.
      process.exit(diff.introduced.length > 0 ? 1 : 0);
    })
    .catch((err: Error) => {
      cleanup();
      console.error('Diff failed:', err.message);
      process.exit(2);
    });
}

function printTriageStats(): void {
  const { loadTriageStore, triageStats } = require('./engine/triage');
  const store = loadTriageStore();
  const stats = triageStats(store);
  console.log('\nThroughline Triage Verdicts');
  console.log('═'.repeat(50));
  console.log(`  Total reviewed:    ${stats.total}`);
  console.log(`  Confirmed real:    ${stats.confirmedReal}`);
  console.log(`  False positives:   ${stats.falsePositives}  (hidden unless --no-triage)`);
  console.log(`  With fixes:        ${stats.withFixes}`);
  if (stats.total === 0) {
    console.log('\n  Nothing reviewed yet. Connect an AI via "throughline --mcp" (see docs/MCP.md)');
    console.log('  and ask it to triage — verdicts are stored in .throughline-cache/triage.json');
  }
  console.log('');
}

function main(): void {
  const { options, paths } = parseArgs(process.argv.slice(2));

  // MCP mode owns stdout for protocol frames — hand over before anything prints.
  if (options.mcp) {
    const { startStdioServer } = require('./mcp/server');
    startStdioServer().catch((err: Error) => {
      console.error('[throughline-mcp] fatal:', err.message);
      process.exit(1);
    });
    return;
  }

  if (options.help) { printHelp(); process.exit(0); }
  if (options.triageStats) { printTriageStats(); process.exit(0); }
  if (options.listRules) { printRules(); process.exit(0); }
  if (options.ruleSummary) { printRuleSummary(); process.exit(0); }

  // Init rules
  if (options.initRules) {
    const created = generateExampleRules();
    if (created.length > 0) {
      console.log('\nGenerated example custom rules:');
      for (const file of created) {
        console.log(`  ${file}`);
      }
      console.log('\nEdit these files and re-run the scanner. Custom rules load automatically.\n');
    } else {
      console.log('\nExample rules already exist in .throughline-rules/\n');
    }
    process.exit(0);
  }

  // Diff mode: scan before/after and compare
  if (options.diff) {
    handleDiffMode(options, paths);
    return;
  }

  // Watch mode: continuous scanning
  if (options.watch) {
    handleWatchMode(options, paths);
    return;
  }

  // Show cache stats
  if (options.cacheStats) {
    const stats = cacheStats();
    console.log('\nThroughline Incremental Cache');
    console.log('═'.repeat(50));
    console.log(`  Cached files:  ${stats.totalFiles}`);
    console.log(`  Total size:    ${(stats.totalSize / 1024 / 1024).toFixed(2)} MB`);
    if (stats.oldestEntry) console.log(`  Oldest entry:  ${new Date(stats.oldestEntry).toLocaleString()}`);
    if (stats.newestEntry) console.log(`  Newest entry:  ${new Date(stats.newestEntry).toLocaleString()}`);
    console.log('');
    process.exit(0);
  }

  if (paths.length === 0) {
    console.error('Error: No paths specified. Use "." to scan current directory.');
    console.error('Run "throughline --help" for usage.');
    process.exit(1);
  }

  const scanOptions: any = {
    paths,
    rules: options.rules ? options.rules.split(',').map((r: string) => r.trim()).filter(Boolean) : undefined,
    severity: options.severity as any,
    confidence: options.confidence as any,
    extensions: options.extensions ? options.extensions.split(',').map((e: string) => e.trim()).filter(Boolean) : undefined,
    exclude: options.exclude ? options.exclude.split(',').map((e: string) => e.trim()).filter(Boolean) : undefined,
    maxFileSize: options.maxSize ? parseInt(options.maxSize) : undefined,
    entropy: options.noEntropy ? false : true,
    deps: options.noDeps ? false : true,
    incremental: options.incremental ? true : false,
    clearCache: options.clearCache ? true : false,
    gitAware: options.gitAware ? true : false,
    gitBaseRef: options.gitBase || 'HEAD~1',
    applyTriage: options.noTriage ? false : true,
  };

  // Use async scan (includes dep CVE + incremental)
  scanAsync(scanOptions).then(result => {
    const format = options.format || 'pretty';

    let output: string;
    switch (format) {
      case 'json': output = jsonFormat(result); break;
      case 'sarif': output = sarifFormat(result); break;
      case 'html': output = htmlFormat(result); break;
      case 'pretty': default: output = prettyFormat(result); break;
    }

    if (options.output) {
      const outPath = path.resolve(options.output);
      fs.writeFileSync(outPath, output, 'utf-8');
      console.log(`Report written to ${outPath}`);
    } else {
      console.log(output);
    }

    process.exit(result.findings.length > 0 ? 1 : 0);
  }).catch(err => {
    console.error('Scan failed:', err.message);
    process.exit(2);
  });
}

main();
