import { Finding, ScanResult } from '../types';

const C = {
  reset: '\x1b[0m', dim: '\x1b[2m', bold: '\x1b[1m',
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', cyan: '\x1b[36m', white: '\x1b[37m',
  bgRed: '\x1b[41m', bgGreen: '\x1b[42m', bgYellow: '\x1b[43m',
};

const SEV_COLOR: Record<string, string> = {
  critical: `\x1b[41m\x1b[37m`, high: '\x1b[31m', medium: '\x1b[33m', low: '\x1b[36m', info: '\x1b[37m',
};
const SEV_ICON: Record<string, string> = {
  critical: '◉', high: '▲', medium: '●', low: '○', info: '·',
};

function cvssBadge(score: number | undefined): string {
  if (!score) return '';
  if (score >= 9.0) return ` ${C.bgRed} CVSS:${score} ${C.reset}`;
  if (score >= 7.0) return ` ${C.red}CVSS:${score}${C.reset}`;
  if (score >= 4.0) return ` ${C.yellow}CVSS:${score}${C.reset}`;
  return ` CVSS:${score}`;
}

export function prettyFormat(result: ScanResult): string {
  const lines: string[] = [];
  const { filesScanned, findings, durationMs, summary } = result;

  lines.push('');
  lines.push(`${C.bold}${C.cyan}  ╔══════════════════════════════════════════════════════╗${C.reset}`);
  lines.push(`${C.bold}${C.cyan}  ║       Throughline — Advanced Security Analysis       ║${C.reset}`);
  lines.push(`${C.bold}${C.cyan}  ╚══════════════════════════════════════════════════════╝${C.reset}`);
  lines.push('');

  lines.push(`  ${C.bold}Files:${C.reset} ${filesScanned}   ${C.bold}Findings:${C.reset} ${findings.length}   ${C.bold}Time:${C.reset} ${(durationMs / 1000).toFixed(2)}s`);

  if (result.incremental) {
    const i = result.incremental;
    const parts = [`${i.analysed} re-analysed`, `${i.fromCache} from cache`];
    if (i.cacheMisses) parts.push(`${i.cacheMisses} cache misses re-scanned`);
    if (i.deleted) parts.push(`${i.deleted} deleted`);
    lines.push(`  ${C.dim}Incremental: ${parts.join(', ')}${C.reset}`);
  }

  // Suppression is never silent — a hidden finding must still be counted.
  if (result.triage) {
    const parts: string[] = [];
    if (result.triage.suppressed) parts.push(`${result.triage.suppressed} hidden as reviewed false positives`);
    if (result.triage.severityAdjusted) parts.push(`${result.triage.severityAdjusted} severity-adjusted by review`);
    if (result.triage.stale) parts.push(`${result.triage.stale} verdicts stale (code changed since review)`);
    if (parts.length > 0) {
      lines.push(`  ${C.dim}Triage: ${parts.join(', ')} — use --no-triage to show all${C.reset}`);
    }
  }
  lines.push('');

  if (findings.length === 0) {
    lines.push(`  ${C.bgGreen} PASS ${C.reset} ${C.green}No vulnerabilities detected.${C.reset}`);
    lines.push('');
    return lines.join('\n');
  }

  // ─── Executive Summary ───
  lines.push(`  ${C.bold}╭── Executive Summary ──────────────────────────╮${C.reset}`);
  for (const [sev, count] of Object.entries(summary.bySeverity)) {
    if (count > 0) {
      const pct = ((count / findings.length) * 100).toFixed(0);
      const bar = '█'.repeat(Math.min(30, Math.round((count / findings.length) * 30)));
      lines.push(`  │  ${SEV_COLOR[sev]}${sev.toUpperCase().padEnd(8)}${C.reset} ${String(count).padStart(4)} ${C.dim}${(pct + '%').padStart(4)} ${bar}${C.reset} │`);
    }
  }
  lines.push(`  ╰──────────────────────────────────────────────╯`);
  lines.push('');

  // ─── FP Estimate ───
  const { falsePositiveEstimate: fp } = summary;
  if (fp.low > 0 || fp.high > 0) {
    lines.push(`  ${C.dim}Confidence: ${C.green}${fp.low} high-certainty${C.reset} ${C.dim}| ${C.yellow}${fp.medium} medium${C.reset} ${C.dim}| ${fp.high} low${C.reset}`);
    lines.push('');
  }

  // ─── Detailed Findings ───
  let currentFile = '';
  let fileCount = 0;

  for (const f of findings) {
    if (f.file !== currentFile) {
      currentFile = f.file;
      fileCount++;
      const shortPath = currentFile.length > 70
        ? '...' + currentFile.slice(-67)
        : currentFile;
      lines.push(`  ${C.bold}${C.cyan}📄 ${fileCount}. ${shortPath}${C.reset}`);
    }

    const sevIcon = SEV_ICON[f.severity] || '?';
    const confTag = f.confidence === 'certain' ? `${C.green}[CERTAIN]${C.reset} ` :
                    f.confidence === 'high' ? '' :
                    f.confidence === 'medium' ? `${C.yellow}[MEDIUM CONFIDENCE]${C.reset} ` :
                    `${C.dim}[LOW CONFIDENCE]${C.reset} `;

    const cvss = cvssBadge(f.cvss?.baseScore);

    lines.push(`    ${SEV_COLOR[f.severity]}${sevIcon} [${f.ruleId}]${C.reset}${cvss} line ${f.line}: ${confTag}${f.message}`);

    // Snippet
    const trimmed = f.snippet.substring(0, 120);
    lines.push(`      ${C.dim}${trimmed}${C.reset}`);

    // CWE & OWASP
    lines.push(`      ${C.dim}${f.cwe} | ${f.owasp}${C.reset}`);

    // Fix example if available
    if (f.fixExample) {
      lines.push(`      ${C.green}▶ Fix:${C.reset}`);
      for (const fl of f.fixExample.split('\n')) {
        lines.push(`        ${C.green}${fl}${C.reset}`);
      }
    } else if (f.recommendation) {
      lines.push(`      ${C.green}→ ${f.recommendation}${C.reset}`);
    }

    lines.push('');
  }

  // ─── OWASP Top 10 Coverage ───
  if (Object.keys(summary.byOwasp).length > 0) {
    lines.push(`  ${C.bold}╭── OWASP Top 10 Coverage ─────────────────────╮${C.reset}`);
    const owaspEntries = Object.entries(summary.byOwasp).sort((a, b) => b[1] - a[1]);
    for (const [owasp, count] of owaspEntries) {
      const shortOwasp = owasp.length > 45 ? owasp.substring(0, 45) + '...' : owasp;
      lines.push(`  │  ${C.yellow}${shortOwasp.padEnd(47)}${C.reset} ${count} │`);
    }
    lines.push(`  ╰──────────────────────────────────────────────╯`);
    lines.push('');
  }

  return lines.join('\n');
}
