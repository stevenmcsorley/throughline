import { ScanResult } from '../types';
import * as pathMod from 'path';

export function jsonFormat(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

/**
 * SARIF wants repository-relative URIs. An absolute path (`F:/proj/src/a.ts`)
 * is both an invalid URI reference and unusable to GitHub Code Scanning, which
 * maps results onto the repo tree — annotations silently never appear on the PR.
 * Paths outside the scan root keep their absolute form rather than being
 * mangled into a wrong relative one.
 */
function sarifUri(file: string, root: string): string {
  const abs = pathMod.resolve(file);
  const rel = pathMod.relative(root, abs);
  if (!rel || rel.startsWith('..') || pathMod.isAbsolute(rel)) {
    return abs.replace(/\\/g, '/');
  }
  return rel.replace(/\\/g, '/');
}

export function sarifFormat(result: ScanResult): string {
  const rules = new Map<string, any>();
  const results: any[] = [];
  const root = process.cwd();

  // Fingerprints let GitHub track a finding across runs. Counting occurrences
  // per (rule, file, snippet) keeps duplicates distinct without depending on
  // position in the results array — which used to be part of the fingerprint,
  // so inserting one finding renumbered every later one and GitHub treated the
  // whole set as newly introduced.
  const occurrence = new Map<string, number>();

  for (let i = 0; i < result.findings.length; i++) {
    const f = result.findings[i];
    if (!rules.has(f.ruleId)) {
      rules.set(f.ruleId, {
        id: f.ruleId,
        name: f.title,
        shortDescription: { text: f.message },
        fullDescription: { text: f.message },
        help: {
          text: f.recommendation,
          markdown: `**Recommendation:** ${f.recommendation}\n\n**CWE:** ${f.cwe}\n**OWASP:** ${f.owasp}${f.fixExample ? `\n\n\`\`\`\n${f.fixExample}\n\`\`\`` : ''}`,
        },
        properties: {
          'security-severity': cvssToGitHubSeverity(f.cvss?.baseScore),
          tags: ['security', f.severity, ...f.cwe.split(',')],
          precision: f.confidence === 'certain' ? 'very-high' : f.confidence,
        },
      });
    }

    results.push({
      ruleId: f.ruleId,
      ruleIndex: [...rules.keys()].indexOf(f.ruleId),
      level: severityToSarif(f.severity),
      message: {
        text: `[${f.severity.toUpperCase()}] ${f.message}`,
      },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: sarifUri(f.file, root), uriBaseId: '%SRCROOT%' },
          region: {
            // SARIF requires 1-based line and column. Engine findings report
            // column 0 when they have no column information, which is invalid.
            startLine: Math.max(1, f.line),
            startColumn: Math.max(1, f.column),
            ...(f.endLine ? { endLine: Math.max(1, f.endLine) } : {}),
            ...(f.endColumn ? { endColumn: Math.max(1, f.endColumn) } : {}),
          },
        },
      }],
      partialFingerprints: {
        primary: (() => {
          // Content-addressed: survives line shifts, so unchanged findings stay
          // the same finding when unrelated code moves around them.
          const key = `${f.ruleId}|${sarifUri(f.file, root)}|${hashString(f.snippet.trim())}`;
          const n = occurrence.get(key) ?? 0;
          occurrence.set(key, n + 1);
          return `${key}|${n}`;
        })(),
      },
      properties: {
        confidence: f.confidence,
        cvss: f.cvss?.baseScore,
        owasp: f.owasp,
      },
    });
  }

  return JSON.stringify({
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'VulnScan',
          fullName: 'VulnScan Pro — Advanced Security Vulnerability Scanner',
          version: '2.0.0',
          informationUri: 'https://github.com/vulnscan',
          rules: [...rules.values()],
        },
      },
      results,
    }],
  }, null, 2);
}

function severityToSarif(severity: string): string {
  switch (severity) {
    case 'critical': return 'error';
    case 'high': return 'error';
    case 'medium': return 'warning';
    case 'low': return 'note';
    default: return 'none';
  }
}

function cvssToGitHubSeverity(score: number | undefined): string {
  if (!score) return '0.0';
  return score.toFixed(1);
}

function hashString(s: string): string {
  let hash = 0;
  for (let i = 0; i < s.length; i++) {
    const chr = s.charCodeAt(i);
    hash = ((hash << 5) - hash) + chr;
  }
  return Math.abs(hash).toString(16).substring(0, 8);
}
