import { Rule, DependencyVuln } from '../../types';
import * as fs from 'fs';
import * as path from 'path';

// Known vulnerable package version ranges (simplified — in production, use OSV/ADB databases)
const KNOWN_VULNS: DependencyVuln[] = [
  { package: 'lodash', version: '<4.17.21', cve: 'CVE-2021-23337', severity: 'high', description: 'Command injection in lodash template', fixedIn: '4.17.21' },
  { package: 'minimist', version: '<1.2.6', cve: 'CVE-2021-44906', severity: 'critical', description: 'Prototype pollution via minimist', fixedIn: '1.2.6' },
  { package: 'node-fetch', version: '<2.6.7', cve: 'CVE-2022-0235', severity: 'high', description: 'SSRF via node-fetch', fixedIn: '2.6.7' },
  { package: 'express', version: '<4.17.3', cve: 'CVE-2022-24999', severity: 'high', description: 'qs prototype pollution in Express', fixedIn: '4.17.3' },
  { package: 'jsonwebtoken', version: '<9.0.0', cve: 'CVE-2022-23529', severity: 'critical', description: 'JWT verification bypass', fixedIn: '9.0.0' },
  { package: 'axios', version: '<1.6.0', cve: 'CVE-2023-45857', severity: 'medium', description: 'XSRF-TOKEN cookie vulnerability', fixedIn: '1.6.0' },
  { package: 'semver', version: '<7.5.2', cve: 'CVE-2022-25883', severity: 'high', description: 'ReDoS in semver regex', fixedIn: '7.5.2' },
  { package: 'word-wrap', version: '<1.2.4', cve: 'CVE-2023-26115', severity: 'high', description: 'ReDoS in word-wrap', fixedIn: '1.2.4' },
  { package: 'protobufjs', version: '<7.2.5', cve: 'CVE-2023-36665', severity: 'critical', description: 'Prototype pollution in protobufjs', fixedIn: '7.2.5' },
  { package: 'webpack', version: '<5.94.0', cve: 'CVE-2024-43788', severity: 'high', description: 'DOM clobbering via webpack AutoPublicPath', fixedIn: '5.94.0' },
  { package: 'follow-redirects', version: '<1.15.6', cve: 'CVE-2024-28849', severity: 'high', description: 'Credential leak in follow-redirects', fixedIn: '1.15.6' },
  { package: 'micromatch', version: '<4.0.8', cve: 'CVE-2024-4067', severity: 'high', description: 'ReDoS in micromatch', fixedIn: '4.0.8' },
  { package: 'braces', version: '<3.0.3', cve: 'CVE-2024-4068', severity: 'high', description: 'Uncontrolled recursion in braces', fixedIn: '3.0.3' },
  { package: 'glob', version: '<10.3.12', cve: 'CVE-2024-4069', severity: 'high', description: 'ReDoS in glob', fixedIn: '10.3.12' },
  { package: 'ejs', version: '<3.1.10', cve: 'CVE-2024-33883', severity: 'critical', description: 'RCE via ejs template injection', fixedIn: '3.1.10' },
];

export const dependencyScanRule: Rule = {
  id: 'dependency-vuln',
  name: 'Vulnerable Dependencies',
  description: 'Known CVEs in project dependencies',
  severity: 'high',
  confidence: 'high',
  cwe: 'CWE-1104',
  owasp: 'A06:2021-Vulnerable Components',
  references: ['https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/'],
  extensions: ['.json'],

  scan(filePath: string, content: string, lines: string[]) {
    const findings: any[] = [];
    const filename = path.basename(filePath);

    // Check package.json
    if (filename === 'package.json') {
      try {
        const pkg = JSON.parse(content);
        const deps = { ...pkg.dependencies, ...pkg.devDependencies, ...pkg.peerDependencies };

        for (const [name, version] of Object.entries(deps || {})) {
          // Clean version string (remove ^ ~ >= etc)
          const cleanVer = String(version).replace(/^[\^~>=<]+/, '').split(' ')[0];
          for (const vuln of KNOWN_VULNS) {
            if (vuln.package === name && compareVersions(cleanVer, vuln.version.replace(/^[<>=]+/, '')) < 0) {
              findings.push({
                ruleId: this.id,
                title: this.name,
                severity: vuln.severity,
                confidence: 'high' as const,
                message: `${name}@${version} — ${vuln.description} (${vuln.cve})`,
                file: filePath,
                line: 1,
                column: 1,
                snippet: `"${name}": "${version}"`,
                recommendation: `Update ${name} to ${vuln.fixedIn || 'latest'}. Run: npm install ${name}@${vuln.fixedIn || 'latest'}`,
                cwe: this.cwe,
                owasp: this.owasp,
                references: [`https://nvd.nist.gov/vuln/detail/${vuln.cve}`],
                falsePositiveRisk: 'low' as const,
              });
            }
          }
        }
      } catch { /* invalid JSON */ }
    }

    // Check requirements.txt
    if (filename === 'requirements.txt') {
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;
        const match = /^([A-Za-z0-9_.-]+)\s*([><=!]+\s*[\d.]+)?\s*(?:#.*)?$/.exec(trimmed);
        if (match) {
          const name = match[1].toLowerCase();
          const verConstraint = match[2];
          // Basic Python vuln database
          const pythonVulns: DependencyVuln[] = [
            { package: 'django', version: '<4.2.14', cve: 'CVE-2024-38875', severity: 'high', description: 'Django DoS via urlize', fixedIn: '4.2.14' },
            { package: 'flask', version: '<3.0.3', cve: 'CVE-2024-29034', severity: 'medium', description: 'Flask response splitting', fixedIn: '3.0.3' },
            { package: 'requests', version: '<2.32.2', cve: 'CVE-2024-35195', severity: 'medium', description: 'Requests proxy header leak', fixedIn: '2.32.2' },
            { package: 'jinja2', version: '<3.1.4', cve: 'CVE-2024-34064', severity: 'high', description: 'Jinja2 XSS via xmlattr filter', fixedIn: '3.1.4' },
            { package: 'gunicorn', version: '<22.0.0', cve: 'CVE-2024-1135', severity: 'high', description: 'Gunicorn HTTP request smuggling', fixedIn: '22.0.0' },
          ];
          for (const vuln of pythonVulns) {
            if (vuln.package === name) {
              findings.push({
                ruleId: this.id, title: this.name, severity: vuln.severity, confidence: 'high' as const,
                message: `${name}${verConstraint || ''} — ${vuln.description} (${vuln.cve})`,
                file: filePath, line: lines.indexOf(line) + 1, column: 1,
                snippet: trimmed,
                recommendation: `Update ${name} to ${vuln.fixedIn || 'latest'}. Run: pip install --upgrade ${name}`,
                cwe: this.cwe, owasp: this.owasp,
                references: [`https://nvd.nist.gov/vuln/detail/${vuln.cve}`],
                falsePositiveRisk: 'low' as const,
              });
            }
          }
        }
      }
    }

    return findings;
  }
};

function compareVersions(a: string, b: string): number {
  const parse = (v: string) => v.split('.').map(n => parseInt(n) || 0);
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const diff = (pa[i] || 0) - (pb[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}
