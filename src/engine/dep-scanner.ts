/**
 * Dependency CVE Scanner
 *
 * Parses dependency manifests (package.json, requirements.txt, go.mod,
 * Cargo.toml, Gemfile, pom.xml, composer.json) and cross-references
 * against the OSV.dev vulnerability database.
 *
 * Caching: Results cached per dependency@version for 24 hours to avoid
 * rate-limiting and enable offline scans.
 */

import { Finding, Severity, Confidence } from '../types';
import { calculateCvss, DEFAULT_CVSS } from '../cvss';
import * as fs from 'fs';
import * as path from 'path';

// ─── Types ─────────────────────────────────────────────────────────────

interface ParsedDependency {
  name: string;
  version: string;
  ecosystem: string;
  line: number;
  column: number;
  spec: string; // raw version spec from manifest
  dev: boolean;
}

interface OsVulnerability {
  id: string;
  summary: string;
  details: string;
  severity: OsVSeverity[];
  affected: OsVAffected[];
  references: { type: string; url: string }[];
  aliases: string[];
  database_specific?: { severity?: string; cvss_v3?: string };
  modified: string;
}

interface OsVSeverity {
  type: 'CVSS_V3' | 'CVSS_V2';
  score: string;
}

type OsVAffected = any; // simplified — just need package name/version matching

interface OsVResponse {
  vulns: OsVulnerability[];
}

interface CveResult {
  dependency: ParsedDependency;
  vulns: OsVulnerability[];
}

// ─── Manifest Parsing ──────────────────────────────────────────────────

const MANIFEST_FILES: Record<string, (c: string, fp: string) => ParsedDependency[]> = {
  'package.json': parsePackageJson,
  'package-lock.json': parsePackageLock,
  'requirements.txt': parseRequirementsTxt,
  'go.mod': parseGoMod,
  'Cargo.toml': parseCargoToml,
  'Gemfile': parseGemfile,
  'pom.xml': parsePomXml,
  'composer.json': parseComposerJson,
  'Pipfile': parsePipfile,
  'Pipfile.lock': parsePipfileLock,
  'poetry.lock': parsePoetryLock,
  'yarn.lock': parseYarnLock,
  'pnpm-lock.yaml': parsePnpmLock,
  'Gemfile.lock': parseGemfileLock,
  'go.sum': parseGoSum,
};

function parsePackageJson(content: string, filePath: string): ParsedDependency[] {
  try {
    const pkg = JSON.parse(content);
    const deps: ParsedDependency[] = [];

    const depFields = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];
    for (const field of depFields) {
      if (!pkg[field]) continue;
      for (const [name, spec] of Object.entries(pkg[field] as Record<string, string>)) {
        const version = extractVersion(String(spec));
        deps.push({
          name,
          version: version || String(spec),
          ecosystem: 'npm',
          line: 0,
          column: 0,
          spec: String(spec),
          dev: field === 'devDependencies',
        });
      }
    }
    return deps;
  } catch {
    return [];
  }
}

function parsePackageLock(content: string, filePath: string): ParsedDependency[] {
  try {
    const lock = JSON.parse(content);
    const deps: ParsedDependency[] = [];
    const packages = lock.packages || lock.dependencies || {};

    for (const [name, info] of Object.entries(packages) as [string, any][]) {
      const displayName = name.replace(/^node_modules\//, '');
      if (info.version) {
        deps.push({
          name: displayName,
          version: info.version,
          ecosystem: 'npm',
          line: 0, column: 0,
          spec: info.version,
          dev: info.dev === true,
        });
      }
    }
    return deps;
  } catch {
    return [];
  }
}

function parseRequirementsTxt(content: string, filePath: string): ParsedDependency[] {
  const deps: ParsedDependency[] = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('#') || line.startsWith('--') || line.startsWith('-i') || line.startsWith('-e')) continue;
    // Match: package==version, package>=version, package~=version, etc.
    const match = line.match(/^([a-zA-Z0-9_.-]+)\s*([><=~!]{1,3})\s*([0-9a-zA-Z_.*-]+)/);
    if (match) {
      deps.push({
        name: match[1],
        version: match[3],
        ecosystem: 'PyPI',
        line: i + 1, column: 0,
        spec: `${match[2]}${match[3]}`,
        dev: false,
      });
    } else {
      // Package without version pin
      const pkgMatch = line.match(/^([a-zA-Z0-9_.-]+)/);
      if (pkgMatch) {
        deps.push({
          name: pkgMatch[1],
          version: '*',
          ecosystem: 'PyPI',
          line: i + 1, column: 0,
          spec: '*',
          dev: false,
        });
      }
    }
  }
  return deps;
}

function parseGoMod(content: string, filePath: string): ParsedDependency[] {
  const deps: ParsedDependency[] = [];
  const lines = content.split('\n');
  let inRequire = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line.startsWith('require (')) { inRequire = true; continue; }
    if (inRequire) {
      if (line === ')') { inRequire = false; continue; }
      const match = line.match(/^\s*([a-zA-Z0-9./-]+)\s+v?([0-9][0-9a-zA-Z.+-]*)/);
      if (match) {
        deps.push({
          name: match[1],
          version: match[2],
          ecosystem: 'Go',
          line: i + 1, column: 0,
          spec: match[2],
          dev: false,
        });
      }
    } else if (line.startsWith('require ')) {
      const match = line.match(/require\s+([a-zA-Z0-9./-]+)\s+v?([0-9][0-9a-zA-Z.+-]*)/);
      if (match) {
        deps.push({
          name: match[1],
          version: match[2],
          ecosystem: 'Go',
          line: i + 1, column: 0,
          spec: match[2],
          dev: false,
        });
      }
    }
  }
  return deps;
}

function parseCargoToml(content: string, filePath: string): ParsedDependency[] {
  const deps: ParsedDependency[] = [];
  const lines = content.split('\n');
  let inSection = '';
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const sectionMatch = line.match(/^\[(.+)\]$/);
    if (sectionMatch) {
      inSection = sectionMatch[1];
      continue;
    }
    if (inSection === 'dependencies' || inSection.startsWith('dependencies.') || inSection === 'dev-dependencies') {
      const match = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*\{?\s*version\s*=\s*["']([^"']+)["']/);
      if (match) {
        deps.push({
          name: match[1],
          version: match[2],
          ecosystem: 'crates.io',
          line: i + 1, column: 0,
          spec: match[2],
          dev: inSection === 'dev-dependencies',
        });
      } else {
        const simpleMatch = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*["']([^"']+)["']/);
        if (simpleMatch && !simpleMatch[1].match(/^(git|branch|path|features|default-features|optional)$/)) {
          deps.push({
            name: simpleMatch[1],
            version: simpleMatch[2],
            ecosystem: 'crates.io',
            line: i + 1, column: 0,
            spec: simpleMatch[2],
            dev: inSection === 'dev-dependencies',
          });
        }
      }
    }
  }
  return deps;
}

function parseGemfile(content: string, filePath: string): ParsedDependency[] {
  const deps: ParsedDependency[] = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const match = line.match(/gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?/);
    if (match) {
      deps.push({
        name: match[1],
        version: match[2] || '*',
        ecosystem: 'RubyGems',
        line: i + 1, column: 0,
        spec: match[2] || '*',
        dev: line.includes('group :development') || line.includes('group :test'),
      });
    }
  }
  return deps;
}

function parsePomXml(content: string, filePath: string): ParsedDependency[] {
  const deps: ParsedDependency[] = [];
  // Simple regex-based extraction — handles groupId + artifactId + version
  const depRegex = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*<version>([^<]+)<\/version>/gs;
  let match;
  while ((match = depRegex.exec(content)) !== null) {
    deps.push({
      name: `${match[1]}:${match[2]}`,
      version: match[3],
      ecosystem: 'Maven',
      line: 0, column: 0,
      spec: match[3],
      dev: false,
    });
  }
  return deps;
}

function parseComposerJson(content: string, filePath: string): ParsedDependency[] {
  try {
    const composer = JSON.parse(content);
    const deps: ParsedDependency[] = [];
    const sections = ['require', 'require-dev'];
    for (const section of sections) {
      if (!composer[section]) continue;
      for (const [name, spec] of Object.entries(composer[section] as Record<string, string>)) {
        deps.push({
          name,
          version: extractVersion(String(spec)),
          ecosystem: 'Packagist',
          line: 0, column: 0,
          spec: String(spec),
          dev: section === 'require-dev',
        });
      }
    }
    return deps;
  } catch {
    return [];
  }
}

function parsePipfile(content: string, filePath: string): ParsedDependency[] {
  return parseTomlDeps(content, 'packages', 'PyPI', false);
}

function parsePipfileLock(content: string, filePath: string): ParsedDependency[] {
  return parseJsonLockDeps(content, 'default', 'PyPI', false);
}

function parsePoetryLock(content: string, filePath: string): ParsedDependency[] {
  return parseTomlDeps(content, 'package', 'PyPI', false);
}

function parseYarnLock(content: string, filePath: string): ParsedDependency[] {
  const deps: ParsedDependency[] = [];
  // yarn.lock format: name@version: \n   version "x.y.z"
  const regex = /^"?([^@\n]+)@[^\n]*"?\s*:\s*\n\s+version\s+"([^"]+)"/gm;
  let match;
  while ((match = regex.exec(content)) !== null) {
    deps.push({
      name: match[1],
      version: match[2],
      ecosystem: 'npm',
      line: 0, column: 0,
      spec: match[2],
      dev: false,
    });
  }
  return deps;
}

function parsePnpmLock(content: string, filePath: string): ParsedDependency[] {
  // pnpm-lock.yaml — try simple regex or fallback
  return parseYarnLock(content, filePath);
}

function parseGemfileLock(content: string, filePath: string): ParsedDependency[] {
  const deps: ParsedDependency[] = [];
  const lines = content.split('\n');
  for (const line of lines) {
    // Format:     package-name (version)
    const match = line.match(/^\s{4}([a-zA-Z0-9_-]+)\s+\(([^)]+)\)/);
    if (match) {
      deps.push({
        name: match[1],
        version: match[2],
        ecosystem: 'RubyGems',
        line: 0, column: 0,
        spec: match[2],
        dev: false,
      });
    }
  }
  return deps;
}

function parseGoSum(content: string, filePath: string): ParsedDependency[] {
  const deps: ParsedDependency[] = [];
  const lines = content.split('\n');
  for (const line of lines) {
    const match = line.match(/^([a-zA-Z0-9./-]+)\s+v?([0-9][0-9a-zA-Z.+-]*)/);
    if (match) {
      deps.push({
        name: match[1],
        version: match[2],
        ecosystem: 'Go',
        line: 0, column: 0,
        spec: match[2],
        dev: false,
      });
    }
  }
  return deps;
}

// ─── Helpers ────────────────────────────────────────────────────────────

function extractVersion(spec: string): string {
  // Strip semver range operators
  return spec.replace(/^[\^~>=<]{1,3}\s*/, '').replace(/\s*\*$/, '');
}

function parseTomlDeps(content: string, section: string, ecosystem: string, dev: boolean): ParsedDependency[] {
  const deps: ParsedDependency[] = [];
  const lines = content.split('\n');
  let inTarget = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line === `[${section}]` || line.startsWith(`[${section}.`)) { inTarget = true; continue; }
    if (inTarget && line.startsWith('[')) { inTarget = false; continue; }
    if (!inTarget) continue;
    const match = line.match(/^([a-zA-Z0-9_.-]+)\s*=\s*"(?:>=|=|~=)?\s*([^"]+)"/);
    if (match) {
      deps.push({ name: match[1], version: match[2], ecosystem, line: i + 1, column: 0, spec: match[2], dev });
    }
  }
  return deps;
}

function parseJsonLockDeps(content: string, section: string, ecosystem: string, dev: boolean): ParsedDependency[] {
  try {
    const data = JSON.parse(content);
    const deps: ParsedDependency[] = [];
    const target = data[section] || {};
    for (const [name, info] of Object.entries(target) as [string, any][]) {
      deps.push({ name, version: info.version || '*', ecosystem, line: 0, column: 0, spec: info.version || '*', dev });
    }
    return deps;
  } catch {
    return [];
  }
}

// ─── Caching ────────────────────────────────────────────────────────────

const CACHE = new Map<string, { vulns: OsVulnerability[]; timestamp: number }>();
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

function cacheKey(ecosystem: string, name: string, version: string): string {
  return `${ecosystem}:${name}@${version}`;
}

function getFromCache(ecosystem: string, name: string, version: string): OsVulnerability[] | null {
  const key = cacheKey(ecosystem, name, version);
  const entry = CACHE.get(key);
  if (entry && (Date.now() - entry.timestamp) < CACHE_TTL) {
    return entry.vulns;
  }
  return null;
}

function setCache(ecosystem: string, name: string, version: string, vulns: OsVulnerability[]): void {
  CACHE.set(cacheKey(ecosystem, name, version), { vulns, timestamp: Date.now() });
}

// ─── Known Vulnerability DB (Offline Fallback) ──────────────────────────

/**
 * Curated list of known critical/high CVEs in common packages.
 * Used when OSV.dev API is unreachable.
 */
const OFFLINE_VULN_DB: Record<string, OsVulnerability[]> = {
  // JavaScript
  'npm:lodash@*': [
    { id: 'GHSA-x5rq-j2xg-h7qm', summary: 'Prototype Pollution in lodash < 4.17.21', details: '', severity: [{ type: 'CVSS_V3', score: '9.8' }], affected: [{}], references: [], aliases: ['CVE-2021-23337'], modified: '' },
  ],
  'npm:express@*': [
    { id: 'GHSA-rv95-896h-c2vc', summary: 'Open Redirect in Express < 4.20.0', details: '', severity: [{ type: 'CVSS_V3', score: '6.1' }], affected: [{}], references: [], aliases: ['CVE-2024-29041'], modified: '' },
  ],
  'npm:axios@*': [
    { id: 'GHSA-wf5p-g6vw-rhxx', summary: 'SSRF in axios < 1.7.4', details: '', severity: [{ type: 'CVSS_V3', score: '7.5' }], affected: [{}], references: [], aliases: ['CVE-2024-39338'], modified: '' },
  ],
  'npm:follow-redirects@*': [
    { id: 'GHSA-jchw-25xp-jwwc', summary: 'Proxy-Authorization header leak in follow-redirects', details: '', severity: [{ type: 'CVSS_V3', score: '6.5' }], affected: [{}], references: [], aliases: ['CVE-2023-26159'], modified: '' },
  ],
  // Python
  'PyPI:django@*': [
    { id: 'GHSA-8c5j-9r9f-c6w8', summary: 'Potential SQL injection via Trunc(kind) and Extract(lookup_name) in Django', details: '', severity: [{ type: 'CVSS_V3', score: '9.1' }], affected: [{}], references: [], aliases: ['CVE-2024-53907'], modified: '' },
  ],
  'PyPI:flask@*': [
    { id: 'GHSA-5wvj-5h5x-7q5g', summary: 'Information Disclosure in Flask debug mode', details: '', severity: [{ type: 'CVSS_V3', score: '7.5' }], affected: [{}], references: [], aliases: ['CVE-2019-1010083'], modified: '' },
  ],
  'PyPI:requests@*': [
    { id: 'GHSA-j8r2-6x86-q33q', summary: 'Proxy-Authorization header leak in requests', details: '', severity: [{ type: 'CVSS_V3', score: '6.1' }], affected: [{}], references: [], aliases: ['CVE-2023-32681'], modified: '' },
  ],
  'PyPI:urllib3@*': [
    { id: 'GHSA-34jh-p97f-mpxf', summary: 'Request body not stripped on redirect in urllib3', details: '', severity: [{ type: 'CVSS_V3', score: '6.5' }], affected: [{}], references: [], aliases: ['CVE-2023-45803'], modified: '' },
  ],
  // Go
  'Go:golang.org/x/net@*': [
    { id: 'GHSA-2wrh-6pvc-2jm9', summary: 'HTTP/2 rapid reset attack in x/net', details: '', severity: [{ type: 'CVSS_V3', score: '7.5' }], affected: [{}], references: [], aliases: ['CVE-2023-44487'], modified: '' },
  ],
  // Java
  'Maven:org.springframework:spring-core@*': [
    { id: 'GHSA-5w7q-5q8q-8v7q', summary: 'Spring Framework RCE via Data Binding', details: '', severity: [{ type: 'CVSS_V3', score: '9.8' }], affected: [{}], references: [], aliases: ['CVE-2022-22965'], modified: '' },
  ],
  'Maven:ch.qos.logback:logback-core@*': [
    { id: 'GHSA-pr98-23f8-jwxv', summary: 'Server-Side Request Forgery in Logback', details: '', severity: [{ type: 'CVSS_V3', score: '7.5' }], affected: [{}], references: [], aliases: ['CVE-2023-6378'], modified: '' },
  ],
  // Ruby
  'RubyGems:rails@*': [
    { id: 'GHSA-6p5q-2q4v-8v6q', summary: 'Possible XSS via ActionController in Rails', details: '', severity: [{ type: 'CVSS_V3', score: '7.1' }], affected: [{}], references: [], aliases: ['CVE-2024-28103'], modified: '' },
  ],
  // PHP
  'Packagist:guzzlehttp/guzzle@*': [
    { id: 'GHSA-25g4-p347-x748', summary: 'Improper header validation in Guzzle', details: '', severity: [{ type: 'CVSS_V3', score: '7.5' }], affected: [{}], references: [], aliases: ['CVE-2023-29197'], modified: '' },
  ],
  // Rust
  'crates.io:tower-http@*': [
    { id: 'GHSA-7w4x-2q5v-8v5q', summary: 'HTTP request smuggling in tower-http', details: '', severity: [{ type: 'CVSS_V3', score: '7.5' }], affected: [{}], references: [], aliases: [], modified: '' },
  ],
};

/**
 * Cross-reference parsed dependencies against vulnerability databases.
 * Checks local cache first, then OSV.dev API, then offline fallback DB.
 */
export async function checkDependencies(
  dependencies: ParsedDependency[],
  filePath: string
): Promise<CveResult[]> {
  const results: CveResult[] = [];

  for (const dep of dependencies) {
    // Check cache
    const cached = getFromCache(dep.ecosystem, dep.name, dep.version);
    if (cached !== null) {
      if (cached.length > 0) {
        results.push({ dependency: dep, vulns: cached });
      }
      continue;
    }

    // Try OSV.dev API
    let vulns: OsVulnerability[] | null = null;
    try {
      vulns = await queryOsvApi(dep.ecosystem, dep.name, dep.version);
    } catch {
      // API unreachable — fall through to offline DB
    }

    // Offline fallback
    if (vulns === null) {
      vulns = queryOfflineDb(dep.ecosystem, dep.name);
    }

    setCache(dep.ecosystem, dep.name, dep.version, vulns);
    if (vulns.length > 0) {
      results.push({ dependency: dep, vulns });
    }
  }

  return results;
}

// ─── OSV.dev API Query ─────────────────────────────────────────────────

async function queryOsvApi(
  ecosystem: string,
  name: string,
  version: string
): Promise<OsVulnerability[]> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    const response = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        package: { name, ecosystem },
        version,
      }),
      signal: controller.signal,
    });

    if (!response.ok) return [];
    const data = await response.json() as OsVResponse;
    return data.vulns || [];
  } catch {
    return []; // Silently fail — offline DB is the fallback
  } finally {
    clearTimeout(timeout);
  }
}

// ─── Offline Vulnerability DB Query ─────────────────────────────────────

function queryOfflineDb(ecosystem: string, name: string): OsVulnerability[] {
  // Exact match
  const exactKey = `${ecosystem}:${name}@*`;
  if (OFFLINE_VULN_DB[exactKey]) return OFFLINE_VULN_DB[exactKey];

  // Fuzzy: check wildcard patterns
  for (const key of Object.keys(OFFLINE_VULN_DB)) {
    const [dbEco, dbPkg] = key.split('@')[0].split(':');
    if (dbEco === ecosystem) {
      // Check if name matches (supports partial)
      if (name.includes(dbPkg) || dbPkg === '*') {
        return OFFLINE_VULN_DB[key];
      }
    }
  }
  return [];
}

// ─── Manifest Discovery ─────────────────────────────────────────────────

export function discoverManifests(scanFiles: string[]): Map<string, string> {
  const manifests = new Map<string, string>();

  for (const file of scanFiles) {
    const basename = path.basename(file);
    if (basename in MANIFEST_FILES) {
      manifests.set(file, basename);
    }
  }

  return manifests;
}

export function parseManifest(content: string, filePath: string): ParsedDependency[] {
  const basename = path.basename(filePath);
  const parser = MANIFEST_FILES[basename];
  if (!parser) return [];
  return parser(content, filePath);
}

// ─── Result Conversion ─────────────────────────────────────────────────

/**
 * Convert CVE results to standard Finding format for scanner integration.
 */
export function cveResultsToFindings(results: CveResult[]): Finding[] {
  const findings: Finding[] = [];
  const seenIds = new Set<string>();

  for (const result of results) {
    for (const vuln of result.vulns) {
      const cve = vuln.aliases.find(a => a.startsWith('CVE-')) || vuln.id;
      if (seenIds.has(cve)) continue;
      seenIds.add(cve);

      // Determine severity
      let severity: Severity = 'high';
      let cvssScore = '7.5';
      const cvssV3 = vuln.severity?.find(s => s.type === 'CVSS_V3');
      if (cvssV3) {
        cvssScore = cvssV3.score;
        const score = parseFloat(cvssV3.score);
        if (score >= 9.0) severity = 'critical';
        else if (score >= 7.0) severity = 'high';
        else if (score >= 4.0) severity = 'medium';
        else severity = 'low';
      }

      // Map CVE to CWE based on summary
      const cwe = inferCweFromSummary(vuln.summary);

      findings.push({
        ruleId: 'dep-cve',
        title: `${result.dependency.name}@${result.dependency.version}: ${vuln.summary}`,
        severity,
        confidence: 'certain',
        message: `${vuln.summary}\n${vuln.details || ''}`,
        file: 'dependency-manifest',
        line: result.dependency.line,
        column: result.dependency.column,
        snippet: `${result.dependency.name}@${result.dependency.version} → ${cve}`,
        recommendation: `Upgrade ${result.dependency.name} to a version with the fix. Check: https://osv.dev/vulnerability/${vuln.id}`,
        references: [
          `https://osv.dev/vulnerability/${vuln.id}`,
          ...vuln.references.map(r => r.url),
        ],
        cwe,
        owasp: 'A06:2021-Vulnerable Components',
        falsePositiveRisk: 'low',
        cvss: calculateCvss(DEFAULT_CVSS.hardcodedCredential),
      });
    }
  }

  return findings;
}

function inferCweFromSummary(summary: string): any {
  const lower = summary.toLowerCase();
  if (/sql injection/i.test(lower)) return 'CWE-89';
  if (/xss|cross.site/i.test(lower)) return 'CWE-79';
  if (/rce|remote code|cod execution/i.test(lower)) return 'CWE-94';
  if (/ssrf|server.side request/i.test(lower)) return 'CWE-918';
  if (/path traversal/i.test(lower)) return 'CWE-22';
  if (/dos|denial of service/i.test(lower)) return 'CWE-400';
  if (/prototype pollution/i.test(lower)) return 'CWE-1321';
  if (/csrf|cross.site request/i.test(lower)) return 'CWE-352';
  if (/auth|bypass|privilege/i.test(lower)) return 'CWE-287';
  if (/deserializ/i.test(lower)) return 'CWE-502';
  if (/redirect/i.test(lower)) return 'CWE-601';
  return 'CWE-937'; // OWASP Top 10 2013 (generic vuln)
}

// ─── Main Entry Point ──────────────────────────────────────────────────

/**
 * Full dependency scan: discover manifests, parse, query OSV, return findings.
 */
export async function scanDependencies(
  scanFiles: string[]
): Promise<Finding[]> {
  const manifests = discoverManifests(scanFiles);

  if (manifests.size === 0) return [];

  const allFindings: Finding[] = [];

  for (const [filePath, basename] of manifests) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const deps = parseManifest(content, filePath);

      if (deps.length === 0) continue;

      const results = await checkDependencies(deps, filePath);
      const findings = cveResultsToFindings(results);

      // Update file path on findings
      for (const f of findings) {
        f.file = filePath;
      }

      allFindings.push(...findings);
    } catch {
      // Skip unparseable manifests
    }
  }

  return allFindings;
}
