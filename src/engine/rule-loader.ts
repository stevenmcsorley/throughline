/**
 * JSON Rule DSL — User-Defined Vulnerability Rules
 *
 * Users drop JSON rule files in `.throughline-rules/` and they load
 * automatically at scan time. No TypeScript needed.
 *
 * Example rule file: .throughline-rules/check-api-keys.json
 * ```json
 * {
 *   "id": "my-api-key-check",
 *   "name": "Custom API Key Pattern Check",
 *   "severity": "critical",
 *   "description": "Detects internal API key patterns",
 *   "patterns": [
 *     {
 *       "regex": "API_KEY_[A-Z0-9]{32}",
 *       "message": "Internal API key found in source",
 *       "recommendation": "Use a secrets manager instead"
 *     }
 *   ],
 *   "extensions": [".js", ".ts", ".py", ".go"],
 *   "cwe": "CWE-798",
 *   "owasp": "A02:2021-Cryptographic Failures",
 *   "references": ["https://internal-wiki/security-policy"]
 * }
 * ```
 *
 * Advanced features:
 *   - Multi-pattern rules
 *   - Context-aware patterns (must-match / must-not-match combos)
 *   - Severity override per pattern
 *   - AST-level patterns (source → sink via taint tracking)
 *   - File path filters (only scan certain directories)
 *   - Variable name ignore lists
 */

import * as fs from 'fs';
import * as path from 'path';
import { Finding, Rule, Severity, Confidence, CweId, OwaspCategory, PatternRule } from '../types';
import { calculateCvss, DEFAULT_CVSS } from '../cvss';
import { matchIsInData } from './pattern-engine';

// ─── DSL Types ─────────────────────────────────────────────────────────

interface DslRuleDefinition {
  /** Unique rule identifier (kebab-case, e.g. "my-api-key-check") */
  id: string;
  /** Display name */
  name: string;
  /** Default severity for all patterns */
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** Rule description */
  description: string;
  /** Vulnerability patterns */
  patterns: DslPattern[];
  /** File extensions to scan */
  extensions: string[];
  /** CWE identifier */
  cwe?: string;
  /** OWASP Top 10 category */
  owasp?: string;
  /** External references */
  references?: string[];
  /** Default confidence level */
  confidence?: 'certain' | 'high' | 'medium' | 'low';
  /** CVSS vector string override */
  cvssVector?: string;
  /** Glob patterns for files to include (optional — if set, only scan matching) */
  includeFiles?: string[];
  /** Glob patterns for files to exclude */
  excludeFiles?: string[];
  /** Require ALL patterns to match (AND mode). Default: any match (OR mode) */
  matchAll?: boolean;
  /** Context patterns: all of these must ALSO match for the finding to fire */
  contextPatterns?: DslPattern[];
  /** Context patterns that must NOT match (exclusion context) */
  excludeContextPatterns?: DslPattern[];
  /** Maximum false positive risk estimation */
  falsePositiveRisk?: 'low' | 'medium' | 'high';
}

interface DslPattern {
  /** Regex pattern string (will be compiled with 'gi' flags) */
  regex: string;
  /** Human-readable message for the finding */
  message: string;
  /** Fix recommendation */
  recommendation?: string;
  /** Override severity for this specific pattern */
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** Override confidence for this specific pattern */
  confidence?: 'certain' | 'high' | 'medium' | 'low';
  /** Name of the variable being tainted (for taint tracking) */
  taintSource?: string;
  /** Sink pattern the tainted variable flows to */
  taintSink?: string;
}

// ─── Rule Loader ───────────────────────────────────────────────────────

const RULES_DIR = '.throughline-rules';

/**
 * Load all user-defined rules from .throughline-rules/ directory.
 */
export function loadUserRules(baseDir: string = process.cwd()): Rule[] {
  const rulesDir = path.join(baseDir, RULES_DIR);

  if (!fs.existsSync(rulesDir)) return [];
  if (!fs.statSync(rulesDir).isDirectory()) return [];

  const rules: Rule[] = [];
  const files = fs.readdirSync(rulesDir).filter(f => f.endsWith('.json'));

  for (const file of files) {
    const filePath = path.join(rulesDir, file);
    try {
      const raw = fs.readFileSync(filePath, 'utf-8');
      const def = JSON.parse(raw) as DslRuleDefinition;

      if (!def.id || !def.patterns || def.patterns.length === 0) {
        console.warn(`[throughline] Skipping invalid rule: ${file} (missing id or patterns)`);
        continue;
      }

      const rule = compileRule(def, filePath);
      rules.push(rule);
    } catch (err: any) {
      console.warn(`[throughline] Error loading rule ${file}: ${err.message}`);
    }
  }

  return rules;
}

// ─── Compiler ──────────────────────────────────────────────────────────

function compileRule(def: DslRuleDefinition, filePath: string): Rule {
  // Compile patterns
  const patterns: PatternRule[] = def.patterns.map((p, i) => ({
    regex: new RegExp(p.regex, 'gi'),
    message: p.message,
    recommendation: p.recommendation || `Review this code for "${def.name}".`,
    falsePositiveRisk: def.falsePositiveRisk || 'medium',
    confidence: p.confidence as Confidence || def.confidence as Confidence || 'high',
    contextLines: 2,
  }));

  // Compile context patterns
  const contextPatterns: PatternRule[] = (def.contextPatterns || []).map(p => ({
    regex: new RegExp(p.regex, 'gi'),
    message: p.message,
    recommendation: p.recommendation || '',
    falsePositiveRisk: 'low',
    confidence: 'high',
    contextLines: 1,
  }));

  const excludeContext: PatternRule[] = (def.excludeContextPatterns || []).map(p => ({
    regex: new RegExp(p.regex, 'gi'),
    message: p.message,
    recommendation: '',
    falsePositiveRisk: 'low',
    confidence: 'high',
    contextLines: 1,
  }));

  return {
    id: def.id,
    name: def.name,
    description: def.description,
    severity: def.severity as Severity,
    confidence: (def.confidence as Confidence) || 'high',
    cwe: (def.cwe as CweId) || 'CWE-937',
    owasp: (def.owasp as OwaspCategory) || 'A03:2021-Injection',
    references: def.references || [],
    extensions: def.extensions,
    patterns,

    scan(filePath: string, content: string, lines: string[]): Finding[] {
      const findings: Finding[] = [];

      // Check file filters
      if (def.includeFiles && def.includeFiles.length > 0) {
        const matches = def.includeFiles.some(g => {
          const regex = new RegExp(g.replace(/\*/g, '.*').replace(/\?/g, '.'));
          return regex.test(filePath);
        });
        if (!matches) return [];
      }

      if (def.excludeFiles && def.excludeFiles.length > 0) {
        const matches = def.excludeFiles.some(g => {
          const regex = new RegExp(g.replace(/\*/g, '.*').replace(/\?/g, '.'));
          return regex.test(filePath);
        });
        if (matches) return [];
      }

      // For each pattern, find matches
      for (const pattern of patterns) {
        pattern.regex.lastIndex = 0;
        let match;

        while ((match = pattern.regex.exec(content)) !== null) {
          // A user-supplied pattern may match the empty string (`a*`). exec()
          // would then never advance and this loop would never end.
          if (match[0] === '') {
            pattern.regex.lastIndex++;
            continue;
          }

          const matchLine = (content.substring(0, match.index).match(/\n/g) || []).length + 1;
          const lastNewline = content.lastIndexOf('\n', match.index);
          const column = match.index - lastNewline;

          // Custom rules get the same code/data masking as built-in rules.
          // Running their own match loop previously opted them out of it, so a
          // custom pattern happily matched its own definition in source.
          if (!pattern.matchInStrings &&
              matchIsInData(filePath, lines, matchLine - 1, column - 1, match[0].length)) {
            continue;
          }

          // Check context patterns (must-match)
          if (contextPatterns.length > 0) {
            const allContextMatch = contextPatterns.every(cp => cp.regex.test(content));
            if (!allContextMatch) continue;
          }

          // Check exclusion patterns (must-not-match)
          if (excludeContext.length > 0) {
            const anyExcludeMatch = excludeContext.some(cp => cp.regex.test(content));
            if (anyExcludeMatch) continue;
          }

          // AND mode: all patterns must match somewhere in the file
          if (def.matchAll) {
            const allMatch = patterns.every(p => {
              p.regex.lastIndex = 0;
              return p.regex.test(content);
            });
            if (!allMatch) continue;
          }

          // Extract snippet
          const snippetStart = Math.max(0, matchLine - 1);
          const snippetLine = lines[snippetStart]?.trim()?.substring(0, 100) || match[0].substring(0, 100);

          findings.push({
            ruleId: def.id,
            title: pattern.message,
            severity: def.severity as Severity,
            confidence: pattern.confidence as Confidence || def.confidence as Confidence || 'high',
            message: pattern.message,
            file: filePath,
            line: matchLine,
            column,
            snippet: snippetLine,
            recommendation: pattern.recommendation || `Review this finding for the "${def.name}" rule.`,
            references: def.references || [],
            cwe: (def.cwe as CweId) || 'CWE-937',
            owasp: (def.owasp as OwaspCategory) || 'A03:2021-Injection',
            falsePositiveRisk: def.falsePositiveRisk || 'medium',
          });
        }
      }

      return findings;
    },
  };
}

// ─── Rule Validation ───────────────────────────────────────────────────

/**
 * Validate a DSL rule definition. Returns list of errors (empty = valid).
 */
export function validateRule(def: any): string[] {
  const errors: string[] = [];

  if (!def.id || typeof def.id !== 'string') errors.push('Missing or invalid "id"');
  if (!def.name || typeof def.name !== 'string') errors.push('Missing or invalid "name"');
  if (!def.description || typeof def.description !== 'string') errors.push('Missing or invalid "description"');
  if (!['critical', 'high', 'medium', 'low', 'info'].includes(def.severity)) errors.push('Invalid "severity"');
  if (!Array.isArray(def.extensions) || def.extensions.length === 0) errors.push('Missing or empty "extensions"');
  if (!Array.isArray(def.patterns) || def.patterns.length === 0) errors.push('Missing or empty "patterns"');

  if (def.patterns) {
    for (let i = 0; i < def.patterns.length; i++) {
      const p = def.patterns[i];
      if (!p.regex || typeof p.regex !== 'string') errors.push(`Pattern ${i}: missing "regex"`);
      if (!p.message || typeof p.message !== 'string') errors.push(`Pattern ${i}: missing "message"`);
      // Validate regex compiles
      if (typeof p.regex === 'string') {
        try { new RegExp(p.regex); } catch { errors.push(`Pattern ${i}: invalid regex "${p.regex}"`); }
      }
    }
  }

  return errors;
}

// ─── DSL Examples ──────────────────────────────────────────────────────

/**
 * Generate example rule files in .throughline-rules/
 */
export function generateExampleRules(baseDir: string = process.cwd()): string[] {
  const rulesDir = path.join(baseDir, RULES_DIR);

  if (!fs.existsSync(rulesDir)) {
    fs.mkdirSync(rulesDir, { recursive: true });
  }

  const examples: Array<{ name: string; content: any }> = [
    {
      name: 'check-debug-endpoints.json',
      content: {
        id: 'debug-endpoints',
        name: 'Debug Endpoint Detection',
        severity: 'high',
        description: 'Detects debug/test endpoints in production code',
        patterns: [
          { regex: "app\\.(?:get|post|put|delete)\\s*\\(\\s*['\"]/(?:debug|test|admin)", message: 'Debug/test endpoint detected in route definition', recommendation: 'Remove debug endpoints before deploying to production.' },
        ],
        extensions: ['.js', '.ts', '.py'],
        cwe: 'CWE-489',
        owasp: 'A05:2021-Security Misconfiguration',
        references: ['https://cwe.mitre.org/data/definitions/489.html'],
        falsePositiveRisk: 'low',
      },
    },
    {
      name: 'check-unsafe-regex.json',
      content: {
        id: 'unsafe-regex',
        name: 'Potentially Unsafe Regex (ReDoS)',
        severity: 'medium',
        description: 'Regex patterns with nested quantifiers that may cause ReDoS',
        patterns: [
          { regex: "\\/\\(.*\\+.*\\).*\\+.*\\/", message: 'Regex with nested quantifiers — potential ReDoS vulnerability', recommendation: 'Rewrite regex to avoid nested quantifiers. Use atomic groups or possessive quantifiers if available.' },
        ],
        extensions: ['.js', '.ts', '.py', '.go', '.java', '.rb', '.php', '.cs'],
        cwe: 'CWE-1333',
        owasp: 'A03:2021-Injection',
        references: ['https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS'],
        falsePositiveRisk: 'medium',
      },
    },
    {
      name: 'check-unsafe-eval.json',
      content: {
        id: 'unsafe-dynamic-eval',
        name: 'Dynamic Code Execution',
        severity: 'critical',
        description: 'Detects eval/new Function with any variable interpolation',
        patterns: [
          { regex: "eval\\s*\\(\\s*[`'\"]", message: 'eval() called with potentially dynamic content', recommendation: 'Never use eval() with dynamic content. Use JSON.parse() for data parsing.' },
          { regex: "new\\s+Function\\s*\\([^)]*\\$\\{", message: 'new Function() with template literal — arbitrary code execution', recommendation: 'Avoid dynamic code generation entirely.' },
        ],
        extensions: ['.js', '.ts'],
        cwe: 'CWE-95',
        owasp: 'A03:2021-Injection',
        references: ['https://cwe.mitre.org/data/definitions/95.html'],
      },
    },
  ];

  const created: string[] = [];
  for (const example of examples) {
    const filePath = path.join(rulesDir, example.name);
    if (!fs.existsSync(filePath)) {
      fs.writeFileSync(filePath, JSON.stringify(example.content, null, 2));
      created.push(filePath);
    }
  }

  return created;
}
