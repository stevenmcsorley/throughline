/**
 * Entropy-Based Secrets Detection
 *
 * Uses Shannon entropy to detect high-entropy strings that are likely
 * to be API keys, tokens, private keys, or other credentials.
 *
 * Why entropy: Regex patterns miss secrets with unknown formats.
 * High-entropy strings (base64-encoded keys, hex tokens, etc.) stand out
 * statistically from normal code.
 *
 * Detection categories:
 *   - Base64 entropy: keys/tokens encoded in base64 (AWS, GCP, GitHub, JWT secrets)
 *   - Hex entropy: hex-encoded secrets
 *   - High-entropy identifiers: variable names assigned to high-entropy strings
 *   - Private key headers: -----BEGIN ... PRIVATE KEY-----
 */

import { Finding, Severity, Confidence } from '../types';
import { calculateCvss, DEFAULT_CVSS } from '../cvss';

interface EntropyOptions {
  /** Minimum Shannon entropy threshold (default: 4.2) */
  minEntropy: number;
  /** Minimum string length to analyze (default: 16) */
  minLength: number;
  /** Maximum string length to analyze (default: 512) */
  maxLength: number;
  /** Skip strings that look like English text */
  skipNaturalLanguage: boolean;
}

interface EntropyFinding {
  line: number;
  column: number;
  value: string;
  entropy: number;
  category: 'base64' | 'hex' | 'private-key' | 'generic-secret' | 'password';
  message: string;
  severity: Severity;
  confidence: Confidence;
}

const DEFAULT_OPTIONS: EntropyOptions = {
  minEntropy: 4.2,
  minLength: 16,
  maxLength: 512,
  skipNaturalLanguage: true,
};

// ─── Shannon Entropy ───────────────────────────────────────────────────

function shannonEntropy(str: string): number {
  const len = str.length;
  if (len === 0) return 0;

  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }

  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

// ─── Base64 Detection ───────────────────────────────────────────────────

const BASE64_REGEX = /[A-Za-z0-9+/]{20,}={0,2}/g;
const BASE64_URL_REGEX = /[A-Za-z0-9_-]{20,}/g;
const HEX_REGEX = /\b(?:0x)?[0-9A-Fa-f]{32,}\b/g;
const PRIVATE_KEY_REGEX = /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g;
const PASSWORD_ASSIGN_REGEX = /(?:password|passwd|pwd|secret|token|key|api[_-]?key|apikey|auth[_-]?token|access[_-]?key)\s*[:=]\s*['"]([^'"]{8,})['"]/gi;
const GENERIC_ASSIGN_REGEX = /\b([A-Z_]{3,30})\s*=\s*['"]([A-Za-z0-9+/=]{20,})['"]/g;

// ─── Natural Language Detection ────────────────────────────────────────

const ENGLISH_WORDS = new Set([
  'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had',
  'her', 'was', 'one', 'our', 'out', 'has', 'have', 'from', 'they', 'will',
  'with', 'this', 'that', 'what', 'when', 'make', 'like', 'just', 'into',
  'over', 'such', 'only', 'other', 'some', 'could', 'been', 'than', 'then',
  'also', 'very', 'after', 'about', 'which', 'their', 'there', 'would',
  'should', 'because', 'between', 'through', 'during', 'without', 'another',
]);

function isNaturalLanguage(str: string): boolean {
  const words = str.toLowerCase().split(/\s+/);
  if (words.length < 3) return false;

  let englishCount = 0;
  for (const word of words) {
    const cleaned = word.replace(/[^a-z]/g, '');
    if (ENGLISH_WORDS.has(cleaned)) englishCount++;
    if (cleaned.length > 0 && englishCount >= 2) return true;
  }

  // Check character frequency: natural text has spaces, common letters
  const hasSpaces = str.includes(' ');
  const alphaRatio = (str.match(/[a-zA-Z]/g) || []).length / str.length;

  // Natural language has spaces and moderate alpha ratio
  if (hasSpaces && alphaRatio > 0.6 && alphaRatio < 0.9) return true;

  return false;
}

// ─── Secret Scoring ────────────────────────────────────────────────────

interface SecretScore {
  entropy: number;
  isBase64: boolean;
  isHex: boolean;
  hasMixedCase: boolean;
  hasDigits: boolean;
  hasSpecial: boolean;
  charSetSize: number;
}

function scoreString(str: string): SecretScore {
  const hasUpper = /[A-Z]/.test(str);
  const hasLower = /[a-z]/.test(str);
  const hasDigits = /[0-9]/.test(str);
  const hasSpecial = /[^A-Za-z0-9]/.test(str);

  const uniqueChars = new Set(str);
  const charSetSize = uniqueChars.size;

  return {
    entropy: shannonEntropy(str),
    isBase64: /^[A-Za-z0-9+/]+={0,2}$/.test(str),
    isHex: /^[0-9A-Fa-f]+$/.test(str),
    hasMixedCase: hasUpper && hasLower,
    hasDigits,
    hasSpecial,
    charSetSize,
  };
}

// ─── Value Anonymization ───────────────────────────────────────────────

function anonymize(value: string): string {
  if (value.length <= 8) return '*'.repeat(value.length);
  return value.substring(0, 4) + '*'.repeat(value.length - 8) + value.substring(value.length - 4);
}

// ─── Main Scanners ─────────────────────────────────────────────────────

/**
 * Scan all string literals in source code for high-entropy secrets.
 */
export function scanEntropy(
  content: string,
  filePath: string,
  options: Partial<EntropyOptions> = {}
): EntropyFinding[] {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const findings: EntropyFinding[] = [];
  const lines = content.split('\n');

  // Phase 1: Scan string literals (single-quoted, double-quoted, backtick)
  const stringLiterals = extractStringLiterals(content);

  for (const lit of stringLiterals) {
    // Skip very short or empty strings
    if (lit.value.length < opts.minLength) continue;
    if (lit.value.length > opts.maxLength) continue;

    // Skip natural language text
    if (opts.skipNaturalLanguage && isNaturalLanguage(lit.value)) continue;

    const score = scoreString(lit.value);

    // Skip low-entropy strings
    if (score.entropy < opts.minEntropy) continue;

    // Categorize
    const finding = categorizeSecret(lit.value, score, lit.line, lit.column);
    if (finding) {
      findings.push(finding);
    }
  }

  // Phase 2: Scan for private key headers
  privateKeyScan(content, findings);

  // Phase 3: Scan variable assignments for high-entropy secrets
  variableAssignmentScan(content, opts, findings);

  return findings;
}

// ─── String Literal Extraction ─────────────────────────────────────────

interface StringLiteral {
  value: string;
  line: number;
  column: number;
}

function extractStringLiterals(content: string): StringLiteral[] {
  const literals: StringLiteral[] = [];

  // Match all quoted strings: single, double, backtick
  // Use a stateful approach to track line numbers
  const regex = /(['"`])((?:(?!\1).|\\\1)*?)\1/gs;

  let match;
  while ((match = regex.exec(content)) !== null) {
    const value = match[2];
    // Compute line/column from position
    const before = content.substring(0, match.index);
    const line = (before.match(/\n/g) || []).length + 1;
    const lastNewline = before.lastIndexOf('\n');
    const column = match.index - lastNewline;

    literals.push({
      value: value.length < 200 ? value : value.substring(0, 200),
      line,
      column,
    });
  }

  return literals;
}

// ─── Private Key Detection ─────────────────────────────────────────────

function privateKeyScan(content: string, findings: EntropyFinding[]): void {
  let match;
  PRIVATE_KEY_REGEX.lastIndex = 0;
  while ((match = PRIVATE_KEY_REGEX.exec(content)) !== null) {
    const before = content.substring(0, match.index);
    const line = (before.match(/\n/g) || []).length + 1;

    findings.push({
      line,
      column: 0,
      value: anonymize(match[0]),
      entropy: shannonEntropy(match[0]),
      category: 'private-key',
      message: 'Private key found in source code — never commit private keys',
      severity: 'critical',
      confidence: 'certain',
    });
  }
}

// ─── Variable Assignment Scanning ──────────────────────────────────────

function variableAssignmentScan(
  content: string,
  opts: EntropyOptions,
  findings: EntropyFinding[]
): void {
  // Check password/secret/token assignments
  let match;
  PASSWORD_ASSIGN_REGEX.lastIndex = 0;
  while ((match = PASSWORD_ASSIGN_REGEX.exec(content)) !== null) {
    const value = match[1];
    if (value.length < opts.minLength) continue;

    const before = content.substring(0, match.index);
    const line = (before.match(/\n/g) || []).length + 1;

    const score = scoreString(value);
    if (score.entropy >= 3.5) {
      findings.push({
        line,
        column: (match[0].indexOf(value)),
        value: anonymize(value),
        entropy: score.entropy,
        category: 'password',
        message: `Hardcoded ${match[0].match(/^(?:password|passwd|pwd|secret|token|key|api[_-]?key|apikey|auth[_-]?token|access[_-]?key)/i)?.[0] || 'credential'} found`,
        severity: score.entropy >= 4.5 ? 'critical' : 'high',
        confidence: score.entropy >= 4.5 ? 'certain' : 'high',
      });
    }
  }

  // Check generic UPPERCASE_NAME = "long-value" patterns
  GENERIC_ASSIGN_REGEX.lastIndex = 0;
  while ((match = GENERIC_ASSIGN_REGEX.exec(content)) !== null) {
    const name = match[1];
    const value = match[2];

    const before = content.substring(0, match.index);
    const line = (before.match(/\n/g) || []).length + 1;

    const score = scoreString(value);
    // Only flag if both the name AND the value suggest a secret
    const secretNameIndicators = /(?:KEY|SECRET|TOKEN|PASSWORD|AUTH|CREDENTIAL|API|PRIVATE)/i;
    if (score.entropy >= 3.8 && secretNameIndicators.test(name)) {
      findings.push({
        line,
        column: (match[0].indexOf(value)),
        value: anonymize(value),
        entropy: score.entropy,
        category: 'generic-secret',
        message: `Possible hardcoded secret: ${name} = "${anonymize(value)}"`,
        severity: score.entropy >= 4.5 ? 'critical' : 'high',
        confidence: score.entropy >= 4.5 ? 'high' : 'medium',
      });
    }
  }
}

// ─── Categorization ────────────────────────────────────────────────────

function categorizeSecret(
  value: string,
  score: SecretScore,
  line: number,
  column: number
): EntropyFinding | null {
  const { entropy, isBase64, isHex, hasMixedCase, hasDigits, charSetSize } = score;

  // Base64 secrets (AWS keys, JWT secrets, etc.)
  if (isBase64 && entropy >= 4.5 && value.length >= 20) {
    let subCategory = '';
    let specificSeverity: Severity = 'critical';
    let specificMsg = '';

    // AWS Access Key pattern: AKIA... (20 chars base64)
    if (/^AKIA[0-9A-Z]{16}$/i.test(value)) {
      subCategory = 'aws-access-key';
      specificMsg = 'AWS Access Key ID (AKIA prefix) detected';
      specificSeverity = 'critical';
    }
    // AWS Secret Key pattern: ~40 chars base64
    else if (/^[A-Za-z0-9+/]{40}$/.test(value) && entropy >= 5.0) {
      subCategory = 'aws-secret-key';
      specificMsg = 'AWS Secret Access Key (40-char base64, high entropy) detected';
      specificSeverity = 'critical';
    }
    // GitHub personal access token: ghp_...
    else if (/^gh[pousr]_[A-Za-z0-9]{36,}$/i.test(value)) {
      subCategory = 'github-token';
      specificMsg = 'GitHub Personal Access Token detected';
      specificSeverity = 'critical';
    }
    // Generic high-entropy base64
    else {
      subCategory = 'base64-secret';
      specificMsg = `High-entropy base64 string (entropy: ${entropy.toFixed(2)}) — likely API key or token`;
      specificSeverity = 'high';
    }

    return {
      line,
      column,
      value: anonymize(value),
      entropy,
      category: subCategory as any,
      message: specificMsg,
      severity: specificSeverity,
      confidence: entropy >= 5.2 ? 'certain' : 'high',
    };
  }

  // Hex secrets (crypto keys, HMAC secrets)
  if (isHex && entropy >= 3.5 && value.length >= 32) {
    return {
      line,
      column,
      value: anonymize(value),
      entropy,
      category: 'hex',
      message: `High-entropy hex string (${value.length} chars, entropy: ${entropy.toFixed(2)}) — possible cryptographic key`,
      severity: 'high',
      confidence: entropy >= 4.0 ? 'high' : 'medium',
    };
  }

  // Generic high-entropy strings
  if (entropy >= 4.8 && charSetSize >= 30) {
    return {
      line,
      column,
      value: anonymize(value),
      entropy,
      category: 'generic-secret',
      message: `High-entropy string (entropy: ${entropy.toFixed(2)}, charset: ${charSetSize} unique chars) — possible credential`,
      severity: 'high',
      confidence: 'medium',
    };
  }

  return null;
}

// ─── Integration Helper ────────────────────────────────────────────────

/**
 * Convert entropy findings to the standard Finding format for the scanner.
 */
export function entropyFindingsToFindings(
  eFindings: EntropyFinding[],
  file: string
): Finding[] {
  return eFindings.map(ef => ({
    ruleId: `entropy-${ef.category}`,
    title: ef.message,
    severity: ef.severity,
    confidence: ef.confidence,
    message: `${ef.message} (entropy: ${ef.entropy?.toFixed(2) || 'N/A'})`,
    file,
    line: ef.line,
    column: ef.column,
    snippet: ef.value,
    recommendation: getEntropyRecommendation(ef.category),
    references: ['https://cwe.mitre.org/data/definitions/798.html', 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
    cwe: 'CWE-798',
    owasp: 'A02:2021-Cryptographic Failures' as any,
    falsePositiveRisk: ef.entropy < 4.5 ? 'medium' : 'low',
    cvss: calculateCvss(DEFAULT_CVSS.hardcodedCredential),
  }));
}

function getEntropyRecommendation(category: string): string {
  switch (category) {
    case 'aws-access-key':
    case 'aws-secret-key':
      return 'Use IAM roles (EC2/ECS/Lambda) or environment variables. Never commit AWS credentials. Rotate immediately if exposed.';
    case 'github-token':
      return 'Use GitHub Actions secrets or environment variables. Revoke this token immediately at github.com/settings/tokens.';
    case 'private-key':
      return 'Store private keys in a secrets manager (AWS KMS, HashiCorp Vault, Azure Key Vault). Rotate immediately if exposed.';
    case 'password':
      return 'Use environment variables or a secrets manager. Hash passwords server-side, never store in code.';
    default:
      return 'Move secrets to environment variables, .env files (gitignored), or a secrets manager. Rotate any exposed credentials.';
  }
}
