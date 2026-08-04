/**
 * AI Triage Support
 *
 * Prepares findings for review by an AI and turns its verdicts into something
 * the scanner acts on.
 *
 * The analysis itself is performed by whichever AI is connected to the MCP
 * server in src/mcp/ — Claude, or anything else that speaks MCP. That model
 * already has the repository, the user's intent, and a conversation to ask
 * questions in; it is a far better reviewer than a blind per-finding HTTP call
 * to a model provider, and it needs no API key of its own.
 *
 * This module therefore does three things:
 *   1. Assembles review packets (finding + surrounding source + what to judge).
 *   2. Runs a cheap heuristic prefilter so the AI spends effort where it counts.
 *   3. Validates verdicts coming back before they reach the triage store.
 *
 * Verdict persistence and application live in ./triage.
 */

import * as fs from 'fs';
import { Finding, Severity, Confidence } from '../types';
import { TriageVerdict, findingKey, codeHashOf } from './triage';

// ─── Review packets ────────────────────────────────────────────────────

export interface ReviewPacket {
  findingKey: string;
  codeHash: string;
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  cwe: string;
  owasp: string;
  file: string;
  line: number;
  message: string;
  snippet: string;
  recommendation: string;
  /** Numbered source lines around the finding */
  context: string;
  /** Heuristic hint — a starting point for the reviewer, not a conclusion */
  hint: HeuristicHint;
}

/**
 * Read numbered source lines around a finding so a reviewer can judge whether
 * the input is actually attacker-controlled and whether a sanitizer is present.
 */
export function readFindingContext(finding: Finding, radius: number = 12): string {
  try {
    if (!fs.existsSync(finding.file)) return '(file not found)';
    const lines = fs.readFileSync(finding.file, 'utf-8').split('\n');
    const start = Math.max(0, finding.line - radius - 1);
    const end = Math.min(lines.length, finding.line + radius);
    return lines
      .slice(start, end)
      .map((l, i) => {
        const lineNo = start + i + 1;
        const marker = lineNo === finding.line ? '>' : ' ';
        return `${marker} ${lineNo.toString().padStart(4, ' ')} | ${l}`;
      })
      .join('\n');
  } catch {
    return '(unable to read file)';
  }
}

export function buildReviewPacket(finding: Finding, contextRadius: number = 12): ReviewPacket {
  return {
    findingKey: findingKey(finding),
    codeHash: codeHashOf(finding.snippet),
    ruleId: finding.ruleId,
    title: finding.title,
    severity: finding.severity,
    confidence: finding.confidence,
    cwe: finding.cwe,
    owasp: finding.owasp,
    file: finding.file,
    line: finding.line,
    message: finding.message,
    snippet: finding.snippet,
    recommendation: finding.recommendation,
    context: readFindingContext(finding, contextRadius),
    hint: heuristicPrefilter(finding),
  };
}

/** The review instructions handed to the AI alongside the packets. */
export const TRIAGE_INSTRUCTIONS = `You are reviewing static analysis findings from VulnScan.

For each finding, decide whether it is a genuine, exploitable vulnerability in
this codebase — not whether the pattern is dangerous in the abstract.

Judge each one against:
  - Reachability: can attacker-controlled input actually reach this line?
  - Sanitization: is the value validated, escaped, parameterized, or allowlisted
    before it reaches the sink? Check the context lines, not just the snippet.
  - Environment: is this test fixture, seed data, an example, or a build script?
    Those are usually not exploitable, but a hardcoded production credential in
    a test file still is.
  - Severity: the scanner assigns severity per rule. Correct it when the actual
    blast radius in this code differs.

The "hint" field is a keyword heuristic, not a verdict. Overrule it freely.

When you have judged them, call submit_triage with one verdict per finding.
Pass findingKey and codeHash back exactly as given — the codeHash binds your
verdict to the code you actually read, so it is discarded if the code changes.

Be specific in "analysis": name the sanitizer, the reaching path, or the reason
the input cannot be attacker-controlled. "Looks fine" is not a review.`;

// ─── Heuristic prefilter ───────────────────────────────────────────────

export interface HeuristicHint {
  /** Suggested review order — higher means more likely to be real */
  priority: 'high' | 'medium' | 'low';
  /** Signals suggesting a false positive */
  falsePositiveSignals: string[];
  /** Signals suggesting a genuine issue */
  truePositiveSignals: string[];
}

const FP_INDICATORS: { pattern: RegExp; reason: string }[] = [
  { pattern: /fixture|mock|stub|dummy|example|sample|placeholder/, reason: 'test/mock/example identifier present' },
  { pattern: /\/\/\s*(?:safe|ok|trusted|known|verified)/, reason: 'safety comment on the line' },
  { pattern: /dompurify|sanitize|escape|encodeuri|parameteriz/, reason: 'sanitizer or encoder in the snippet' },
  { pattern: /eslint-disable|tslint-disable|nosec|nolint|codeql\[/, reason: 'suppression directive present' },
  { pattern: /^\s*(?:\/\/|#|\*)/, reason: 'line appears to be a comment' },
];

const TP_INDICATORS: { pattern: RegExp; reason: string }[] = [
  { pattern: /req\.(?:query|body|params|param|cookies|headers)/, reason: 'Express request input' },
  { pattern: /\$_get|\$_post|\$_request|\$_cookie/, reason: 'PHP superglobal input' },
  { pattern: /request\.(?:args|form|get|post|json)/, reason: 'Flask/Django request input' },
  { pattern: /process\.argv|os\.environ|getenv/, reason: 'external process input' },
];

/** Path-based signals — checked against the file path rather than the snippet. */
const TEST_PATH = /(?:^|[\\/])(?:tests?|__tests__|spec|fixtures?|examples?|mocks?)[\\/]|\.(?:test|spec)\.[jt]sx?$/i;

/**
 * A cheap keyword pass to order the review queue. Deliberately not a verdict —
 * keyword matching cannot tell reachable from unreachable, which is exactly why
 * the AI review exists.
 */
export function heuristicPrefilter(finding: Finding): HeuristicHint {
  const snippet = finding.snippet.toLowerCase();
  const falsePositiveSignals: string[] = [];
  const truePositiveSignals: string[] = [];

  for (const { pattern, reason } of FP_INDICATORS) {
    if (pattern.test(snippet)) falsePositiveSignals.push(reason);
  }
  for (const { pattern, reason } of TP_INDICATORS) {
    if (pattern.test(snippet)) truePositiveSignals.push(reason);
  }
  if (TEST_PATH.test(finding.file)) {
    falsePositiveSignals.push('file lives under a test/fixture/example path');
  }
  if (finding.taintFlow) {
    truePositiveSignals.push(
      `dataflow traced from "${finding.taintFlow.source}" with ${finding.taintFlow.sanitizers.length} sanitizer(s) on the path`
    );
  }

  let priority: HeuristicHint['priority'];
  if (truePositiveSignals.length > 0 && falsePositiveSignals.length === 0) {
    priority = 'high';
  } else if (falsePositiveSignals.length >= 2 && truePositiveSignals.length === 0) {
    priority = 'low';
  } else {
    priority = 'medium';
  }

  return { priority, falsePositiveSignals, truePositiveSignals };
}

/** Order findings so the most likely-real are reviewed first. */
export function prioritizeForReview(findings: Finding[]): Finding[] {
  const severityRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const priorityRank: Record<string, number> = { high: 0, medium: 1, low: 2 };
  return [...findings].sort((a, b) => {
    const p = priorityRank[heuristicPrefilter(a).priority] - priorityRank[heuristicPrefilter(b).priority];
    if (p !== 0) return p;
    return severityRank[a.severity] - severityRank[b.severity];
  });
}

// ─── Verdict validation ────────────────────────────────────────────────

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const CONFIDENCES: Confidence[] = ['certain', 'high', 'medium', 'low'];

export interface RawVerdict {
  findingKey: string;
  codeHash: string;
  isRealVulnerability: boolean;
  reviewConfidence?: string;
  analysis: string;
  riskAssessment?: string;
  exploitScenario?: string;
  adjustedSeverity?: string;
  fix?: string;
  fixIsAutoApplicable?: boolean;
  caveats?: string;
}

/**
 * Validate a verdict submitted by a reviewer before it is persisted.
 * Rejects rather than coerces: a malformed verdict that silently becomes
 * "false positive" would hide a real vulnerability.
 */
export function validateVerdict(
  raw: RawVerdict,
  triagedBy: string,
  now: string
): { ok: true; verdict: TriageVerdict } | { ok: false; error: string } {
  if (!raw.findingKey || typeof raw.findingKey !== 'string') {
    return { ok: false, error: 'findingKey is required' };
  }
  if (!raw.codeHash || typeof raw.codeHash !== 'string') {
    return { ok: false, error: `codeHash is required (finding ${raw.findingKey}); pass back the value from the review packet` };
  }
  if (typeof raw.isRealVulnerability !== 'boolean') {
    return { ok: false, error: `isRealVulnerability must be true or false (finding ${raw.findingKey})` };
  }
  if (!raw.analysis || raw.analysis.trim().length < 10) {
    return { ok: false, error: `analysis must explain the verdict (finding ${raw.findingKey})` };
  }
  if (raw.adjustedSeverity && !SEVERITIES.includes(raw.adjustedSeverity as Severity)) {
    return { ok: false, error: `adjustedSeverity "${raw.adjustedSeverity}" must be one of: ${SEVERITIES.join(', ')}` };
  }
  if (raw.reviewConfidence && !CONFIDENCES.includes(raw.reviewConfidence as Confidence)) {
    return { ok: false, error: `reviewConfidence "${raw.reviewConfidence}" must be one of: ${CONFIDENCES.join(', ')}` };
  }

  return {
    ok: true,
    verdict: {
      findingKey: raw.findingKey,
      codeHash: raw.codeHash,
      isRealVulnerability: raw.isRealVulnerability,
      reviewConfidence: (raw.reviewConfidence as Confidence) || 'medium',
      analysis: raw.analysis.trim(),
      riskAssessment: raw.riskAssessment?.trim() || undefined,
      exploitScenario: raw.exploitScenario?.trim() || undefined,
      adjustedSeverity: (raw.adjustedSeverity as Severity) || undefined,
      fix: raw.fix?.trim() || undefined,
      fixIsAutoApplicable: raw.fixIsAutoApplicable ?? false,
      caveats: raw.caveats?.trim() || undefined,
      triagedBy,
      triagedAt: now,
    },
  };
}

// ─── Fix templates ─────────────────────────────────────────────────────

const RULE_FIX_TEMPLATES: Record<string, string> = {
  'sql-injection': 'Parameterize the query:\n- db.query(`SELECT * FROM users WHERE id = ${userId}`)\n+ db.query("SELECT * FROM users WHERE id = ?", [userId])',
  'command-injection': 'Pass arguments as an array instead of a shell string:\n- exec(`ping ${host}`)\n+ execFile("ping", [host])',
  'xss': 'Assign text, not markup:\n- element.innerHTML = userInput\n+ element.textContent = userInput',
  'hardcoded-secrets': 'Move the secret out of source and rotate it:\n- const API_KEY = "sk-abc123"\n+ const API_KEY = process.env.API_KEY',
  'insecure-crypto': 'Use a modern algorithm:\n- crypto.createHash("md5")\n+ crypto.createHash("sha256")',
  'path-traversal': 'Confine the path to a base directory:\n- fs.readFile(userPath)\n+ const safe = path.resolve(BASE, path.basename(userPath))\n+ if (!safe.startsWith(BASE)) throw new Error("Path escape")',
  'ssrf': 'Allowlist the destination:\n- fetch(userUrl)\n+ const u = new URL(userUrl)\n+ if (!ALLOWED_HOSTS.has(u.hostname)) throw new Error("Blocked")',
  'insecure-jwt': 'Use an asymmetric algorithm and a real key:\n- jwt.sign(payload, "secret")\n+ jwt.sign(payload, process.env.JWT_PRIVATE_KEY, { algorithm: "RS256" })',
  'open-redirect': 'Validate the redirect target:\n- res.redirect(req.query.url)\n+ const u = new URL(req.query.url, BASE)\n+ if (u.origin !== BASE) return res.status(400).end()\n+ res.redirect(u.toString())',
};

/**
 * A starting-point patch for common rules. The AI reviewing through MCP should
 * replace this with a fix written against the actual code; this is what is shown
 * when nothing has been triaged yet.
 */
export function suggestFixTemplate(finding: Finding): string {
  if (finding.fixExample) return finding.fixExample;
  return RULE_FIX_TEMPLATES[finding.ruleId] || finding.recommendation;
}
