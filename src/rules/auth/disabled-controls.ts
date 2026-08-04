import { Rule, Finding } from '../../types';

/**
 * Security controls that were commented out rather than removed.
 *
 * This is a blind spot every other rule has by construction: comments are
 * masked precisely so that documentation and disabled code do not generate
 * findings. But a commented-out CSRF registration is not documentation — it is
 * a protection the application no longer has, and the surrounding code still
 * looks correct.
 *
 * It happens for ordinary reasons. Someone disables CSRF or a helmet header to
 * get a local integration test passing, and the comment ships. Reviewers skim
 * past comment blocks. Nothing else in a scanner looks there.
 *
 * Deliberately narrow: it matches a *call* to a known protective middleware, or
 * an explicit re-enable of escaping, inside a comment. Prose that merely
 * mentions CSRF does not match, because the pattern requires call syntax.
 */

interface DisabledControl {
  regex: RegExp;
  what: string;
}

const DISABLED_CONTROLS: DisabledControl[] = [
  // CSRF middleware — Express/Koa/Django/Rails
  { regex: /\b(?:app|router|server)\s*\.\s*use\s*\(\s*csrf\w*\s*\(/i, what: 'CSRF protection middleware' },
  { regex: /\bcsurf\s*\(/i, what: 'CSRF protection (csurf)' },
  { regex: /\bcsrf_protect\b|\bCsrfViewMiddleware\b|\bprotect_from_forgery\b/i, what: 'CSRF protection' },

  // Security headers
  { regex: /\b(?:app|router|server)\s*\.\s*use\s*\(\s*helmet\b/i, what: 'helmet security headers' },
  { regex: /\bhelmet\s*\.\s*(?:frameguard|contentSecurityPolicy|hsts|noSniff|xssFilter|referrerPolicy)\s*\(/i, what: 'a helmet security header' },
  { regex: /\bapp\s*\.\s*disable\s*\(\s*["']x-powered-by["']\s*\)/i, what: 'x-powered-by header removal' },
  { regex: /\bSecurityMiddleware\b|\bSECURE_SSL_REDIRECT\b|\bSECURE_HSTS_SECONDS\b/i, what: 'a Django security setting' },

  // Authentication / authorisation guards
  { regex: /\b(?:app|router)\s*\.\s*use\s*\(\s*(?:requireLogin|isAuthenticated|ensureAuthenticated|requireAuth|authGuard|authenticate)\s*[,)(]/i, what: 'an authentication guard' },
  { regex: /\b@?login_required\b|\b@?permission_required\b|\bbefore_action\s*:\s*:authenticate/i, what: 'an authorisation decorator' },

  // Output escaping
  { regex: /\bautoescape\s*[:=]\s*true\b/i, what: 'template auto-escaping' },
  { regex: /\bsanitize\w*\s*\([^)]*\)\s*;?\s*$/i, what: 'input sanitisation' },

  // Transport security
  { regex: /\bsecure\s*:\s*true\b/i, what: 'the Secure cookie flag' },
  { regex: /\bhttpOnly\s*:\s*true\b/i, what: 'the HttpOnly cookie flag' },
  { regex: /\bsameSite\s*:\s*["'](?:strict|lax)["']/i, what: 'the SameSite cookie attribute' },
];

export const disabledSecurityControlRule: Rule = {
  id: 'disabled-security-control',
  name: 'Security Control Commented Out',
  description: 'A security middleware, guard or hardening flag exists in the source but is commented out, so the application runs without it',
  severity: 'high',
  confidence: 'medium',
  cwe: 'CWE-1188',
  owasp: 'A05:2021-Security Misconfiguration',
  references: [
    'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',
    'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
  ],
  extensions: ['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.py', '.rb', '.php', '.go', '.java'],

  patterns: DISABLED_CONTROLS.map(c => ({
    regex: new RegExp(c.regex.source, 'gi'),
    onlyInComments: true,
    message: `${c.what} is commented out — the application runs without it`,
    recommendation: 'Re-enable the control, or delete the dead code so the gap is explicit rather than looking like an oversight.',
    confidence: 'medium' as const,
    falsePositiveRisk: 'medium' as const,
  })),

  scan(filePath: string, content: string, lines: string[]): Finding[] {
    const { applyPatternRule, buildVariableMap } = require('../../engine/pattern-engine');
    const varMap = buildVariableMap(lines);
    const findings: Finding[] = [];
    for (const p of this.patterns || []) {
      findings.push(...applyPatternRule(this, filePath, lines, p, varMap));
    }

    // A hardening block is usually commented out wholesale, and several
    // patterns can describe the same disabled line. Report each distinct
    // control once per file, and never twice for the same line.
    const seenMessage = new Set<string>();
    const seenLine = new Set<number>();
    return findings.filter(f => {
      if (seenMessage.has(f.message) || seenLine.has(f.line)) return false;
      seenMessage.add(f.message);
      seenLine.add(f.line);
      return true;
    });
  },
};
