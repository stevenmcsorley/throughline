import { Rule, Finding } from '../../types';

/**
 * Insecure Direct Object Reference: an owner identifier read from the request
 * instead of from the authenticated session.
 *
 * `GET /allocations/:userId` looks harmless until you change the number in the
 * URL and read someone else's data. The fix is always the same shape — take the
 * identity from the session, not from something the caller controls.
 *
 * The existing pattern rule only matched a single-expression form
 * (`.findById(req.params.id)`). Real handlers destructure first and use the
 * value a few lines later, which no single regex can follow, so the classic
 * shape went undetected.
 *
 * This is a heuristic and says so: it reports medium confidence, and stays
 * silent when the same handler also consults the session or calls something
 * that looks like an ownership check. Broken access control is the top OWASP
 * category precisely because deciding it properly needs intent that is not in
 * the source — a scanner can flag the smell, not prove the bug.
 */

/** Identifiers that name a principal rather than an arbitrary record. */
const OWNER_ID = String.raw`(?:user|owner|account|customer|member|profile|tenant|org|employee|patient|client)_?[Ii]d`;

/** Reading one of those straight out of the request. */
const FROM_REQUEST: RegExp[] = [
  // const { userId } = req.params  /  { user_id } = request.args
  // Handlers routinely spread the destructure over several lines, so this has
  // to cross newlines — bounded, so it cannot run away across a whole file.
  new RegExp(String.raw`\{[\s\S]{0,150}?\b${OWNER_ID}\b[\s\S]{0,150}?\}\s*=\s*(?:req|request)\s*\.\s*(?:params|query|body|args|form)\b`, 'g'),
  // const userId = req.params.userId
  new RegExp(String.raw`\b${OWNER_ID}\s*=\s*(?:req|request)\s*\.\s*(?:params|query|body|args|form)\s*[.\[]`, 'g'),
  // params[:user_id]  /  $_GET['user_id']  /  request.GET['user_id']
  new RegExp(String.raw`(?:params|_GET|_POST|_REQUEST|GET|POST)\s*\[\s*['":]?${OWNER_ID}['"]?\s*\]`, 'g'),
];

/**
 * Signals that the handler establishes identity properly, or checks ownership.
 * Any of these in the file and the rule stays quiet.
 */
const HAS_AUTHORISATION = new RegExp(
  String.raw`\b(?:req|request)\s*\.\s*(?:session|user)\b` +
  String.raw`|\bsession\s*\[` +
  String.raw`|\bcurrent_?[Uu]ser\b` +
  String.raw`|\bget_?[Cc]urrent_?[Uu]ser\b` +
  String.raw`|\b(?:authorize|authorise|can_?access|check_?owner|ensure_?owner|verify_?owner|is_?owner|assert_?permission)\b` +
  String.raw`|\brequest\.user\b`
);

export const idorRule: Rule = {
  id: 'idor',
  name: 'Insecure Direct Object Reference',
  description: 'An owner identifier is taken from the request rather than the authenticated session, so changing it in the URL may expose another user\'s data',
  severity: 'high',
  confidence: 'medium',
  cwe: 'CWE-639',
  owasp: 'A01:2021-Broken Access Control',
  mitreAttack: { tactic: 'TA0001', technique: 'T1190' },
  references: [
    'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
    'https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html',
  ],
  extensions: ['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.py', '.rb', '.php', '.go', '.java', '.cs'],

  // Handled entirely in scan(): the decision needs whole-file context, not a
  // line match, because the mitigating evidence lives elsewhere in the handler.
  patterns: [],

  scan(filePath: string, content: string, lines: string[]): Finding[] {
    const path = require('path');
    const { languageKind, maskFile } = require('../../engine/pattern-engine');
    const kind = languageKind(path.extname(filePath));
    if (kind === 'unknown') return [];

    // Blank out comments while preserving offsets, so line and column numbers
    // still line up. Both halves of this rule need it: a destructure can span
    // lines, and — the case that matters — NodeGoat ships the *fix*
    // (`const { userId } = req.session`) commented out directly above the
    // vulnerable code. Testing raw content would find that `req.session` and
    // conclude the handler was safe.
    const commentMask: boolean[][] = maskFile(lines, kind, true);
    const code = lines
      .map((line, i) => {
        const mask = commentMask[i];
        if (!mask) return line;
        return [...line].map((ch, c) => (mask[c] ? ' ' : ch)).join('');
      })
      .join('\n');

    // The session or an explicit ownership check is the fix for this weakness.
    // Where one is present in live code, assume the developer handled it rather
    // than second-guessing them — the alternative is flagging every REST route.
    HAS_AUTHORISATION.lastIndex = 0;
    if (HAS_AUTHORISATION.test(code)) return [];

    const findings: Finding[] = [];
    const reportedLines = new Set<number>();

    for (const pattern of FROM_REQUEST) {
      pattern.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(code)) !== null) {
        if (match[0] === '') { pattern.lastIndex++; continue; }

        // A destructure may span several lines; anchor the finding on the line
        // holding the request access, which is the actionable one.
        const upto = code.slice(0, match.index + match[0].length);
        const line = upto.split('\n').length;
        if (reportedLines.has(line)) continue;
        reportedLines.add(line);

        findings.push({
          ruleId: this.id,
          title: this.name,
          severity: this.severity,
          confidence: 'medium',
          message: "Owner identifier read from the request, with no session lookup or ownership check in this file — another user's records may be reachable by changing the value",
          file: filePath,
          line,
          column: 1,
          snippet: (lines[line - 1] || '').trim().slice(0, 150),
          recommendation: 'Take the identity from the authenticated session (req.session.userId / request.user.id), or verify that the requested record belongs to the caller before returning it.',
          fixExample: '// Instead of: const { userId } = req.params;\n// Use:        const { userId } = req.session;',
          cwe: this.cwe,
          owasp: this.owasp,
          mitreAttack: this.mitreAttack,
          references: [...this.references],
          falsePositiveRisk: 'medium',
        });
      }
    }

    // The judgement is about the handler, not the individual expression — a
    // file reading `$_GET['user_id']` on three consecutive lines has one access
    // control problem, not three. Report the first occurrence.
    return findings.slice(0, 1);
  },
};
