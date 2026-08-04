import { extname as pathExtname } from 'path';
import { Finding, PatternRule, Rule, Confidence } from '../types';

// Tracks variable assignments within a file for basic intra-file taint
interface VariableAssignment {
  name: string;
  line: number;
  value: string;
}

export function buildVariableMap(lines: string[]): Map<string, VariableAssignment[]> {
  const varMap = new Map<string, VariableAssignment[]>();
  const assignPatterns = [
    // const/let/var x = y
    /(?:const|let|var)\s+(\w+)\s*=\s*(.+?)(?:;|\n)/g,
    // x = y
    /(\w+)\s*=\s*(.+?)(?:;|\n)/g,
  ];

  for (let i = 0; i < lines.length; i++) {
    for (const pattern of assignPatterns) {
      pattern.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(lines[i])) !== null) {
        const name = match[1];
        const value = match[2].trim();
        if (!varMap.has(name)) varMap.set(name, []);
        varMap.get(name)!.push({ name, line: i + 1, value });
      }
    }
  }
  return varMap;
}

// Check if a variable value contains a pattern matching a taint source
export function isTainted(
  varName: string,
  varMap: Map<string, VariableAssignment[]>,
  taintPatterns: RegExp[],
  depth: number = 0
): { tainted: boolean; chain: string[] } {
  if (depth > 3) return { tainted: false, chain: [] };

  const assignments = varMap.get(varName);
  if (!assignments) return { tainted: false, chain: [] };

  for (const assign of assignments) {
    for (const pattern of taintPatterns) {
      if (pattern.test(assign.value)) {
        return { tainted: true, chain: [varName] };
      }
    }
    // Check if it's assigned from another variable
    const simpleVar = /^(\w+)$/.exec(assign.value.trim());
    if (simpleVar && simpleVar[1] !== varName) {
      const result = isTainted(simpleVar[1], varMap, taintPatterns, depth + 1);
      if (result.tainted) {
        return { tainted: true, chain: [varName, ...result.chain] };
      }
    }
  }

  return { tainted: false, chain: [] };
}

// ─── Code vs data ──────────────────────────────────────────────────────

/**
 * Languages whose string and comment syntax we can mask reliably. Anything not
 * listed (YAML, Dockerfile, Terraform, .env, …) is scanned verbatim, because
 * guessing wrong there would suppress real findings.
 */
const C_LIKE = new Set([
  '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts',
  '.java', '.cs', '.c', '.cpp', '.cc', '.h', '.hpp', '.go', '.php',
  '.swift', '.kt', '.kts', '.scala', '.rs', '.dart',
]);
const HASH_COMMENT = new Set(['.py', '.pyw', '.rb', '.sh', '.bash', '.pl', '.pm', '.r']);

type LangKind = 'c-like' | 'hash-comment' | 'unknown';

export function languageKind(extension: string): LangKind {
  const ext = extension.toLowerCase();
  if (C_LIKE.has(ext)) return 'c-like';
  if (HASH_COMMENT.has(ext)) return 'hash-comment';
  return 'unknown';
}

/** Characters that can legally precede a regex literal rather than division. */
const REGEX_PRECEDERS = new Set(['(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';', '+', '*', '%', '<', '>', '~', '^', 'return']);

/**
 * Mark every character of a line that lives inside a string literal, regex
 * literal, or comment — i.e. data rather than executable code.
 *
 * A vulnerability pattern matching inside one of those is almost always noise:
 * it is documentation, a test string, or — the case that started this — a
 * scanner rule whose own pattern text matches itself. `insecure-crypto` alone
 * produced 24 such hits on this repository.
 *
 * Line-scoped, so a template literal spanning lines is only masked on its first
 * line. That errs toward reporting, which is the safe direction.
 */
/** Lexer state that survives a line break. */
type CarryState = { blockComment: boolean; template: boolean };

/**
 * Mask one line, given the state carried in from the previous line, and report
 * the state to carry out. Block comments and template literals span lines, so
 * a purely line-local scan mislabels their continuation lines as code — which
 * is how prose inside a multi-line template string was being reported as a
 * weak-crypto finding.
 */
function maskLine(
  line: string,
  kind: LangKind,
  carry: CarryState,
  commentsOnly = false
): { mask: boolean[]; carry: CarryState } {
  const mask = new Array<boolean>(line.length).fill(false);
  const out: CarryState = { ...carry };

  // Escape hatch for diagnosing a suspected false negative: if a finding you
  // expect is missing, re-run with VULNSCAN_NO_MASK=1 to see whether masking
  // hid it.
  if (kind === 'unknown' || process.env.VULNSCAN_NO_MASK === '1') {
    return { mask, carry: { blockComment: false, template: false } };
  }

  /**
   * In comments-only mode, string and regex spans are still *tracked* — a `//`
   * inside a string is not a comment — but not masked. Secret detection needs
   * to read string contents, since that is where a credential lives, while
   * still ignoring prose that merely discusses one.
   */
  const paint = (from: number, to: number, isComment: boolean) => {
    if (commentsOnly && !isComment) return;
    for (let i = from; i <= to && i < line.length; i++) mask[i] = true;
  };

  let i = 0;
  let lastCode = '';

  // Continuation of a block comment opened on an earlier line.
  if (out.blockComment) {
    const close = line.indexOf('*/');
    const end = close === -1 ? line.length : close + 2;
    paint(0, end - 1, true);
    if (close === -1) return { mask, carry: out };
    out.blockComment = false;
    i = end;
  }

  // Continuation of a template literal opened on an earlier line.
  if (out.template) {
    let j = i;
    let closed = false;
    while (j < line.length) {
      if (line[j] === '\\') { j += 2; continue; }
      if (line[j] === '`') { closed = true; break; }
      j++;
    }
    const end = closed ? j : line.length - 1;
    paint(i, end, false);
    if (!closed) return { mask, carry: out };
    out.template = false;
    i = end + 1;
  }

  while (i < line.length) {
    const ch = line[i];
    const next = line[i + 1];

    if (kind === 'c-like' && ch === '/' && (next === '/' || next === '*')) {
      if (next === '/') {
        paint(i, line.length - 1, true);
        return { mask, carry: out };
      }
      const close = line.indexOf('*/', i + 2);
      if (close === -1) {
        paint(i, line.length - 1, true);
        out.blockComment = true;
        return { mask, carry: out };
      }
      paint(i, close + 1, true);
      i = close + 2;
      continue;
    }
    if (kind === 'hash-comment' && ch === '#') {
      paint(i, line.length - 1, true);
      return { mask, carry: out };
    }

    // String literals. A backtick that never closes on this line opens a
    // template literal that continues onto the next.
    if (ch === '"' || ch === "'" || ch === '`') {
      const quote = ch;
      let j = i + 1;
      let closed = false;
      while (j < line.length) {
        if (line[j] === '\\') { j += 2; continue; }
        if (line[j] === quote) { closed = true; break; }
        j++;
      }
      const end = closed ? j : line.length - 1;
      paint(i, end, false);
      if (!closed && quote === '`') {
        out.template = true;
        return { mask, carry: out };
      }
      i = end + 1;
      continue;
    }

    // Regex literals — only where a regex can legally start, so that division
    // is not mistaken for one.
    if (kind === 'c-like' && ch === '/' && (lastCode === '' || REGEX_PRECEDERS.has(lastCode))) {
      let j = i + 1;
      let inClass = false;
      let closed = false;
      while (j < line.length) {
        if (line[j] === '\\') { j += 2; continue; }
        if (line[j] === '[') inClass = true;
        else if (line[j] === ']') inClass = false;
        else if (line[j] === '/' && !inClass) { closed = true; break; }
        j++;
      }
      if (closed) {
        paint(i, j, false);
        i = j + 1;
        continue;
      }
    }

    if (!/\s/.test(ch)) lastCode = ch;
    i++;
  }

  return { mask, carry: out };
}

/**
 * Mask an entire file in one sequential pass, so multi-line constructs are
 * tracked correctly.
 */
export function maskFile(lines: string[], kind: LangKind, commentsOnly = false): boolean[][] {
  const masks: boolean[][] = new Array(lines.length);
  let carry: CarryState = { blockComment: false, template: false };
  for (let i = 0; i < lines.length; i++) {
    const res = maskLine(lines[i], kind, carry, commentsOnly);
    masks[i] = res.mask;
    carry = res.carry;
  }
  return masks;
}

/** Single-line masking. Retained for callers with no file context. */
export function maskDataSpans(line: string, kind: LangKind): boolean[] {
  return maskLine(line, kind, { blockComment: false, template: false }).mask;
}

/**
 * Masks depend only on the line and the language, but `applyPatternRule` is
 * called once per pattern — around 150 times per file across the rule set.
 * Recomputing per pattern cost 87% on top of the pattern phase; memoising on the
 * `lines` array (the same object for every pattern of a file) removes it.
 */
// Two variants per file: the full mask, and a comments-only mask for secret
// rules. Both are memoised, since ~150 patterns are applied per file.
const maskCache = new WeakMap<string[], Map<string, boolean[][]>>();

function masksFor(lines: string[], kind: LangKind, commentsOnly: boolean): boolean[][] {
  let perFile = maskCache.get(lines);
  if (!perFile) { perFile = new Map(); maskCache.set(lines, perFile); }

  const key = `${kind}:${commentsOnly}`;
  let masks = perFile.get(key);
  if (!masks) {
    // One sequential pass over the file — multi-line constructs need the
    // ordering, and the result is reused across every pattern.
    masks = maskFile(lines, kind, commentsOnly);
    perFile.set(key, masks);
  }
  return masks;
}

/**
 * Whether a match at the given position is data rather than code.
 *
 * Exported so rules that run their own matching loop — notably the custom-rule
 * DSL loader — get the same treatment as the built-in pattern path instead of
 * silently opting out of it.
 */
export function matchIsInData(
  filePath: string,
  lines: string[],
  lineIndex: number,
  column: number,
  length: number
): boolean {
  const kind = languageKind(pathExtname(filePath));
  if (kind === 'unknown') return false;
  const masks = masksFor(lines, kind, false);
  const mask = masks[lineIndex];
  if (!mask) return false;
  return matchIsData(mask, column, length);
}

/** True when the whole match sits inside masked data. */
function matchIsData(mask: boolean[], start: number, length: number): boolean {
  if (length === 0) return false;
  for (let i = start; i < start + length && i < mask.length; i++) {
    if (!mask[i]) return false;
  }
  return true;
}

// exec() in a loop only advances through `lastIndex`, which non-global regexes
// never update — the same match would be returned forever. Rule authors keep
// forgetting the /g flag, so normalize here rather than relying on discipline.
const globalRegexCache = new WeakMap<RegExp, RegExp>();

function asGlobal(regex: RegExp): RegExp {
  if (regex.global) return regex;
  let cached = globalRegexCache.get(regex);
  if (!cached) {
    cached = new RegExp(regex.source, `${regex.flags}g`);
    globalRegexCache.set(regex, cached);
  }
  return cached;
}

export function applyPatternRule(
  rule: Rule,
  filePath: string,
  lines: string[],
  pattern: PatternRule,
  varMap: Map<string, VariableAssignment[]>,
): Finding[] {
  const findings: Finding[] = [];
  const regex = asGlobal(pattern.regex);

  // Secret-detection rules must read string contents — that is where secrets
  // live — so they opt out of data masking. Everything else looks at code only.
  // Secret rules read string contents — that is where a credential lives — but
  // still skip comments, which are prose *about* credentials. Blanket-disabling
  // the mask made this rule match its own documentation.
  const kind = languageKind(pathExtname(filePath));
  const masks = kind === 'unknown' ? null : masksFor(lines, kind, pattern.matchInStrings === true);

  // A pattern can require the file to establish context before it applies.
  if (pattern.requiresFileContext) {
    const ctx = asGlobal(pattern.requiresFileContext);
    ctx.lastIndex = 0;
    if (!ctx.test(lines.join('\n'))) return findings;
  }

  for (let i = 0; i < lines.length; i++) {
    const lineText = lines[i];
    regex.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = regex.exec(lineText)) !== null) {
      // A zero-length match also leaves lastIndex parked — step over it.
      if (match[0] === '') {
        regex.lastIndex++;
        continue;
      }

      // Skip matches that live entirely inside a string, regex, or comment.
      if (masks && masks[i] && matchIsData(masks[i], match.index, match[0].length)) continue;

      // Skip when a recognised sanitizer neutralises the call on this line.
      if (pattern.neutralizedBy) {
        const neutralizer = asGlobal(pattern.neutralizedBy);
        neutralizer.lastIndex = 0;
        if (neutralizer.test(lineText)) continue;
      }

      // If this pattern requires a taint source, check context lines
      if (pattern.requiresTaintSource && pattern.contextLines) {
        const startLine = Math.max(0, i - pattern.contextLines);
        const endLine = Math.min(lines.length - 1, i + pattern.contextLines);
        let foundSource = false;

        for (let j = startLine; j <= endLine; j++) {
          if (j === i) continue;
          // Check if nearby lines have user input patterns
          if (/req\.(?:body|query|params|cookies|headers)|request\.(?:body|query|params)|ctx\.(?:request\.body|query|params)/.test(lines[j])) {
            foundSource = true;
            break;
          }
        }
        if (!foundSource) continue; // No taint source nearby — skip for confidence
      }

      findings.push({
        ruleId: rule.id,
        title: rule.name,
        severity: rule.severity,
        confidence: pattern.confidence,
        message: pattern.message,
        file: filePath,
        line: i + 1,
        column: match.index + 1,
        snippet: lineText.trim().substring(0, 150),
        recommendation: pattern.recommendation,
        fixExample: pattern.fixExample,
        cwe: rule.cwe,
        owasp: rule.owasp,
        references: [...rule.references],
        falsePositiveRisk: pattern.falsePositiveRisk,
        cvss: undefined, // Set by scanner
        mitreAttack: rule.mitreAttack,
      });
    }
  }

  return findings;
}
