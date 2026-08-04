/**
 * Detection coverage.
 *
 * Every vulnerability the reference fixture *declares* must actually be found,
 * at roughly the right place, classified as roughly the right thing.
 *
 * This exists because a weaker test nearly let a real regression through. It
 * asserted `ids.has('hardcoded-secrets')` — which stayed true when the AWS key
 * detection broke, because a second secret on the next line kept the rule
 * firing. "A rule fired somewhere" is not the same claim as "this vulnerability
 * was found", and only the second one is worth testing.
 */

const { test, describe, before } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');

const ROOT = path.resolve(__dirname, '..');
const FIXTURE = path.join(__dirname, 'vulnerable-app.js');
const { scan } = require(path.join(ROOT, 'dist/scanner.js'));

/**
 * Each entry is a vulnerability the fixture deliberately contains.
 * `within` allows for the finding landing on the vulnerable line rather than
 * the comment above it, without letting an unrelated finding satisfy the check.
 */
const EXPECTED = [
  { name: 'Hardcoded AWS access key', line: 11, within: 1, cwe: ['CWE-798'], mustMatch: /AWS/ },
  { name: 'Hardcoded database password', line: 12, within: 1, cwe: ['CWE-798'] },
  { name: 'SQL injection',             line: 21, within: 6, cwe: ['CWE-89'] },
  { name: 'Command injection',         line: 30, within: 6, cwe: ['CWE-78'] },
  { name: 'Cross-site scripting',      line: 39, within: 12, cwe: ['CWE-79'] },
  { name: 'Path traversal',            line: 55, within: 6, cwe: ['CWE-22'] },
  { name: 'Insecure crypto (MD5)',     line: 64, within: 5, cwe: ['CWE-327', 'CWE-328'] },
  { name: 'Weak JWT configuration',    line: 70, within: 5, cwe: ['CWE-347', 'CWE-345'] },
  { name: 'Code execution via eval',   line: 76, within: 5, cwe: ['CWE-95', 'CWE-94'] },
  { name: 'Open redirect',             line: 82, within: 5, cwe: ['CWE-601'] },
  { name: 'Prototype pollution',       line: 87, within: 6, cwe: ['CWE-915', 'CWE-1321', 'CWE-235'] },
  { name: 'SSRF',                      line: 94, within: 6, cwe: ['CWE-918'] },
];

let findings;

before(() => {
  const result = scan({ paths: [FIXTURE], deps: false, entropy: false, applyTriage: false });
  findings = result.findings;
});

describe('every declared vulnerability in the fixture is detected', () => {
  for (const exp of EXPECTED) {
    test(`${exp.name} (declared at line ${exp.line})`, () => {
      const nearby = findings.filter(f => Math.abs(f.line - exp.line) <= exp.within);
      assert.ok(nearby.length > 0,
        `nothing reported within ${exp.within} lines of ${exp.line}`);

      const matching = nearby.filter(f => exp.cwe.includes(f.cwe));
      assert.ok(matching.length > 0,
        `expected one of ${exp.cwe.join('/')} near line ${exp.line}, ` +
        `got ${nearby.map(f => `${f.cwe}(${f.ruleId}@${f.line})`).join(', ')}`);

      if (exp.mustMatch) {
        assert.ok(matching.some(f => exp.mustMatch.test(f.message)),
          `no finding near line ${exp.line} matched ${exp.mustMatch}; ` +
          `messages: ${matching.map(f => f.message).join(' | ')}`);
      }
    });
  }

  test('the fixture declares no vulnerability the suite forgot to assert', () => {
    // Keeps EXPECTED honest: adding a `// VULN:` marker to the fixture without
    // a matching entry here fails, rather than silently going unchecked.
    const src = fs.readFileSync(FIXTURE, 'utf-8').split('\n');
    const declared = [];
    src.forEach((line, i) => {
      if (/^\s*\/\/\s*VULN:/.test(line)) declared.push(i + 1);
    });

    const covered = new Set(EXPECTED.map(e => e.line));
    const unasserted = declared.filter(l => !covered.has(l));
    assert.deepStrictEqual(unasserted, [],
      `fixture declares vulnerabilities at lines ${unasserted.join(', ')} with no entry in EXPECTED`);
  });
});

describe('classification is specific, not generic', () => {
  test('taint findings are classified by the sink they reach', () => {
    // Previously every inter-procedural finding was stamped CWE-20 / Injection
    // regardless of whether it reached a database, a shell, or an HTTP client.
    const taint = findings.filter(f => f.ruleId === 'interproc-taint');
    assert.ok(taint.length >= 4, `expected several taint paths, got ${taint.length}`);

    const cwes = new Set(taint.map(f => f.cwe));
    assert.ok(cwes.size > 1,
      `all taint findings share one CWE (${[...cwes]}) — they are not being classified`);
    assert.ok(!cwes.has('CWE-20'),
      'CWE-20 is the unclassified fallback; every fixture sink should be recognised');
  });

  test('an SSRF is reported as SSRF, not as SQL injection', () => {
    const ssrf = findings.find(f => f.cwe === 'CWE-918');
    assert.ok(ssrf, 'the http.get flow should be reported');
    assert.strictEqual(ssrf.owasp, 'A10:2021-SSRF');
    assert.ok(!/^sql:/.test(ssrf.taintFlow?.sinks?.[0] || ''),
      'http.get must not be classified as a database sink');
  });

  test('OWASP categories are derived, not defaulted to Injection', () => {
    const categories = new Set(findings.map(f => f.owasp));
    assert.ok(categories.size >= 4,
      `expected a spread of OWASP categories, got ${[...categories].join(', ')}`);
  });

  test('every finding carries a resolvable CWE and OWASP category', () => {
    for (const f of findings) {
      assert.match(f.cwe, /^CWE-\d+$/, `${f.ruleId} has a malformed CWE`);
      assert.match(f.owasp, /^A\d{2}:2021-/, `${f.ruleId} has a malformed OWASP category`);
    }
  });
});

describe('summary integrity', () => {
  test('counts are numbers, never NaN', () => {
    const result = scan({ paths: [FIXTURE], deps: false, entropy: false, applyTriage: false });
    const { bySeverity, byConfidence, falsePositiveEstimate, totalFindings } = result.summary;

    for (const [k, v] of Object.entries(bySeverity)) {
      assert.ok(Number.isInteger(v), `bySeverity.${k} is ${v}`);
    }
    for (const [k, v] of Object.entries(byConfidence)) {
      assert.ok(Number.isInteger(v), `byConfidence.${k} is ${v}`);
    }
    for (const [k, v] of Object.entries(falsePositiveEstimate)) {
      assert.ok(Number.isInteger(v), `falsePositiveEstimate.${k} is ${v}`);
    }
    assert.strictEqual(totalFindings, result.findings.length);
  });

  test('a finding with no falsePositiveRisk does not corrupt the summary', () => {
    // Engine-generated findings have occasionally omitted this field; the
    // summary used to increment `undefined` into NaN and poison the report.
    const { buildSummaryForTest } = require(path.join(ROOT, 'dist/scanner.js'));
    if (typeof buildSummaryForTest !== 'function') return; // not exported: skip

    const summary = buildSummaryForTest([
      { severity: 'high', confidence: 'high', owasp: 'A03:2021-Injection', cwe: 'CWE-89' },
    ]);
    for (const v of Object.values(summary.falsePositiveEstimate)) {
      assert.ok(Number.isInteger(v), `falsePositiveEstimate contains ${v}`);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────

describe('dogfooding: the scanner is clean on its own source', () => {
  test('src/ produces no findings', { timeout: 120000 }, () => {
    // A security tool that cannot pass its own scan has no standing to report
    // on anyone else's code. This is a real assertion, not a formality: it went
    // 59 -> 10 -> 0 as rule precision improved, and it will fail loudly if a
    // rule regresses into noise or someone introduces a genuine vulnerability.
    const result = scan({
      paths: [path.join(ROOT, 'src')],
      deps: false,
      applyTriage: false,
    });

    const summary = result.findings
      .map(f => `${f.ruleId} ${path.relative(ROOT, f.file)}:${f.line} — ${f.snippet.trim().slice(0, 70)}`)
      .join('\n  ');

    assert.strictEqual(result.findings.length, 0,
      `the scanner should be clean on its own source, but reported:\n  ${summary}\n\n` +
      'If these are real, fix them. If they are noise, tighten the rule — do not ' +
      'raise this threshold.');
  });
});
