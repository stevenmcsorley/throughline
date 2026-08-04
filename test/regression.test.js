/**
 * Regression tests — one per bug that shipped.
 *
 * These run against dist/, i.e. exactly what a user installs, so a broken build
 * fails the suite rather than passing against TypeScript that never compiled.
 *
 *   npm test
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const ROOT = path.resolve(__dirname, '..');
const FIXTURES = path.join(__dirname, 'fixtures');

const { scan } = require(path.join(ROOT, 'dist/scanner.js'));
const { applyPatternRule } = require(path.join(ROOT, 'dist/engine/pattern-engine.js'));
const { diffFindings } = require(path.join(ROOT, 'dist/engine/semantic-diff.js'));
const triage = require(path.join(ROOT, 'dist/engine/triage.js'));
const { validateVerdict } = require(path.join(ROOT, 'dist/engine/ai-analyzer.js'));

/** Write `code` to a throwaway file, scan it, and hand the result to `check`. */
function withTempFile(code, check, filename = 'sample.js') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'throughline-case-'));
  try {
    const file = path.join(dir, filename);
    fs.writeFileSync(file, code);
    check(scanFixture(file));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** Scan helper that never touches the developer's real triage store. */
function scanFixture(files, options = {}) {
  return scan({
    paths: Array.isArray(files) ? files : [files],
    deps: false,
    entropy: false,
    applyTriage: false,
    ...options,
  });
}

// ─────────────────────────────────────────────────────────────────────────

describe('pattern engine: non-global regex must not spin forever', () => {
  test('applyPatternRule terminates on a regex declared without /g', () => {
    // Before the fix, exec() in a while loop never advanced lastIndex on a
    // non-global regex, so this call never returned and the array grew until
    // V8 died. A plain assertion is enough: if it regresses, the test hangs and
    // the runner's timeout kills it.
    const rule = {
      id: 'test-rule', name: 'Test', severity: 'high', confidence: 'high',
      cwe: 'CWE-1', owasp: 'A03:2021-Injection', references: [], extensions: ['*'],
    };
    const pattern = {
      regex: /privileged\s*:\s*true/i, // deliberately not global
      message: 'm', recommendation: 'r', confidence: 'high', falsePositiveRisk: 'low',
    };
    const lines = ['        privileged: true'];

    const findings = applyPatternRule(rule, 'pod.yaml', lines, pattern, new Map());
    assert.strictEqual(findings.length, 1, 'one match per occurrence, not infinite');
    assert.strictEqual(findings[0].line, 1);
  });

  test('a zero-length match does not stall the loop', () => {
    const rule = {
      id: 'z', name: 'Z', severity: 'low', confidence: 'low',
      cwe: 'CWE-1', owasp: 'A03:2021-Injection', references: [], extensions: ['*'],
    };
    const pattern = {
      regex: /x*/g, // matches empty string at every position
      message: 'm', recommendation: 'r', confidence: 'low', falsePositiveRisk: 'low',
    };
    const findings = applyPatternRule(rule, 'f.js', ['abc'], pattern, new Map());
    assert.ok(Array.isArray(findings), 'returns rather than hanging');
  });

  test('scanning a k8s manifest completes and reports its misconfigurations', () => {
    const started = Date.now();
    const result = scanFixture(path.join(FIXTURES, 'k8s-privileged.yaml'));
    const elapsed = Date.now() - started;

    assert.ok(elapsed < 10000, `should be fast, took ${elapsed}ms`);
    assert.ok(result.findings.length > 0, 'privileged pod must be flagged');
    const ids = new Set(result.findings.map(f => f.ruleId));
    assert.ok(ids.has('k8s-security'), `expected k8s-security, got ${[...ids]}`);
  });
});

// ─────────────────────────────────────────────────────────────────────────

describe('filters apply to findings, and compose', () => {
  const app = path.join(__dirname, 'vulnerable-app.js');

  test('baseline produces findings across several severities', () => {
    const result = scanFixture(app);
    const severities = new Set(result.findings.map(f => f.severity));
    assert.ok(result.findings.length > 5, 'fixture should produce findings');
    assert.ok(severities.size > 1, 'fixture should span multiple severities');
  });

  test('--severity filters findings, not rule declarations', () => {
    const result = scanFixture(app, { severity: 'critical' });
    const offenders = result.findings.filter(f => f.severity !== 'critical');
    assert.deepStrictEqual(offenders.map(f => `${f.ruleId}:${f.severity}`), [],
      'only critical findings may survive a critical threshold');
  });

  test('--confidence filters findings', () => {
    const result = scanFixture(app, { confidence: 'certain' });
    const offenders = result.findings.filter(f => f.confidence !== 'certain');
    assert.deepStrictEqual(offenders.map(f => f.ruleId), []);
  });

  test('--rules restricts output, including taint-engine findings', () => {
    const result = scanFixture(app, { rules: ['sql-injection'] });
    assert.ok(result.findings.length > 0, 'sql-injection should match this fixture');
    for (const f of result.findings) {
      const isSql = f.ruleId === 'sql-injection' ||
        f.ruleId === 'cpg-precise-sql' || f.ruleId === 'cpg-direct-sql' ||
        (f.ruleId === 'interproc-taint' && /^sql:/.test(f.taintFlow?.sinks?.[0] || ''));
      assert.ok(isSql, `${f.ruleId} is not a SQL finding but survived --rules sql-injection`);
    }
  });

  test('--rules and --severity compose instead of overwriting', () => {
    const result = scanFixture(app, { rules: ['sql-injection'], severity: 'critical' });
    for (const f of result.findings) {
      assert.strictEqual(f.severity, 'critical');
      assert.ok(/sql/.test(f.ruleId) || f.ruleId === 'interproc-taint',
        `${f.ruleId} leaked past the composed filter`);
    }
  });

  test('an unselected rule cannot appear', () => {
    const result = scanFixture(app, { rules: ['sql-injection'] });
    assert.ok(!result.findings.some(f => f.ruleId === 'hardcoded-secrets'),
      'hardcoded-secrets must not appear when only sql-injection was requested');
  });

  test('an invalid threshold is rejected loudly', () => {
    assert.throws(() => scanFixture(app, { severity: 'bogus' }), /Invalid severity/);
    assert.throws(() => scanFixture(app, { confidence: 'nope' }), /Invalid confidence/);
  });
});

// ─────────────────────────────────────────────────────────────────────────

describe('detection quality', () => {
  test('the vulnerable fixture trips the expected engines', () => {
    const result = scanFixture(path.join(__dirname, 'vulnerable-app.js'));
    const ids = new Set(result.findings.map(f => f.ruleId));

    assert.ok(ids.has('hardcoded-secrets'), 'should find the hardcoded AWS key');
    assert.ok([...ids].some(id => /sql/.test(id)), 'should find SQL injection');
    assert.ok([...ids].some(id => /command|exec/.test(id)), 'should find command injection');
  });

  test('safe idiomatic code produces no critical findings', () => {
    const result = scanFixture(path.join(FIXTURES, 'safe-app.js'));
    const critical = result.findings.filter(f => f.severity === 'critical');
    assert.deepStrictEqual(
      critical.map(f => `${f.ruleId}@${f.line}: ${f.snippet.trim().slice(0, 60)}`), [],
      'parameterized queries, execFile, textContent and allowlists must not be critical'
    );
  });

  test('findings carry the metadata downstream consumers rely on', () => {
    const result = scanFixture(path.join(__dirname, 'vulnerable-app.js'));
    for (const f of result.findings) {
      assert.match(f.cwe, /^CWE-\d+$/, `bad cwe on ${f.ruleId}`);
      assert.ok(f.severity && f.confidence, `missing severity/confidence on ${f.ruleId}`);
      assert.ok(typeof f.line === 'number' && f.line > 0, `bad line on ${f.ruleId}`);
      assert.ok(['low', 'medium', 'high'].includes(f.falsePositiveRisk),
        `bad falsePositiveRisk on ${f.ruleId}: ${f.falsePositiveRisk}`);
    }
  });

  test('summary counts agree with the findings list', () => {
    const result = scanFixture(path.join(__dirname, 'vulnerable-app.js'));
    const summed = Object.values(result.summary.bySeverity).reduce((a, b) => a + b, 0);
    assert.strictEqual(result.summary.totalFindings, result.findings.length);
    assert.strictEqual(summed, result.findings.length, 'bySeverity must account for every finding');
  });

  test('no identical finding is emitted twice', () => {
    // Two different sub-issues from one rule on one line are legitimate (e.g.
    // insecure-jwt reporting both a literal secret and a weak algorithm), so
    // identity includes the message.
    const result = scanFixture(path.join(__dirname, 'vulnerable-app.js'));
    const keys = result.findings.map(f => `${f.file}:${f.line}:${f.ruleId}:${f.message}`);
    assert.strictEqual(new Set(keys).size, keys.length, 'exact duplicate finding emitted');
  });
});

// ─────────────────────────────────────────────────────────────────────────

describe('precision: parameterized queries are not injection', () => {
  test('a literal query with bound parameters is not reported', () => {
    const result = scanFixture(path.join(FIXTURES, 'safe-app.js'));
    const sql = result.findings.filter(f => /sql/.test(f.ruleId));
    assert.deepStrictEqual(sql.map(f => `${f.ruleId}@${f.line}`), [],
      'db.query("… = ?", [taint]) is the recommended form and must stay silent');
  });

  test('string-concatenated SQL is still reported', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'throughline-sqlfp-'));
    try {
      const file = path.join(dir, 'unsafe.js');
      fs.writeFileSync(file,
        'function h(db, req) { return db.query("SELECT * FROM u WHERE id = " + req.params.id); }\n');
      const result = scanFixture(file);
      assert.ok(result.findings.some(f => /sql/.test(f.ruleId)),
        'concatenated SQL must still be caught');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a template literal with interpolation is still reported', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'throughline-sqltpl-'));
    try {
      const file = path.join(dir, 'unsafe2.js');
      fs.writeFileSync(file,
        'function h(db, req) { return db.query(`SELECT * FROM u WHERE id = ${req.params.id}`); }\n');
      const result = scanFixture(file);
      assert.ok(result.findings.some(f => /sql/.test(f.ruleId)),
        'interpolated template SQL must still be caught');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a non-shell exec with a tainted argument is not reported', () => {
    // execFile/spawn hand argv to the OS directly, so shell metacharacters in
    // an argument are inert data. This is the recommended fix for exec().
    withTempFile(
      'const { execFile } = require("child_process");\n' +
      'function ping(req, cb) { execFile("ping", ["-c", "1", req.query.host], cb); }\n',
      result => assert.deepStrictEqual(
        result.findings.map(f => f.ruleId), [],
        'execFile with a fixed binary and array args is safe'
      )
    );
  });

  test('spawn with array arguments is not reported', () => {
    withTempFile(
      'const { spawn } = require("child_process");\n' +
      'function ls(req) { return spawn("ls", ["-la", req.query.dir]); }\n',
      result => assert.deepStrictEqual(result.findings.map(f => f.ruleId), [])
    );
  });

  test('exec with a concatenated command is still reported', () => {
    withTempFile(
      'const { exec } = require("child_process");\n' +
      'function ping(req, cb) { exec("ping " + req.query.host, cb); }\n',
      result => assert.ok(result.findings.length > 0, 'shell concatenation must be caught')
    );
  });

  test('shell:true voids the execFile exemption', () => {
    withTempFile(
      'const { execFile } = require("child_process");\n' +
      'function s(req, cb) { execFile("sh", ["-c", "ping " + req.query.h], { shell: true }, cb); }\n',
      result => assert.ok(result.findings.length > 0,
        'shell:true puts a shell back in the path')
    );
  });

  test('a tainted program name is still reported', () => {
    // Argument injection is contained by execFile; choosing the binary is not.
    withTempFile(
      'const { execFile } = require("child_process");\n' +
      'function run(req, cb) { execFile(req.query.cmd, ["--version"], cb); }\n',
      result => assert.ok(result.findings.length > 0,
        'the attacker choosing which binary runs is still a vulnerability')
    );
  });

  test('a mix of safe and unsafe queries in one function is still reported', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'throughline-sqlmix-'));
    try {
      const file = path.join(dir, 'mixed.js');
      fs.writeFileSync(file,
        'function h(db, req) {\n' +
        '  db.query("SELECT 1 WHERE id = ?", [req.params.id]);\n' +
        '  return db.query("SELECT * FROM u WHERE n = " + req.params.n);\n' +
        '}\n');
      const result = scanFixture(file);
      assert.ok(result.findings.some(f => /sql/.test(f.ruleId)),
        'one safe call must not exempt an unsafe one in the same function');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────

describe('precision: patterns match code, not prose', () => {
  test('a vulnerability named in a comment is not a finding', () => {
    withTempFile(
      '// This function used to use an md5 hash, which was insecure.\n' +
      'const x = 1;\n',
      result => assert.deepStrictEqual(result.findings.map(f => f.ruleId), [],
        'a comment describing a vulnerability is documentation, not a vulnerability')
    );
  });

  test('the real call is still found when a comment mentions it too', () => {
    withTempFile(
      '// VULN: uses md5\n' +
      'const crypto = require("crypto");\n' +
      'const h = crypto.createHash("md5").update(d).digest("hex");\n',
      result => {
        const crypt = result.findings.filter(f => f.ruleId === 'insecure-crypto');
        assert.strictEqual(crypt.length, 1, 'exactly the real call, not the comment too');
        assert.strictEqual(crypt[0].line, 3);
      }
    );
  });

  test("a scanner rule's own pattern text does not match itself", () => {
    // This is what produced 24 self-inflicted findings in src/rules/crypto.
    withTempFile(
      'const rules = [\n' +
      '  { regex: /\\b(?:md5|md4)\\b/g, message: "MD5/MD4 hash used" },\n' +
      '];\nmodule.exports = { rules };\n',
      result => assert.deepStrictEqual(result.findings.map(f => f.ruleId), [],
        'pattern text inside a regex literal or string is data, not a weak hash call')
    );
  });

  test('secrets inside string literals are still found', () => {
    // Secret rules opt out of masking — the credential *is* the string content.
    // Getting this wrong silently stops reporting hardcoded credentials.
    withTempFile(
      'const AWS_ACCESS_KEY = "AKIA1234567890ABCDEF";\n',
      result => {
        const secrets = result.findings.filter(f => f.ruleId === 'hardcoded-secrets');
        assert.ok(secrets.length > 0, 'an AWS key in a string literal must be reported');
        assert.match(secrets[0].message, /AWS/);
      }
    );
  });

  test('the bundled vulnerable fixture still reports its hardcoded AWS key', () => {
    const result = scanFixture(path.join(__dirname, 'vulnerable-app.js'));
    assert.ok(
      result.findings.some(f => f.ruleId === 'hardcoded-secrets' && /AWS/.test(f.message)),
      'masking must not hide credentials in the reference fixture'
    );
  });

  test('unknown file types are scanned verbatim', () => {
    // YAML has different quoting semantics, so masking is not applied there;
    // k8s misconfigurations must keep firing.
    const result = scanFixture(path.join(FIXTURES, 'k8s-privileged.yaml'));
    assert.ok(result.findings.length >= 5,
      `expected the k8s misconfigurations, got ${result.findings.length}`);
  });

  test('THROUGHLINE_NO_MASK=1 restores unmasked matching', () => {
    const prev = process.env.THROUGHLINE_NO_MASK;
    process.env.THROUGHLINE_NO_MASK = '1';
    try {
      withTempFile(
        '// this mentions md5 in a comment\nconst x = 1;\n',
        result => assert.ok(result.findings.length > 0,
          'the escape hatch should surface what masking hides, for diagnosis')
      );
    } finally {
      if (prev === undefined) delete process.env.THROUGHLINE_NO_MASK;
      else process.env.THROUGHLINE_NO_MASK = prev;
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────

describe('semantic diff', () => {
  const mk = (ruleId, line, severity = 'high') => ({
    ruleId, title: ruleId, severity, confidence: 'high', message: '',
    file: 'src/a.js', line, column: 0, snippet: '', recommendation: '',
    cwe: 'CWE-89', owasp: 'A03:2021-Injection', references: [], falsePositiveRisk: 'low',
  });

  test('an unchanged finding is persisted, not also resolved', () => {
    // The matched set was never populated, so every before-finding was reported
    // resolved even when it had just been matched as persisted.
    const before = [mk('sql-injection', 10)];
    const after = [mk('sql-injection', 10)];
    const diff = diffFindings(before, after);

    assert.strictEqual(diff.persisted.length, 1, 'should persist');
    assert.strictEqual(diff.resolved.length, 0, 'must not also be resolved');
    assert.strictEqual(diff.introduced.length, 0);
  });

  test('a genuinely fixed finding is resolved', () => {
    const diff = diffFindings([mk('sql-injection', 10)], []);
    assert.strictEqual(diff.resolved.length, 1);
    assert.strictEqual(diff.introduced.length, 0);
  });

  test('a new finding is introduced', () => {
    const diff = diffFindings([], [mk('xss', 5)]);
    assert.strictEqual(diff.introduced.length, 1);
    assert.strictEqual(diff.resolved.length, 0);
  });

  test('two findings in one file do not double-claim one match', () => {
    const before = [mk('sql-injection', 10), mk('sql-injection', 100)];
    const after = [mk('sql-injection', 10)];
    const diff = diffFindings(before, after);

    assert.strictEqual(diff.persisted.length, 1, 'line 10 persists');
    assert.strictEqual(diff.resolved.length, 1, 'line 100 was fixed');
  });

  test('a severity increase is reported as worsened', () => {
    const diff = diffFindings([mk('xss', 10, 'medium')], [mk('xss', 10, 'critical')]);
    assert.strictEqual(diff.worsened.length, 1);
    assert.strictEqual(diff.worsened[0].previousSeverity, 'medium');
  });
});

// ─────────────────────────────────────────────────────────────────────────

describe('triage store', () => {
  function inTempStore(fn) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'throughline-triage-'));
    try { return fn(dir); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  }

  const finding = {
    ruleId: 'sql-injection', file: 'src/a.js', line: 42,
    snippet: 'db.query("SELECT " + req.params.id)', severity: 'critical',
  };

  test('codeHash ignores reformatting but not edits', () => {
    const a = triage.codeHashOf('db.query( x )');
    const b = triage.codeHashOf('db.query(   x   )');
    const c = triage.codeHashOf('db.query( y )');
    assert.strictEqual(a, b, 'whitespace-only change must not invalidate a verdict');
    assert.notStrictEqual(a, c, 'a real edit must invalidate a verdict');
  });

  test('a fresh false-positive verdict suppresses the finding', () => inTempStore(dir => {
    triage.recordVerdicts([{
      findingKey: triage.findingKey(finding),
      codeHash: triage.codeHashOf(finding.snippet),
      isRealVulnerability: false,
      reviewConfidence: 'high', analysis: 'Test fixture, not shipped code.',
      triagedBy: 'test', triagedAt: new Date().toISOString(),
    }], dir);

    const store = triage.loadTriageStore(dir);
    const { findings, outcome } = triage.applyTriage([{ ...finding }], store);
    assert.strictEqual(findings.length, 0, 'confirmed false positive is hidden');
    assert.strictEqual(outcome.suppressed, 1, 'suppression must be counted, never silent');
  }));

  test('a verdict whose code changed is ignored and reported stale', () => inTempStore(dir => {
    triage.recordVerdicts([{
      findingKey: triage.findingKey(finding),
      codeHash: 'staleeeeeeeeeeee',
      isRealVulnerability: false,
      reviewConfidence: 'high', analysis: 'Reviewed against different code.',
      triagedBy: 'test', triagedAt: new Date().toISOString(),
    }], dir);

    const store = triage.loadTriageStore(dir);
    const { findings, outcome } = triage.applyTriage([{ ...finding }], store);
    assert.strictEqual(findings.length, 1, 'a dismissal must not outlive the code it described');
    assert.strictEqual(outcome.stale, 1);
    assert.strictEqual(outcome.suppressed, 0);
  }));

  test('a verdict can correct severity', () => inTempStore(dir => {
    triage.recordVerdicts([{
      findingKey: triage.findingKey(finding),
      codeHash: triage.codeHashOf(finding.snippet),
      isRealVulnerability: true, adjustedSeverity: 'low',
      reviewConfidence: 'high', analysis: 'Reachable only from an admin-only path.',
      triagedBy: 'test', triagedAt: new Date().toISOString(),
    }], dir);

    const store = triage.loadTriageStore(dir);
    const { findings, outcome } = triage.applyTriage([{ ...finding }], store);
    assert.strictEqual(findings[0].severity, 'low');
    assert.strictEqual(outcome.severityAdjusted, 1);
  }));

  test('a corrupt store degrades to empty rather than failing the scan', () => inTempStore(dir => {
    fs.mkdirSync(path.join(dir, '.throughline-cache'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.throughline-cache', 'triage.json'), '{ not json', 'utf-8');
    const store = triage.loadTriageStore(dir);
    assert.deepStrictEqual(store.verdicts, {});
  }));
});

// ─────────────────────────────────────────────────────────────────────────

describe('verdict validation rejects rather than defaults', () => {
  const now = new Date().toISOString();
  const base = {
    findingKey: 'sql-injection:src/a.js:1', codeHash: 'abc123',
    isRealVulnerability: false, analysis: 'A sufficiently detailed explanation.',
  };

  test('a well-formed verdict is accepted', () => {
    const r = validateVerdict({ ...base }, 'test', now);
    assert.ok(r.ok, r.ok ? '' : r.error);
  });

  test('a missing codeHash is rejected', () => {
    const r = validateVerdict({ ...base, codeHash: undefined }, 'test', now);
    assert.ok(!r.ok && /codeHash/.test(r.error));
  });

  test('an empty analysis is rejected — silence must not become a dismissal', () => {
    const r = validateVerdict({ ...base, analysis: 'no' }, 'test', now);
    assert.ok(!r.ok && /analysis/.test(r.error));
  });

  test('a non-boolean verdict is rejected', () => {
    const r = validateVerdict({ ...base, isRealVulnerability: 'maybe' }, 'test', now);
    assert.ok(!r.ok && /isRealVulnerability/.test(r.error));
  });

  test('an invalid adjustedSeverity is rejected', () => {
    const r = validateVerdict({ ...base, adjustedSeverity: 'catastrophic' }, 'test', now);
    assert.ok(!r.ok && /adjustedSeverity/.test(r.error));
  });
});

// ─────────────────────────────────────────────────────────────────────────

describe('precision: multi-line constructs', () => {
  test('prose inside a multi-line template literal is not a finding', () => {
    // Masking used to be line-scoped, so continuation lines of a template
    // literal were treated as code — reporting documentation as vulnerabilities.
    withTempFile(
      'const INSTRUCTIONS = `\n' +
      'Consider whether this uses an md5 hash or a DES cipher.\n' +
      'Also check for eval() usage in the request handler.\n' +
      '`;\nmodule.exports = { INSTRUCTIONS };\n',
      result => assert.deepStrictEqual(result.findings.map(f => `${f.ruleId}@${f.line}`), [],
        'text inside a template literal is data, not code')
    );
  });

  test('code after a multi-line template literal is still scanned', () => {
    // The carried state must be cleared when the literal closes, or everything
    // after it would be silently exempt.
    withTempFile(
      'const T = `\nsome text\n`;\n' +
      'const crypto = require("crypto");\n' +
      'const h = crypto.createHash("md5").update(d).digest("hex");\n',
      result => {
        const crypt = result.findings.filter(f => f.ruleId === 'insecure-crypto');
        assert.strictEqual(crypt.length, 1, 'the real call after the literal must still report');
        assert.strictEqual(crypt[0].line, 5);
      }
    );
  });

  test('prose inside a multi-line block comment is not a finding', () => {
    withTempFile(
      '/*\n * This routine once used an md5 hash.\n * It also called eval() on input.\n */\n' +
      'const x = 1;\n',
      result => assert.deepStrictEqual(result.findings.map(f => f.ruleId), [])
    );
  });

  test('code after a block comment closes is still scanned', () => {
    withTempFile(
      '/*\n * historical note\n */\n' +
      'const crypto = require("crypto");\n' +
      'const h = crypto.createHash("md5").update(d).digest("hex");\n',
      result => assert.ok(result.findings.some(f => f.ruleId === 'insecure-crypto'),
        'the block comment must not swallow the rest of the file')
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────

describe('precision: false positives found by scanning a real repository', () => {
  // Every case here was reported against a real production codebase and was
  // wrong. Scanning real code found classes of noise that purpose-built
  // fixtures never would.

  test('the ordinary word "seed" is not the SEED cipher', () => {
    // SEED is a real Korean block cipher, but matched case-insensitively it
    // fired on `from .seed import seed`, `def seed(db)`, and even
    // `seed = random.SystemRandom()` — the *secure* RNG. Eight false positives
    // in one repository.
    withTempFile(
      'from .seed import seed\n\ndef seed(db):\n    pass\n',
      result => assert.deepStrictEqual(result.findings.map(f => f.ruleId), []),
      'app.py'
    );
  });

  test('a crypto file still reports the real SEED cipher', () => {
    withTempFile(
      'from Crypto.Cipher import SEED\ncipher = SEED.new(key)\n',
      result => assert.ok(result.findings.some(f => f.ruleId === 'insecure-crypto'),
        'uppercase SEED in a crypto context is a real finding'),
      'crypto_thing.py'
    );
  });

  test('fetch credentials option is not a hardcoded secret', () => {
    withTempFile(
      'const r = await fetch(path, { ...init, headers, credentials: "same-origin" });\n',
      result => assert.deepStrictEqual(result.findings.map(f => f.ruleId), [],
        'credentials: "same-origin" is a request option, not a credential')
    );
  });

  test('a connection string using a variable is not a hardcoded credential', () => {
    // `postgres://user:${DB_PASSWORD}@host` is the correct form — the secret is
    // injected at runtime. Flagging it is precisely backwards.
    withTempFile(
      'const url = "postgresql://umami:${UMAMI_DB_PASSWORD}@umami-db:5432/umami";\n',
      result => assert.deepStrictEqual(result.findings.map(f => f.ruleId), [])
    );
  });

  test('a literal credential in a connection string is still reported', () => {
    withTempFile(
      'const url = "postgresql://umami:hunter2plaintext@umami-db:5432/umami";\n',
      result => assert.ok(result.findings.some(f => f.ruleId === 'hardcoded-secrets'),
        'an actual embedded password must still be caught')
    );
  });

  test('a hardened config is not reported for clickjacking', () => {
    // The rule matched the *presence* of X-Frame-Options and frame-ancestors,
    // emitting "good practice" as a security finding. A correctly hardened
    // nginx config produced a finding for being hardened.
    withTempFile(
      'add_header X-Frame-Options "DENY" always;\n' +
      'add_header Content-Security-Policy "default-src \'self\'; frame-ancestors \'none\'" always;\n',
      result => assert.deepStrictEqual(result.findings.map(f => f.ruleId), []),
      'nginx.conf'
    );
  });

  test('a config with security headers but no frame protection is reported', () => {
    withTempFile(
      'add_header Content-Security-Policy "default-src \'self\'" always;\n' +
      'add_header Referrer-Policy "strict-origin" always;\n',
      result => assert.ok(result.findings.some(f => f.ruleId === 'clickjacking'),
        'missing frame protection is the actual risk this rule exists for'),
      'nginx.conf'
    );
  });

  test('a config that sets no security headers at all is not reported', () => {
    // Absence of frame protection only means something where headers are
    // configured; an arbitrary file is not a web server config.
    withTempFile(
      'server {\n  listen 80;\n  root /var/www;\n}\n',
      result => assert.ok(!result.findings.some(f => f.ruleId === 'clickjacking')),
      'nginx.conf'
    );
  });

  test('taint from an environment variable is not reported as certain', () => {
    // Environment variables are operator-supplied configuration. Worth
    // surfacing, but ranking them above genuine attacker-input findings is
    // backwards.
    withTempFile(
      'import os, urllib.request\n' +
      '_URL = os.environ.get("INGEST_URL", "")\n' +
      'def send(payload):\n' +
      '    return urllib.request.Request(_URL, data=payload)\n',
      result => {
        const env = result.findings.filter(f => /ssrf/.test(f.ruleId));
        for (const f of env) {
          assert.notStrictEqual(f.confidence, 'certain',
            'an env-sourced flow must not outrank attacker-controlled input');
        }
      },
      'sender.py'
    );
  });

  test('every finding carries a valid confidence value', () => {
    // Two patterns used `confidence: 'info'`, which is not in the Confidence
    // union. Such findings were silently dropped by any --confidence threshold.
    const valid = new Set(['certain', 'high', 'medium', 'low']);
    const result = scanFixture(path.join(__dirname, 'vulnerable-app.js'));
    for (const f of result.findings) {
      assert.ok(valid.has(f.confidence), `${f.ruleId} has confidence "${f.confidence}"`);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────

describe('explicitly requested paths are always scanned', () => {
  // Found by CI on Linux, not reachable locally on Windows. The default exclude
  // list contains `tmp`, `temp`, `out`, `bin`, `target` and `env`, and those
  // patterns were tested against the absolute path — so `throughline /tmp/project`
  // scanned nothing at all, silently. On Windows the temp directory is
  // `...\AppData\Local\Temp\...`, which did not match the lowercase `tmp`, so
  // every local run looked fine.
  const VULN = 'const cp = require("child_process");\n' +
    'function h(req) { cp.exec("ls " + req.query.d); }\n';

  function inTree(build, check) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'throughline-excl-'));
    try {
      check(build(root), root);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  }

  for (const dirName of ['tmp', 'temp', 'out', 'bin', 'target', 'env', 'build', 'dist']) {
    test(`a project inside a directory named "${dirName}" is scanned when named directly`, () => {
      inTree(
        root => {
          const dir = path.join(root, dirName);
          fs.mkdirSync(dir);
          fs.writeFileSync(path.join(dir, 'app.js'), VULN);
          return dir;
        },
        dir => {
          const result = scanFixture(dir);
          assert.strictEqual(result.filesScanned, 1,
            `naming ${dirName}/ explicitly must scan it, not silently skip it`);
          assert.ok(result.findings.length > 0, 'and must report its vulnerability');
        }
      );
    });
  }

  test('an explicitly named file inside an excluded directory is scanned', () => {
    inTree(
      root => {
        const dir = path.join(root, 'node_modules');
        fs.mkdirSync(dir);
        const file = path.join(dir, 'app.js');
        fs.writeFileSync(file, VULN);
        return file;
      },
      file => {
        const result = scanFixture(file);
        assert.strictEqual(result.filesScanned, 1,
          'asking for one specific file and getting silence is never right');
      }
    );
  });

  test('an excluded directory found during a walk is still pruned', () => {
    // The exemption must apply only to the root the user named, or the default
    // exclude list stops working entirely.
    inTree(
      root => {
        const nested = path.join(root, 'node_modules');
        fs.mkdirSync(nested);
        fs.writeFileSync(path.join(nested, 'dep.js'), VULN);
        fs.writeFileSync(path.join(root, 'main.js'), 'const x = 1;\n');
        return root;
      },
      root => {
        const result = scanFixture(root);
        assert.strictEqual(result.filesScanned, 1, 'node_modules/ must still be pruned');
        assert.ok(!result.findings.some(f => f.file.includes('node_modules')));
      }
    );
  });
});
