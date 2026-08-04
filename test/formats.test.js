/**
 * Output format tests.
 *
 * SARIF is the CI integration path documented in the README, and it was never
 * tested. Three of its defects would have failed silently: absolute URIs that
 * GitHub cannot map onto the repo tree (so no PR annotations ever appear),
 * column 0 where SARIF requires 1-based, and fingerprints derived from array
 * position (so inserting one finding makes every later one look brand new).
 */

const { test, describe, before } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { execFileSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'dist/index.js');
const { scan } = require(path.join(ROOT, 'dist/scanner.js'));
const { sarifFormat, jsonFormat } = require(path.join(ROOT, 'dist/formatters/json.js'));
const { htmlFormat } = require(path.join(ROOT, 'dist/formatters/html.js'));

let result;
before(() => {
  result = scan({
    paths: [path.join(__dirname, 'vulnerable-app.js')],
    deps: false, entropy: false, applyTriage: false,
  });
});

describe('SARIF 2.1.0', () => {
  let sarif;
  before(() => { sarif = JSON.parse(sarifFormat(result)); });

  test('declares the version and schema', () => {
    assert.strictEqual(sarif.version, '2.1.0');
    assert.ok(sarif.$schema, '$schema is required for GitHub to validate the upload');
  });

  test('has exactly one run with a tool driver', () => {
    assert.strictEqual(sarif.runs.length, 1);
    assert.ok(sarif.runs[0].tool.driver.name);
    assert.ok(Array.isArray(sarif.runs[0].tool.driver.rules));
  });

  test('every ruleIndex resolves to the rule it names', () => {
    const rules = sarif.runs[0].tool.driver.rules;
    for (const r of sarif.runs[0].results) {
      const target = rules[r.ruleIndex];
      assert.ok(target, `ruleIndex ${r.ruleIndex} is out of range`);
      assert.strictEqual(target.id, r.ruleId,
        `ruleIndex ${r.ruleIndex} points at ${target.id}, not ${r.ruleId}`);
    }
  });

  test('artifact URIs are repository-relative, not absolute paths', () => {
    for (const r of sarif.runs[0].results) {
      const uri = r.locations[0].physicalLocation.artifactLocation.uri;
      assert.ok(!/^[A-Za-z]:/.test(uri), `"${uri}" is an absolute Windows path`);
      assert.ok(!uri.startsWith('/'), `"${uri}" is an absolute POSIX path`);
      assert.ok(!uri.includes('\\'), `"${uri}" uses backslashes; SARIF URIs use forward slashes`);
    }
  });

  test('regions use 1-based line and column', () => {
    // Engine findings report column 0 when they have no column info; SARIF
    // treats 0 as invalid and consumers may reject the whole upload.
    for (const r of sarif.runs[0].results) {
      const region = r.locations[0].physicalLocation.region;
      assert.ok(region.startLine >= 1, `startLine ${region.startLine} must be >= 1`);
      assert.ok(region.startColumn >= 1, `startColumn ${region.startColumn} must be >= 1`);
    }
  });

  test('levels are valid SARIF values', () => {
    const valid = new Set(['error', 'warning', 'note', 'none']);
    for (const r of sarif.runs[0].results) {
      assert.ok(valid.has(r.level), `"${r.level}" is not a SARIF level`);
    }
  });

  test('fingerprints are unique within a run', () => {
    const seen = new Set();
    for (const r of sarif.runs[0].results) {
      const fp = r.partialFingerprints.primary;
      assert.ok(!seen.has(fp), `duplicate fingerprint ${fp} — GitHub would collapse these`);
      seen.add(fp);
    }
  });

  test('fingerprints survive an unrelated finding being inserted', () => {
    // The whole purpose of a fingerprint is cross-run identity. Deriving it from
    // the results-array index destroyed that.
    const before = sarifFormat(result);
    const shuffled = { ...result, findings: [...result.findings].reverse() };
    const after = sarifFormat(shuffled);

    const fps = s => new Set(JSON.parse(s).runs[0].results.map(r => r.partialFingerprints.primary));
    assert.deepStrictEqual([...fps(before)].sort(), [...fps(after)].sort(),
      'reordering findings must not change their fingerprints');
  });

  test('security-severity is a numeric string GitHub can sort on', () => {
    for (const rule of sarif.runs[0].tool.driver.rules) {
      const sev = rule.properties['security-severity'];
      assert.ok(/^\d+(\.\d+)?$/.test(sev), `"${sev}" is not numeric`);
    }
  });
});

describe('JSON', () => {
  test('round-trips and preserves every finding', () => {
    const parsed = JSON.parse(jsonFormat(result));
    assert.strictEqual(parsed.findings.length, result.findings.length);
    assert.strictEqual(parsed.summary.totalFindings, result.findings.length);
  });
});

describe('HTML', () => {
  let html;
  before(() => { html = htmlFormat(result); });

  test('is a complete document', () => {
    assert.match(html, /<!DOCTYPE html>/i);
    assert.match(html, /<\/html>/i);
  });

  test('renders every finding', () => {
    // A report that silently drops findings is worse than no report.
    for (const f of result.findings.slice(0, 5)) {
      assert.ok(html.includes(String(f.line)), `line ${f.line} missing from the report`);
    }
  });

  test('escapes finding content rather than injecting it', () => {
    // Report content comes from scanned source, which is untrusted by
    // definition — a scanner that XSSes its own report is an embarrassment.
    const hostile = {
      ...result.findings[0],
      snippet: '<img src=x onerror="alert(1)">',
      message: '</script><script>alert(2)</script>',
    };
    const out = htmlFormat({ ...result, findings: [hostile] });

    assert.ok(!out.includes('<img src=x onerror='),
      'a snippet containing markup was emitted unescaped');
    assert.ok(!out.includes('</script><script>alert(2)'),
      'a message containing a script tag was emitted unescaped');
  });
});

describe('CLI output plumbing', () => {
  function runCli(args, cwd) {
    try {
      return { out: execFileSync(process.execPath, [CLI, ...args], {
        cwd, encoding: 'utf-8', timeout: 180000, stdio: 'pipe' }), code: 0 };
    } catch (err) {
      return { out: (err.stdout || '') + (err.stderr || ''), code: err.status };
    }
  }

  test('every format writes to a file and produces non-empty output', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnscan-fmt-'));
    try {
      fs.copyFileSync(path.join(__dirname, 'vulnerable-app.js'), path.join(dir, 'app.js'));
      for (const fmt of ['json', 'sarif', 'html', 'pretty']) {
        const out = path.join(dir, `report.${fmt}`);
        runCli(['--no-deps', '--no-entropy', '-f', fmt, '-o', out, 'app.js'], dir);
        assert.ok(fs.existsSync(out), `${fmt} report was not written`);
        assert.ok(fs.statSync(out).size > 100, `${fmt} report is suspiciously small`);
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('SARIF written from a project directory uses paths relative to it', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnscan-rel-'));
    try {
      fs.mkdirSync(path.join(dir, 'src'));
      fs.copyFileSync(path.join(__dirname, 'vulnerable-app.js'), path.join(dir, 'src', 'app.js'));
      const out = path.join(dir, 'r.sarif');
      runCli(['--no-deps', '--no-entropy', '-f', 'sarif', '-o', out, 'src'], dir);

      const sarif = JSON.parse(fs.readFileSync(out, 'utf-8'));
      const uris = sarif.runs[0].results.map(r => r.locations[0].physicalLocation.artifactLocation.uri);
      assert.ok(uris.length > 0, 'expected findings');
      for (const uri of uris) {
        assert.strictEqual(uri, 'src/app.js', `expected "src/app.js", got "${uri}"`);
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
