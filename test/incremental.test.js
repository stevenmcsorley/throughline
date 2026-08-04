/**
 * Incremental scanning tests.
 *
 * The invariant that matters: an incremental scan must report exactly what a
 * full scan would. Speed is worthless if the fast path quietly loses findings —
 * and it did, because unchanged files were never merged back in.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { execFileSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'dist/index.js');

const SQLI = 'function a(db, req) { return db.query("SELECT * FROM u WHERE id = " + req.params.id); }\n';
const CMDI = 'function b(cp, req) { cp.exec("ping " + req.query.h); }\n';
const CLEAN = 'const x = 1;\nmodule.exports = { x };\n';
const SAFE_SQL = 'function a(db, req) { return db.query("SELECT * FROM u WHERE id = ?", [req.params.id]); }\n';

function sandbox() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnscan-inc-'));
  fs.writeFileSync(path.join(dir, 'a.js'), SQLI);
  fs.writeFileSync(path.join(dir, 'b.js'), CMDI);
  fs.writeFileSync(path.join(dir, 'c.js'), CLEAN);
  return dir;
}

/** Run the CLI as JSON so assertions read structure, not formatted text. */
function run(dir, extraArgs) {
  const args = [CLI, '--no-deps', '--no-entropy', '-f', 'json', ...extraArgs, '.'];
  let stdout;
  try {
    stdout = execFileSync(process.execPath, args, {
      cwd: dir, encoding: 'utf-8', timeout: 240000, stdio: 'pipe',
    });
  } catch (err) {
    // Exit code 1 just means findings were present.
    stdout = err.stdout || '';
    if (!stdout) throw new Error(`CLI failed: ${err.stderr || err.message}`);
  }
  return JSON.parse(stdout);
}

/** Comparable identity for a finding, independent of ordering. */
function identity(report) {
  return (report.findings || [])
    .map(f => `${path.basename(f.file)}:${f.line}:${f.ruleId}`)
    .sort();
}

describe('incremental scanning', () => {
  test('a warm incremental scan reports the same findings as a full scan', () => {
    const dir = sandbox();
    try {
      const full = run(dir, []);
      run(dir, ['--incremental']);              // populate the cache
      const warm = run(dir, ['--incremental']);  // everything served from cache

      assert.deepStrictEqual(identity(warm), identity(full),
        'the fast path must not lose findings');
      assert.ok(full.findings.length >= 2, 'fixture should have findings to lose');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('an unchanged repository still reports its known vulnerabilities', () => {
    // The original bug: a second incremental run reported nothing at all,
    // so a vulnerable repository looked clean the moment nobody touched it.
    const dir = sandbox();
    try {
      run(dir, ['--incremental']);
      const warm = run(dir, ['--incremental']);
      assert.ok(warm.findings.length >= 2,
        `expected cached findings, got ${warm.findings.length}`);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('nothing is re-analysed when nothing changed', () => {
    const dir = sandbox();
    try {
      run(dir, ['--incremental']);
      const warm = run(dir, ['--incremental']);
      assert.strictEqual(warm.incremental.analysed, 0, 'no file changed, so none should be re-read');
      assert.strictEqual(warm.incremental.fromCache, 3);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a newly introduced vulnerability is picked up', () => {
    const dir = sandbox();
    try {
      run(dir, ['--incremental']);
      fs.writeFileSync(path.join(dir, 'c.js'),
        'function c(db, req) { return db.query("SELECT " + req.body.q); }\n');

      const after = run(dir, ['--incremental']);
      assert.strictEqual(after.incremental.analysed, 1, 'only the edited file should be re-read');
      assert.ok(identity(after).some(k => k.startsWith('c.js:')), 'the new finding must appear');
      assert.deepStrictEqual(identity(after), identity(run(dir, [])), 'must match a full scan');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a fixed vulnerability disappears', () => {
    const dir = sandbox();
    try {
      const before = run(dir, ['--incremental']);
      fs.writeFileSync(path.join(dir, 'a.js'), SAFE_SQL);

      const after = run(dir, ['--incremental']);
      assert.ok(after.findings.length < before.findings.length, 'the fix should reduce findings');
      assert.ok(!identity(after).some(k => k.startsWith('a.js:')), 'a.js should now be clean');
      assert.deepStrictEqual(identity(after), identity(run(dir, [])), 'must match a full scan');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a deleted file drops out of the results and the cache', () => {
    const dir = sandbox();
    try {
      run(dir, ['--incremental']);
      fs.unlinkSync(path.join(dir, 'b.js'));

      const after = run(dir, ['--incremental']);
      assert.ok(!identity(after).some(k => k.startsWith('b.js:')), 'deleted file must not linger');
      assert.strictEqual(after.incremental.deleted, 1);
      assert.deepStrictEqual(identity(after), identity(run(dir, [])), 'must match a full scan');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('changing the rule selection invalidates the cache', () => {
    const dir = sandbox();
    try {
      run(dir, ['--incremental']);
      // A different rule set means different results, so nothing may be reused.
      const narrowed = run(dir, ['--incremental', '-r', 'sql-injection']);
      assert.ok(narrowed.incremental.analysed > 0,
        'a changed rule set must force re-analysis rather than serve stale findings');
      for (const f of narrowed.findings) {
        assert.ok(/sql/.test(f.ruleId) || f.ruleId === 'interproc-taint',
          `${f.ruleId} leaked from the pre-invalidation cache`);
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a lost cache entry causes a re-scan, never a silent clean result', () => {
    const dir = sandbox();
    try {
      run(dir, ['--incremental']);

      // Simulate a partially deleted cache: drop the per-file findings but keep
      // the manifest claiming those files were scanned and had findings.
      const findingsDir = path.join(dir, '.vulnscan-cache', 'findings');
      assert.ok(fs.existsSync(findingsDir), 'setup: findings should be cached on disk');
      for (const f of fs.readdirSync(findingsDir)) fs.unlinkSync(path.join(findingsDir, f));

      const after = run(dir, ['--incremental']);
      assert.ok(after.incremental.cacheMisses > 0, 'the loss should be detected');
      assert.deepStrictEqual(identity(after), identity(run(dir, [])),
        'a missing cache entry must be re-scanned, not assumed clean');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('the scanner does not scan its own cache directory', () => {
    const dir = sandbox();
    try {
      const first = run(dir, ['--incremental']);
      const second = run(dir, ['--incremental']);
      assert.strictEqual(second.filesScanned, first.filesScanned,
        'the cache written by run one must not appear as source in run two');
      assert.strictEqual(second.filesScanned, 3);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('--clear-cache forces a full re-analysis', () => {
    const dir = sandbox();
    try {
      run(dir, ['--incremental']);
      const cleared = run(dir, ['--incremental', '--clear-cache']);
      assert.strictEqual(cleared.incremental.fromCache, 0);
      assert.strictEqual(cleared.incremental.analysed, 3);
      assert.deepStrictEqual(identity(cleared), identity(run(dir, [])));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
