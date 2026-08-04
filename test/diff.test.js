/**
 * Semantic diff integration tests.
 *
 * Builds throwaway git repositories and runs the real CLI against them, because
 * the interesting failures here are environmental — shell quoting, ref peeling,
 * and checkout mechanics — not logic that a unit test would reach.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { execFileSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'dist/index.js');

const SAFE = 'function getUser(db, req) {\n' +
  '  return db.query("SELECT * FROM u WHERE id = ?", [req.params.id]);\n' +
  '}\nmodule.exports = { getUser };\n';

const UNSAFE = 'function getUser(db, req) {\n' +
  '  return db.query("SELECT * FROM u WHERE id = " + req.params.id);\n' +
  '}\nmodule.exports = { getUser };\n';

function hasGit() {
  try { execFileSync('git', ['--version'], { stdio: 'pipe' }); return true; } catch { return false; }
}

/** Create a repo whose two commits contain the given file contents. */
function makeRepo(firstContent, secondContent) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnscan-diff-'));
  const g = args => execFileSync('git', args, { cwd: dir, stdio: 'pipe', encoding: 'utf-8' });

  g(['init', '-q']);
  g(['config', 'user.email', 'test@example.com']);
  g(['config', 'user.name', 'Test']);
  g(['config', 'commit.gpgsign', 'false']);

  fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'src', 'app.js'), firstContent);
  g(['add', '-A']);
  g(['commit', '-qm', 'first']);

  fs.writeFileSync(path.join(dir, 'src', 'app.js'), secondContent);
  g(['add', '-A']);
  g(['commit', '-qm', 'second']);

  return dir;
}

/** Run the CLI in a repo and capture stdout plus the exit code. */
function runDiff(dir, args) {
  try {
    const stdout = execFileSync(process.execPath, [CLI, ...args], {
      cwd: dir, encoding: 'utf-8', timeout: 240000, stdio: 'pipe',
    });
    return { stdout, code: 0 };
  } catch (err) {
    return { stdout: (err.stdout || '') + (err.stderr || ''), code: err.status };
  }
}

function section(stdout, label) {
  const m = new RegExp(`${label}:\\s*(\\d+)`).exec(stdout.replace(/\x1b\[[0-9;]*m/g, ''));
  return m ? Number(m[1]) : null;
}

describe('semantic diff against real git history', { skip: !hasGit() && 'git not on PATH' }, () => {
  test('a newly introduced vulnerability is reported and fails the build', () => {
    const dir = makeRepo(SAFE, UNSAFE);
    try {
      const { stdout, code } = runDiff(dir, ['--diff', 'HEAD~1..HEAD', 'src/']);
      assert.strictEqual(section(stdout, 'Introduced'), 1, stdout);
      assert.strictEqual(section(stdout, 'Resolved'), 0, stdout);
      assert.strictEqual(code, 1, 'introducing a vulnerability must fail the pipeline');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a fixed vulnerability is reported as resolved and passes', () => {
    const dir = makeRepo(UNSAFE, SAFE);
    try {
      const { stdout, code } = runDiff(dir, ['--diff', 'HEAD~1..HEAD', 'src/']);
      assert.strictEqual(section(stdout, 'Introduced'), 0, stdout);
      assert.strictEqual(section(stdout, 'Resolved'), 1, stdout);
      assert.strictEqual(code, 0, 'fixing a vulnerability must not fail the pipeline');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('an unchanged vulnerability is persisted, not re-reported as new', () => {
    // Pre-existing issues are not this change's fault and must not fail CI.
    const dir = makeRepo(UNSAFE, UNSAFE.replace('module.exports', '// touched\nmodule.exports'));
    try {
      const { stdout, code } = runDiff(dir, ['--diff', 'HEAD~1..HEAD', 'src/']);
      assert.strictEqual(section(stdout, 'Introduced'), 0, stdout);
      assert.strictEqual(section(stdout, 'Persisted'), 1, stdout);
      assert.strictEqual(code, 0, 'a pre-existing finding must not fail the pipeline');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('the working tree, index and HEAD are left untouched', () => {
    const dir = makeRepo(SAFE, UNSAFE);
    try {
      const g = args => execFileSync('git', args, { cwd: dir, stdio: 'pipe', encoding: 'utf-8' }).trim();
      const headBefore = g(['rev-parse', 'HEAD']);

      // Leave an uncommitted edit to prove it survives the historical checkout.
      fs.writeFileSync(path.join(dir, 'src', 'scratch.js'), 'const inProgress = true;\n');
      runDiff(dir, ['--diff', 'HEAD~1..HEAD', 'src/']);

      assert.strictEqual(g(['rev-parse', 'HEAD']), headBefore, 'HEAD must not move');
      assert.ok(fs.existsSync(path.join(dir, 'src', 'scratch.js')), 'uncommitted work must survive');
      assert.match(g(['status', '--porcelain']), /scratch\.js/, 'the edit must still be pending');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('no temporary worktree is left registered', () => {
    const dir = makeRepo(SAFE, UNSAFE);
    try {
      runDiff(dir, ['--diff', 'HEAD~1..HEAD', 'src/']);
      const list = execFileSync('git', ['worktree', 'list'], { cwd: dir, encoding: 'utf-8', stdio: 'pipe' });
      const entries = list.trim().split('\n').filter(Boolean);
      assert.strictEqual(entries.length, 1, `expected only the main worktree, got:\n${list}`);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a ref that does not exist is refused clearly', () => {
    const dir = makeRepo(SAFE, UNSAFE);
    try {
      const { stdout, code } = runDiff(dir, ['--diff', 'no-such-ref..HEAD', 'src/']);
      assert.strictEqual(code, 2, 'a bad ref is a usage error, not a findings result');
      assert.match(stdout, /does not resolve to a commit/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('refs containing shell metacharacters are handled, not interpreted', () => {
    // HEAD~1^{commit} peeling broke under cmd.exe, where ^ is the escape char.
    const dir = makeRepo(SAFE, UNSAFE);
    try {
      const { stdout, code } = runDiff(dir, ['--diff', 'HEAD~1..HEAD', 'src/']);
      assert.notStrictEqual(code, 2, `ref peeling should succeed, got:\n${stdout}`);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('diff outside a git repository', () => {
  test('is refused with a clear message', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnscan-nogit-'));
    try {
      fs.writeFileSync(path.join(dir, 'a.js'), 'const x = 1;\n');
      const { stdout, code } = runDiff(dir, ['--diff', 'HEAD~1..HEAD', '.']);
      assert.strictEqual(code, 2);
      assert.match(stdout, /git repository/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
