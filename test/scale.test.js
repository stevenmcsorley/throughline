/**
 * Scaling tests.
 *
 * Everything else in the suite runs on a handful of files, where a quadratic
 * algorithm looks fine. The CPG taint query resolved every edge with
 * `graph.edges.find(e => e.id === eid)` — a linear scan of the whole edge array,
 * inside the BFS inner loop. At 100 files that was invisible; at 200 it was 13x
 * the cost of 100, and 840 files never finished.
 *
 * These tests exist to notice that class of regression before a user does.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const ROOT = path.resolve(__dirname, '..');
const { scan } = require(path.join(ROOT, 'dist/scanner.js'));
const { createGraph, addNode, addEdge } = require(path.join(ROOT, 'dist/engine/cpg/graph.js'));

/** A file with enough structure to produce graph nodes and taint edges. */
function sampleModule(i) {
  return `
const helper${i} = require('./helper${i}');

function handler${i}(req, res) {
  const value = req.query.input;
  const derived = transform${i}(value);
  return render${i}(res, derived);
}

function transform${i}(v) {
  const trimmed = String(v).trim();
  return trimmed.toLowerCase();
}

function render${i}(res, v) {
  return res.json({ ok: true, v });
}

module.exports = { handler${i}, transform${i}, render${i} };
`;
}

function makeCorpus(count) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnscan-scale-'));
  for (let i = 0; i < count; i++) {
    fs.writeFileSync(path.join(dir, `mod${i}.js`), sampleModule(i));
  }
  return dir;
}

describe('CPG edge index', () => {
  test('every edge is reachable by id without scanning', () => {
    // The structural invariant behind the fix. A timing assertion would be
    // flaky on shared CI runners; this is exact and cannot regress silently.
    const g = createGraph();
    const a = addNode(g, 'FUNCTION', 'a.js', 1, 1, 'function a() {}');
    const b = addNode(g, 'FUNCTION', 'a.js', 2, 2, 'function b() {}');
    const c = addNode(g, 'CALL_SITE', 'a.js', 3, 3, 'a()');

    const e1 = addEdge(g, 'CALLS', a.id, b.id);
    const e2 = addEdge(g, 'CALLS', b.id, c.id);

    assert.ok(g.edgeIndex, 'the graph must expose an edge index');
    assert.strictEqual(g.edgeIndex.size, g.edges.length,
      'every edge must be indexed, or lookups silently fall back to scanning');
    assert.strictEqual(g.edgeIndex.get(e1.id), e1);
    assert.strictEqual(g.edgeIndex.get(e2.id), e2);
  });
});

describe('scan cost grows roughly linearly with corpus size', () => {
  test('doubling the file count does not multiply the time', { timeout: 300000 }, () => {
    const small = makeCorpus(40);
    const large = makeCorpus(80);
    try {
      const opts = { deps: false, entropy: false, applyTriage: false };

      // Warm the process so JIT and grammar loading are not attributed to the
      // first measurement.
      scan({ ...opts, paths: [small] });

      const t1 = Date.now();
      const rSmall = scan({ ...opts, paths: [small] });
      const smallMs = Date.now() - t1;

      const t2 = Date.now();
      const rLarge = scan({ ...opts, paths: [large] });
      const largeMs = Date.now() - t2;

      assert.strictEqual(rSmall.filesScanned, 40);
      assert.strictEqual(rLarge.filesScanned, 80);

      // Linear would be ~2x. The quadratic version was 13x for a 2x increase.
      // 6x leaves generous headroom for a loaded CI runner while still catching
      // a return to superlinear behaviour.
      const ratio = largeMs / Math.max(smallMs, 1);
      assert.ok(ratio < 6,
        `2x the files took ${ratio.toFixed(1)}x the time ` +
        `(${smallMs}ms -> ${largeMs}ms) — scan cost is superlinear again`);
    } finally {
      fs.rmSync(small, { recursive: true, force: true });
      fs.rmSync(large, { recursive: true, force: true });
    }
  });

  test('a few hundred files complete in reasonable time', { timeout: 300000 }, () => {
    const dir = makeCorpus(200);
    try {
      const started = Date.now();
      const result = scan({ paths: [dir], deps: false, entropy: false, applyTriage: false });
      const elapsed = Date.now() - started;

      assert.strictEqual(result.filesScanned, 200);
      // Before the edge index this took ~57s locally. The bound is deliberately
      // loose — it is a cliff detector, not a benchmark.
      assert.ok(elapsed < 120000, `200 files took ${(elapsed / 1000).toFixed(1)}s`);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('results do not change with corpus size', () => {
    // Guards against a performance fix that quietly drops findings — the
    // failure mode that would make the tests above meaningless.
    const dir = makeCorpus(30);
    try {
      const opts = { deps: false, entropy: false, applyTriage: false };
      const whole = scan({ ...opts, paths: [dir] });
      const single = scan({ ...opts, paths: [path.join(dir, 'mod0.js')] });

      const inWhole = whole.findings
        .filter(f => path.basename(f.file) === 'mod0.js')
        .map(f => `${f.ruleId}:${f.line}`).sort();
      const alone = single.findings.map(f => `${f.ruleId}:${f.line}`).sort();

      assert.deepStrictEqual(inWhole, alone,
        'a file must yield the same findings whether scanned alone or in a corpus');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────

describe('native resource use does not grow with corpus size', () => {
  const {
    clearTreeSitterCaches, treeSitterCacheStats,
  } = require(path.join(ROOT, 'dist/engine/tree-sitter-engine.js'));

  test('parsers and compiled queries are shared, not allocated per file', () => {
    // Both hold native memory that V8 only reclaims via a finalizer, so churning
    // them inflates RSS invisibly — the JS heap stays small while resident memory
    // climbs into the gigabytes. A Parser was built per file and a Query per
    // pattern per file; now both are keyed by grammar and query text.
    clearTreeSitterCaches();

    const small = makeCorpus(10);
    const large = makeCorpus(80);
    try {
      const opts = { deps: false, entropy: false, applyTriage: false };

      scan({ ...opts, paths: [small] });
      const afterSmall = treeSitterCacheStats();

      scan({ ...opts, paths: [large] });
      const afterLarge = treeSitterCacheStats();

      assert.deepStrictEqual(afterLarge, afterSmall,
        `caches grew from ${JSON.stringify(afterSmall)} to ${JSON.stringify(afterLarge)} ` +
        'when scanning 8x the files — something is allocating per file');

      // One grammar (.js) and one entry per distinct semantic query.
      assert.ok(afterLarge.parsers <= 4,
        `${afterLarge.parsers} parsers cached for a single-language corpus`);
      assert.ok(afterLarge.queries < 100,
        `${afterLarge.queries} queries cached — expected roughly one per pattern`);
    } finally {
      fs.rmSync(small, { recursive: true, force: true });
      fs.rmSync(large, { recursive: true, force: true });
    }
  });

  test('resident memory stays bounded on a few hundred files', { timeout: 300000 }, () => {
    // Before parse-once and cache sharing, an 840-file corpus peaked at 1.3GB.
    const dir = makeCorpus(200);
    try {
      let peak = 0;
      const sample = setInterval(() => {
        const rss = process.memoryUsage().rss;
        if (rss > peak) peak = rss;
      }, 40);

      try {
        scan({ paths: [dir], deps: false, entropy: false, applyTriage: false });
      } finally {
        clearInterval(sample);
      }
      peak = Math.max(peak, process.memoryUsage().rss);

      const peakMb = peak / 1048576;
      assert.ok(peakMb < 800,
        `peak RSS ${peakMb.toFixed(0)}MB on 200 files — native memory is leaking again`);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a file is parsed once per scan, not once per rule', () => {
    // Six rules carry semantic patterns. analyze() was called per rule, so each
    // file was parsed six times and six native trees were allocated for it.
    const { TreeSitterEngine } = require(path.join(ROOT, 'dist/engine/tree-sitter-engine.js'));
    const dir = makeCorpus(5);
    try {
      const engine = new TreeSitterEngine();
      let parses = 0;
      const realInit = engine.init.bind(engine);
      engine.init = ext => {
        const ok = realInit(ext);
        if (ok && engine.parser && !engine.parser.__counted) {
          const inner = engine.parser;
          const realParse = inner.parse.bind(inner);
          inner.parse = src => { parses++; return realParse(src); };
          inner.__counted = true;
        }
        return ok;
      };

      const { SEMANTIC_RULES } = require(path.join(ROOT, 'dist/engine/tree-sitter-engine.js'));
      assert.ok(Object.keys(SEMANTIC_RULES).length > 1,
        'setup: more than one rule must carry semantic patterns for this to mean anything');

      const content = fs.readFileSync(path.join(dir, 'mod0.js'), 'utf-8');
      engine.init('.js');
      const all = Object.values(SEMANTIC_RULES).flat();
      engine.analyze(content, all);

      assert.strictEqual(parses, 1,
        `${parses} parses for one file — patterns should share a single parse tree`);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
