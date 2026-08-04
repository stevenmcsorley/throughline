/**
 * Multi-language detection.
 *
 * The README claims six languages and sells multi-language analysis as a
 * differentiator, but every other test in this suite is JavaScript. When these
 * fixtures were first run, Go found nothing at all, and Ruby and PHP missed both
 * their SQL and command injections.
 *
 * The cause was structural rather than a missing pattern: `scanFilePatterns`
 * skipped the regex fallback for any rule that had tree-sitter patterns — but
 * those patterns were written for JavaScript and Python. On Go, PHP and Ruby the
 * AST queries could not match, and the regex rules that would have caught the
 * bugs were skipped anyway, so those rules were silently dead.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const FIXTURES = path.join(__dirname, 'fixtures');
const { scan } = require(path.join(ROOT, 'dist/scanner.js'));
const { TreeSitterEngine } = require(path.join(ROOT, 'dist/engine/tree-sitter-engine.js'));

function scanFixture(name) {
  return scan({
    paths: [path.join(FIXTURES, name)],
    deps: false,
    entropy: false,
    applyTriage: false,
  });
}

/** Every language must catch at least these two classes. */
const LANGUAGES = [
  { name: 'Python', vulnerable: 'vulnerable.py', safe: 'safe.py', extra: ['insecure-crypto', 'hardcoded-secrets'] },
  { name: 'Go', vulnerable: 'vulnerable.go', safe: 'safe.go', extra: [] },
  { name: 'PHP', vulnerable: 'vulnerable.php', safe: 'safe.php', extra: ['insecure-crypto', 'hardcoded-secrets'] },
  { name: 'Ruby', vulnerable: 'vulnerable.rb', safe: 'safe.rb', extra: ['hardcoded-secrets'] },
];

for (const lang of LANGUAGES) {
  describe(`${lang.name}`, () => {
    test('detects SQL injection', () => {
      const ids = new Set(scanFixture(lang.vulnerable).findings.map(f => f.ruleId));
      assert.ok([...ids].some(id => /sql/.test(id)),
        `no SQL injection reported in ${lang.vulnerable}; got ${[...ids].join(', ') || '(nothing)'}`);
    });

    test('detects command injection', () => {
      const ids = new Set(scanFixture(lang.vulnerable).findings.map(f => f.ruleId));
      assert.ok([...ids].some(id => /command|exec/.test(id)),
        `no command injection reported in ${lang.vulnerable}; got ${[...ids].join(', ') || '(nothing)'}`);
    });

    for (const extra of lang.extra) {
      test(`detects ${extra}`, () => {
        const ids = new Set(scanFixture(lang.vulnerable).findings.map(f => f.ruleId));
        assert.ok(ids.has(extra), `expected ${extra}; got ${[...ids].join(', ') || '(nothing)'}`);
      });
    }

    test('idiomatic safe code produces no findings', () => {
      // Parameterized queries, argument-list process calls, allowlists and
      // environment variables are the recommended forms. Flagging them is what
      // makes a scanner get switched off.
      const result = scanFixture(lang.safe);
      assert.deepStrictEqual(
        result.findings.map(f => `${f.ruleId}@${f.line}: ${f.snippet.trim().slice(0, 60)}`),
        [],
        `${lang.safe} should be clean`
      );
    });

    test('every declared vulnerability marker is covered', () => {
      // The fixtures annotate each planted bug with `VULN:`. If one is added
      // without detection following, this fails rather than going unnoticed.
      const fs = require('node:fs');
      const src = fs.readFileSync(path.join(FIXTURES, lang.vulnerable), 'utf-8').split('\n');
      const markers = src
        .map((line, i) => (/VULN:/.test(line) ? i + 1 : 0))
        .filter(Boolean);
      assert.ok(markers.length >= 2, 'setup: fixture should declare several vulnerabilities');

      const findings = scanFixture(lang.vulnerable).findings;
      const uncovered = markers.filter(
        m => !findings.some(f => Math.abs(f.line - m) <= 5)
      );
      assert.deepStrictEqual(uncovered, [],
        `no finding within 5 lines of the VULN markers at ${uncovered.join(', ')}`);
    });
  });
}

describe('language support is reported honestly', () => {
  test('every extension claimed as tree-sitter supported actually initialises', () => {
    // `.php` silently failed to initialise: tree-sitter-php exports an object of
    // dialects rather than a bare Language, so setLanguage threw and init()
    // returned false. Detection still worked via regex, but the AST path did not
    // exist despite being advertised.
    const engine = new TreeSitterEngine();
    const claimed = TreeSitterEngine.supportedExtensions();
    const broken = claimed.filter(ext => !engine.init(ext));

    assert.deepStrictEqual(broken, [],
      `these extensions are listed as tree-sitter supported but fail to initialise: ${broken.join(', ')}`);
  });
});

// ─────────────────────────────────────────────────────────────────────────

describe('multi-language code property graph', () => {
  const { MultiLangBuilder, runAllCpgQueries } =
    require(path.join(ROOT, 'dist/engine/cpg/index.js'));

  function cpgFindings(fixture) {
    const graph = new MultiLangBuilder().buildAll([path.join(FIXTURES, fixture)]);
    return { graph, vulns: runAllCpgQueries(graph) };
  }

  test('the builder emits data-flow edges', () => {
    // It emitted none at all — only AST_CHILD, CALLS and taint self-annotations.
    // The precise query traverses DATA_FLOW, so sources and sinks were both
    // being marked while nothing connected them: the multi-language CPG could
    // not report a finding no matter what it was pointed at.
    for (const fixture of ['vulnerable.py', 'vulnerable.go', 'vulnerable.php', 'vulnerable.rb']) {
      const { graph } = cpgFindings(fixture);
      const dataFlow = graph.edges.filter(e => e.type === 'DATA_FLOW');
      assert.ok(dataFlow.length > 0, `${fixture} produced no DATA_FLOW edges`);
    }
  });

  test('PHP builds a non-empty graph', () => {
    // tree-sitter-php exports { php, php_only }; passing the module object made
    // every query throw and PHP built literally nothing.
    const { graph } = cpgFindings('vulnerable.php');
    assert.ok(graph.nodes.size > 0, 'PHP produced an empty graph');
  });

  for (const fixture of ['vulnerable.py', 'vulnerable.go', 'vulnerable.php', 'vulnerable.rb']) {
    test(`${fixture} yields a traced taint path`, () => {
      const { vulns } = cpgFindings(fixture);
      assert.ok(vulns.length > 0,
        `no CPG finding for ${fixture} — the graph is built but no source reaches a sink`);
      for (const v of vulns) {
        assert.match(v.ruleId, /^cpg-/);
        assert.ok(v.line > 0, 'a finding must point at a real line');
      }
    });
  }

  for (const fixture of ['safe.py', 'safe.go', 'safe.php', 'safe.rb']) {
    test(`${fixture} yields no CPG finding`, () => {
      const { vulns } = cpgFindings(fixture);
      assert.deepStrictEqual(vulns.map(v => `${v.ruleId}@${v.line}`), [],
        `${fixture} is idiomatic safe code and must not be flagged`);
    });
  }

  test('interpolated strings are not mistaken for static literals', () => {
    // Ruby and PHP interpolate inside double quotes, unlike JavaScript. Treating
    // `"SELECT ... #{id}"` as a static literal made an injected query look
    // correctly parameterized and silently exempted it.
    const { vulns } = cpgFindings('vulnerable.rb');
    assert.ok(vulns.some(v => v.ruleId === 'cpg-precise-sql'),
      'Ruby interpolated SQL should be reported, not exempted as parameterized');
  });

  test('running a shell through a non-shell API is still a shell', () => {
    // exec.Command("sh", "-c", cmd) uses an argv API to launch a shell, so the
    // argument-vector guarantee does not apply.
    const { vulns } = cpgFindings('vulnerable.go');
    assert.ok(vulns.some(v => v.ruleId === 'cpg-precise-command-exec'),
      'exec.Command("sh", "-c", ...) must not be exempted as a safe argv call');
  });
});
