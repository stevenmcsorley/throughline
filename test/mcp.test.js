/**
 * MCP integration tests.
 *
 * Drives the server through a real MCP client over stdio, so the protocol
 * handshake, schemas, and the triage round-trip are all exercised as a client
 * would see them.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const ROOT = path.resolve(__dirname, '..');
const { Client } = require(path.join(ROOT, 'node_modules/@modelcontextprotocol/sdk/dist/cjs/client/index.js'));
const { StdioClientTransport } = require(path.join(ROOT, 'node_modules/@modelcontextprotocol/sdk/dist/cjs/client/stdio.js'));

/** Run the server with its own working directory so tests never touch the real cache. */
let client;
let transport;
let workDir;

function payload(res) {
  const text = res.content.map(c => c.text).join('');
  if (res.isError) throw new Error(text);
  try { return JSON.parse(text); } catch { return text; }
}

before(async () => {
  workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'throughline-mcp-'));
  // Give the sandbox a copy of the vulnerable fixture to scan.
  fs.copyFileSync(path.join(__dirname, 'vulnerable-app.js'), path.join(workDir, 'app.js'));

  transport = new StdioClientTransport({
    command: process.execPath,
    args: [path.join(ROOT, 'dist/mcp/server.js')],
    cwd: workDir,
  });
  client = new Client({ name: 'throughline-test', version: '1.0.0' });
  await client.connect(transport);
});

after(async () => {
  if (client) await client.close();
  if (workDir) fs.rmSync(workDir, { recursive: true, force: true });
});

describe('MCP protocol surface', () => {
  test('handshake reports the server identity', () => {
    assert.strictEqual(client.getServerVersion().name, 'throughline');
  });

  test('every documented tool is registered with a schema', async () => {
    const { tools } = await client.listTools();
    const names = new Set(tools.map(t => t.name));
    const expected = [
      'scan', 'scan_git_diff', 'scan_dependencies', 'scan_secrets', 'scan_snippet',
      'list_rules', 'rule_summary', 'create_custom_rule', 'init_example_rules',
      'export_report', 'get_review_queue', 'submit_triage', 'get_triage',
      'get_finding_context', 'suggest_fix', 'apply_fix', 'cache_stats', 'clear_cache',
    ];
    for (const name of expected) {
      assert.ok(names.has(name), `tool "${name}" is missing`);
    }
    for (const t of tools) {
      assert.ok(t.description && t.description.length > 20, `${t.name} needs a real description`);
      assert.ok(t.inputSchema, `${t.name} needs an input schema`);
    }
  });

  test('prompts and resources are registered', async () => {
    const { prompts } = await client.listPrompts();
    const { resources } = await client.listResources();
    assert.deepStrictEqual(
      prompts.map(p => p.name).sort(),
      ['fix_vulnerability', 'review_my_changes', 'security_review']
    );
    assert.deepStrictEqual(
      resources.map(r => r.uri).sort(),
      ['throughline://last-scan', 'throughline://rules', 'throughline://triage']
    );
  });
});

describe('MCP scanning', () => {
  test('scan returns findings with triage keys attached', async () => {
    const res = payload(await client.callTool({
      name: 'scan', arguments: { paths: ['app.js'], deps: false, entropy: false },
    }));
    assert.ok(res.totalFindings > 0, 'fixture should produce findings');
    for (const f of res.findings) {
      assert.ok(f.findingKey, 'every finding needs a findingKey for triage');
      assert.ok(f.codeHash, 'every finding needs a codeHash for triage');
    }
  });

  test('the severity threshold is honoured through MCP', async () => {
    const res = payload(await client.callTool({
      name: 'scan', arguments: { paths: ['app.js'], deps: false, entropy: false, severity: 'critical' },
    }));
    const offenders = res.findings.filter(f => f.severity !== 'critical');
    assert.deepStrictEqual(offenders.map(f => f.ruleId), []);
  });

  test('scan_snippet analyses code without writing it into the project', async () => {
    const res = payload(await client.callTool({
      name: 'scan_snippet',
      arguments: {
        filename: 'h.js',
        code: 'const cp=require("child_process");\nfunction h(req){ cp.exec("ls "+req.query.d); }\n',
      },
    }));
    assert.ok(res.totalFindings > 0, 'command injection should be detected');
    assert.ok(!fs.existsSync(path.join(workDir, 'h.js')), 'snippet must not be persisted');
  });

  test('list_rules reports the catalogue', async () => {
    const res = payload(await client.callTool({ name: 'list_rules', arguments: {} }));
    assert.ok(res.totalRules >= 31, `expected the full rule set, got ${res.totalRules}`);
  });
});

describe('MCP triage round-trip', () => {
  test('a verdict suppresses the finding, and the suppression is reported', async () => {
    const before = payload(await client.callTool({
      name: 'scan', arguments: { paths: ['app.js'], deps: false, entropy: false },
    }));
    const target = before.findings.find(f => f.ruleId === 'hardcoded-secrets');
    assert.ok(target, 'fixture should contain a hardcoded secret');

    const submitted = payload(await client.callTool({
      name: 'submit_triage',
      arguments: {
        triagedBy: 'throughline-test',
        verdicts: [{
          findingKey: target.findingKey,
          codeHash: target.codeHash,
          isRealVulnerability: false,
          analysis: 'Deliberately vulnerable test fixture; the key is a documented dummy value.',
          reviewConfidence: 'high',
        }],
      },
    }));
    assert.strictEqual(submitted.accepted, 1);
    assert.deepStrictEqual(submitted.rejected, []);

    const after = payload(await client.callTool({
      name: 'scan', arguments: { paths: ['app.js'], deps: false, entropy: false },
    }));
    assert.strictEqual(after.totalFindings, before.totalFindings - 1);
    assert.strictEqual(after.triage.suppressed, 1, 'suppression must be reported, never silent');
    assert.ok(!after.findings.some(f => f.findingKey === target.findingKey));
  });

  test('applyTriage:false restores suppressed findings', async () => {
    const res = payload(await client.callTool({
      name: 'scan',
      arguments: { paths: ['app.js'], deps: false, entropy: false, applyTriage: false },
    }));
    assert.ok(res.findings.some(f => f.ruleId === 'hardcoded-secrets'),
      'opting out of triage must show everything again');
  });

  test('a malformed verdict is rejected without sinking the batch', async () => {
    const queue = payload(await client.callTool({ name: 'get_review_queue', arguments: { limit: 2 } }));
    assert.ok(queue.packets.length > 0, 'there should be findings left to review');
    const good = queue.packets[0];

    const res = payload(await client.callTool({
      name: 'submit_triage',
      arguments: {
        verdicts: [
          { findingKey: 'bogus:x.js:1', codeHash: 'abc', isRealVulnerability: false, analysis: 'no' },
          {
            findingKey: good.findingKey, codeHash: good.codeHash, isRealVulnerability: true,
            analysis: 'Reachable from an unauthenticated route with no sanitizer on the path.',
          },
        ],
      },
    }));
    assert.strictEqual(res.accepted, 1, 'the valid verdict must still store');
    assert.strictEqual(res.rejected.length, 1, 'the empty-analysis verdict must be refused');
    assert.match(res.rejected[0].error, /analysis/);
  });

  test('review packets carry source context and a heuristic hint', async () => {
    const queue = payload(await client.callTool({
      name: 'get_review_queue', arguments: { limit: 1, contextRadius: 5 },
    }));
    const p = queue.packets[0];
    assert.ok(queue.instructions.length > 100, 'the AI needs review instructions');
    assert.ok(p.context.includes('|'), 'context should be numbered source lines');
    assert.ok(['high', 'medium', 'low'].includes(p.hint.priority));
  });
});

describe('MCP error handling', () => {
  test('apply_fix refuses a non-matching edit', async () => {
    const res = await client.callTool({
      name: 'apply_fix',
      arguments: { file: 'app.js', oldCode: 'THIS_TEXT_IS_NOT_PRESENT', newCode: 'x' },
    });
    assert.ok(res.isError, 'should surface a tool error');
    assert.match(res.content[0].text, /not found/);
  });

  test('apply_fix refuses an ambiguous edit', async () => {
    fs.writeFileSync(path.join(workDir, 'dup.js'), 'const a = 1;\nconst a = 1;\n');
    const res = await client.callTool({
      name: 'apply_fix',
      arguments: { file: 'dup.js', oldCode: 'const a = 1;', newCode: 'const a = 2;' },
    });
    assert.ok(res.isError);
    assert.match(res.content[0].text, /appears 2 times/);
  });

  test('apply_fix applies an unambiguous edit and re-scans', async () => {
    fs.writeFileSync(path.join(workDir, 'fixme.js'),
      'function h(db, req) { return db.query("SELECT * FROM u WHERE id = " + req.params.id); }\n');
    const before = payload(await client.callTool({
      name: 'scan', arguments: { paths: ['fixme.js'], deps: false, entropy: false, applyTriage: false },
    }));
    assert.ok(before.totalFindings > 0, 'setup: the unsafe query should be flagged');

    const res = payload(await client.callTool({
      name: 'apply_fix',
      arguments: {
        file: 'fixme.js',
        oldCode: 'db.query("SELECT * FROM u WHERE id = " + req.params.id)',
        newCode: 'db.query("SELECT * FROM u WHERE id = ?", [req.params.id])',
      },
    }));
    assert.strictEqual(res.applied, true);
    assert.strictEqual(res.findingsRemainingInFile, 0,
      'parameterizing the query should clear the finding');
  });

  test('an invalid severity is surfaced as a tool error', async () => {
    const res = await client.callTool({
      name: 'scan', arguments: { paths: ['app.js'], severity: 'catastrophic' },
    });
    assert.ok(res.isError);
  });
});
