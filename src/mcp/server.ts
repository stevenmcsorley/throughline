#!/usr/bin/env node
/**
 * Throughline MCP Server
 *
 * Exposes the whole scanner over the Model Context Protocol so any MCP-capable
 * AI can drive it: scan, filter, export, manage rules, and — the part that used
 * to be a stub — actually triage findings.
 *
 * The triage loop is:
 *   get_review_queue  → findings + source context + what to judge
 *   (the AI reasons)
 *   submit_triage     → verdicts persisted to .throughline-cache/triage.json
 *   scan              → confirmed false positives are now suppressed, with the
 *                       suppression count always reported
 *
 * Transport is stdio, so the server is launched by the MCP client rather than
 * run standalone. Nothing is written to stdout except protocol frames —
 * diagnostics go to stderr, or they would corrupt the stream.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import * as tools from './tools';

const SEVERITY = z.enum(['critical', 'high', 'medium', 'low', 'info']);
const CONFIDENCE = z.enum(['certain', 'high', 'medium', 'low']);

/** Shared scan filters, reused across the scanning tools. */
const scanFilters = {
  paths: z.array(z.string()).optional()
    .describe('Files or directories to scan. Defaults to the current directory.'),
  rules: z.array(z.string()).optional()
    .describe('Rule IDs to run. Selecting a declared rule also includes its taint-engine findings (sql-injection covers cpg-precise-sql).'),
  severity: SEVERITY.optional().describe('Minimum severity of findings to report.'),
  confidence: CONFIDENCE.optional().describe('Minimum confidence of findings to report.'),
  extensions: z.array(z.string()).optional().describe('Limit to these file extensions, e.g. [".js", ".py"].'),
  exclude: z.array(z.string()).optional().describe('Extra directory names to exclude.'),
  maxFileSize: z.number().int().positive().optional().describe('Skip files larger than this many bytes (default 10MB).'),
};

function ok(payload: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(payload, null, 2) }] };
}

function fail(err: unknown) {
  const message = err instanceof Error ? err.message : String(err);
  return { content: [{ type: 'text' as const, text: `Error: ${message}` }], isError: true };
}

/** Wrap a handler so a thrown error becomes a tool error, not a dead server. */
function handler<A>(fn: (args: A) => unknown | Promise<unknown>) {
  return async (args: A) => {
    try {
      return ok(await fn(args));
    } catch (err) {
      return fail(err);
    }
  };
}

export function createServer(): McpServer {
  const server = new McpServer(
    { name: 'throughline', version: '1.1.0' },
    {
      instructions:
        'Throughline is a static application security scanner. Use scan to find vulnerabilities, ' +
        'then get_review_queue and submit_triage to review them — your verdicts persist and ' +
        'suppress confirmed false positives in later scans. Prefer scan_git_diff when the user ' +
        'is asking about their current changes rather than the whole repository.',
    }
  );

  // ─── Scanning ────────────────────────────────────────────────────────

  server.registerTool('scan', {
    title: 'Scan for vulnerabilities',
    description:
      'Run a full security scan: tree-sitter AST rules, regex patterns, inter-procedural taint ' +
      'analysis, code property graph dataflow, entropy secret detection, and dependency CVEs. ' +
      'Returns findings with severity, CWE/OWASP mapping, and a findingKey for triage.',
    inputSchema: {
      ...scanFilters,
      entropy: z.boolean().optional().describe('Detect high-entropy secrets. Default true.'),
      deps: z.boolean().optional().describe('Check dependencies against OSV.dev. Needs network. Default true.'),
      incremental: z.boolean().optional().describe('Only scan files changed since the last scan.'),
      applyTriage: z.boolean().optional().describe('Hide findings already reviewed as false positives. Default true.'),
    },
  }, handler(tools.runScan));

  server.registerTool('scan_git_diff', {
    title: 'Scan changed files',
    description: 'Scan only the files changed between two git refs — the right tool for reviewing a branch or PR.',
    inputSchema: {
      ...scanFilters,
      baseRef: z.string().optional().describe('Base ref. Default HEAD~1.'),
      targetRef: z.string().optional().describe('Target ref. Default HEAD.'),
    },
  }, handler(tools.runGitDiffScan));

  server.registerTool('scan_dependencies', {
    title: 'Scan dependencies for CVEs',
    description: 'Check manifests (package.json, requirements.txt, go.mod, Gemfile, pom.xml) against the OSV.dev vulnerability database. Requires network access.',
    inputSchema: { paths: z.array(z.string()).optional().describe('Directories containing manifests. Defaults to the current directory.') },
  }, handler(tools.runDependencyScan));

  server.registerTool('scan_secrets', {
    title: 'Scan for hardcoded secrets',
    description: 'Entropy and pattern based detection of API keys, tokens, private keys, and passwords.',
    inputSchema: { paths: z.array(z.string()).optional() },
  }, handler(tools.runEntropyScan));

  server.registerTool('scan_snippet', {
    title: 'Scan a code snippet',
    description: 'Run the full engine over a snippet without writing it into the project. Useful for checking code before suggesting it.',
    inputSchema: {
      code: z.string().describe('Source code to analyse.'),
      filename: z.string().describe('A filename such as "handler.ts" — the extension selects the language.'),
    },
  }, handler(tools.scanSnippet));

  // ─── Rules ───────────────────────────────────────────────────────────

  server.registerTool('list_rules', {
    title: 'List detection rules',
    description: 'List every built-in and custom rule with its severity, CWE, OWASP category, and target languages.',
    inputSchema: { severity: SEVERITY.optional().describe('Only rules declared at this severity.') },
  }, handler(tools.listRules));

  server.registerTool('rule_summary', {
    title: 'Rule coverage summary',
    description: 'Counts of rules by severity, plus the CWEs and languages covered.',
    inputSchema: {},
  }, handler(() => tools.ruleSummary()));

  server.registerTool('create_custom_rule', {
    title: 'Create a custom rule',
    description:
      'Write a project-specific detection rule to .throughline-rules/. Patterns are regexes compiled case-insensitively. ' +
      'Verifies the rule loads before reporting success.',
    inputSchema: {
      id: z.string().describe('Kebab-case unique id, e.g. "internal-token-format".'),
      name: z.string().describe('Human-readable name.'),
      description: z.string(),
      severity: SEVERITY,
      cwe: z.string().optional().describe('e.g. "CWE-798".'),
      owasp: z.string().optional().describe('e.g. "A02:2021-Cryptographic Failures".'),
      confidence: CONFIDENCE.optional(),
      patterns: z.array(z.object({
        regex: z.string().describe('Regex source. Compiled with the g and i flags.'),
        message: z.string(),
        recommendation: z.string().optional(),
      })).min(1),
      contextPatterns: z.array(z.object({ regex: z.string(), message: z.string() })).optional()
        .describe('All of these must also match in the file for the rule to fire.'),
      excludeContextPatterns: z.array(z.object({ regex: z.string(), message: z.string() })).optional()
        .describe('If any of these match, the finding is suppressed.'),
      matchAll: z.boolean().optional().describe('Require every pattern to match rather than any.'),
      extensions: z.array(z.string()).optional().describe('Target extensions. Defaults to all files.'),
    },
  }, handler(tools.createCustomRule));

  server.registerTool('init_example_rules', {
    title: 'Generate example custom rules',
    description: 'Write starter rule files into .throughline-rules/ to use as templates.',
    inputSchema: {},
  }, handler(() => tools.initExampleRules()));

  // ─── Reporting ───────────────────────────────────────────────────────

  server.registerTool('export_report', {
    title: 'Export a scan report',
    description: 'Scan and write a report to disk. SARIF suits GitHub/GitLab code scanning; HTML is a standalone interactive report.',
    inputSchema: {
      ...scanFilters,
      format: z.enum(['json', 'sarif', 'html', 'pretty']),
      outputPath: z.string().describe('Where to write the report.'),
    },
  }, handler(tools.exportReport));

  // ─── Triage: the AI review loop ──────────────────────────────────────

  server.registerTool('get_review_queue', {
    title: 'Get findings to review',
    description:
      'THE TRIAGE ENTRY POINT. Returns findings that have not been reviewed against their current code, ' +
      'each with surrounding source, a heuristic hint, and a codeHash. Read the context, decide whether ' +
      'each is genuinely exploitable here, then call submit_triage.',
    inputSchema: {
      limit: z.number().int().positive().max(25).optional().describe('How many to return. Default 10.'),
      severity: SEVERITY.optional().describe('Only review findings at this severity.'),
      contextRadius: z.number().int().positive().max(60).optional().describe('Source lines either side. Default 12.'),
      paths: z.array(z.string()).optional()
        .describe('Only used when no scan has run yet. Otherwise the queue is drawn from the most recent scan — so a filtered scan yields a filtered queue.'),
    },
  }, handler(tools.getReviewQueue));

  server.registerTool('submit_triage', {
    title: 'Submit triage verdicts',
    description:
      'Record your review verdicts. Findings marked isRealVulnerability=false are suppressed in later scans, ' +
      'with the suppression count still reported. Pass findingKey and codeHash back exactly as received — ' +
      'the hash ties your verdict to the code you read, so it is discarded if that code changes. ' +
      'Malformed verdicts are rejected rather than defaulted.',
    inputSchema: {
      triagedBy: z.string().optional().describe('Who reviewed, e.g. a model name. Recorded for audit.'),
      verdicts: z.array(z.object({
        findingKey: z.string().describe('Exactly as given in the review packet.'),
        codeHash: z.string().describe('Exactly as given in the review packet.'),
        isRealVulnerability: z.boolean().describe('Is this genuinely exploitable in this codebase?'),
        // Length is enforced in validateVerdict rather than here, so one weak
        // verdict is rejected individually instead of failing the whole batch.
        analysis: z.string().describe('Why. Name the sanitizer, the reaching path, or why input cannot be attacker-controlled. Must be a real explanation, not "looks fine".'),
        reviewConfidence: CONFIDENCE.optional().describe('Your confidence in this verdict.'),
        riskAssessment: z.string().optional().describe('Actual blast radius if real.'),
        exploitScenario: z.string().optional().describe('A concrete attack, if real.'),
        adjustedSeverity: SEVERITY.optional().describe('Set only if the scanner severity is wrong for this code.'),
        fix: z.string().optional().describe('A concrete patch for this code, not a generic tip.'),
        fixIsAutoApplicable: z.boolean().optional().describe('True if the fix can be applied without judgement.'),
        caveats: z.string().optional().describe('Anything the user still needs to verify.'),
      })).min(1),
    },
  }, handler(tools.submitTriage));

  server.registerTool('get_triage', {
    title: 'Get stored triage verdicts',
    description: 'Read the persisted review history, including which findings are suppressed and why.',
    inputSchema: { onlyFalsePositives: z.boolean().optional() },
  }, handler(tools.getTriage));

  server.registerTool('get_finding_context', {
    title: 'Read source around a location',
    description: 'Numbered source lines around a file:line, for judging a finding without loading the whole file.',
    inputSchema: {
      file: z.string(),
      line: z.number().int().positive(),
      radius: z.number().int().positive().max(200).optional().describe('Lines either side. Default 20.'),
    },
  }, handler(tools.getFindingContext));

  // ─── Fixes ───────────────────────────────────────────────────────────

  server.registerTool('suggest_fix', {
    title: 'Get fix scaffolding for a finding',
    description: 'Return the code around a finding plus a template patch for its rule, as a starting point for writing a real fix.',
    inputSchema: { findingKey: z.string().describe('From a scan or review packet.') },
  }, handler(tools.suggestFix));

  server.registerTool('apply_fix', {
    title: 'Apply a fix',
    description:
      'Replace an exact code string in a file and re-scan it. oldCode must match exactly and appear exactly once — ' +
      'ambiguous or missing matches are refused rather than guessed at.',
    inputSchema: {
      file: z.string(),
      oldCode: z.string().describe('Exact current code, including indentation.'),
      newCode: z.string().describe('Replacement code.'),
      expectedLine: z.number().int().positive().optional().describe('Guard: refuse if the match is more than 3 lines away.'),
    },
  }, handler(tools.applyFix));

  // ─── Cache ───────────────────────────────────────────────────────────

  server.registerTool('cache_stats', {
    title: 'Cache and triage statistics',
    description: 'Size of the incremental scan cache and a breakdown of stored triage verdicts.',
    inputSchema: {},
  }, handler(() => tools.getCacheStats()));

  server.registerTool('clear_cache', {
    title: 'Clear caches',
    description: 'Remove the incremental scan cache. Triage verdicts are kept unless includeTriage is set.',
    inputSchema: { includeTriage: z.boolean().optional().describe('Also delete every triage verdict. Not reversible.') },
  }, handler(tools.resetCache));

  // ─── Resources ───────────────────────────────────────────────────────

  server.registerResource('rules', 'throughline://rules', {
    title: 'Rule catalogue',
    description: 'Every detection rule with severity, CWE, and language coverage.',
    mimeType: 'application/json',
  }, async uri => ({
    contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(tools.listRules({}), null, 2) }],
  }));

  server.registerResource('last-scan', 'throughline://last-scan', {
    title: 'Last scan result',
    description: 'The complete, untruncated findings from the most recent scan in this session.',
    mimeType: 'application/json',
  }, async uri => {
    const last = tools.getLastScan();
    const body = last
      ? JSON.stringify({ at: last.at, paths: last.paths, ...last.result }, null, 2)
      : JSON.stringify({ note: 'No scan has run yet in this session. Call the scan tool first.' }, null, 2);
    return { contents: [{ uri: uri.href, mimeType: 'application/json', text: body }] };
  });

  server.registerResource('triage', 'throughline://triage', {
    title: 'Triage verdicts',
    description: 'Persisted review history: what was judged real, what was suppressed, and why.',
    mimeType: 'application/json',
  }, async uri => ({
    contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(tools.getTriage({}), null, 2) }],
  }));

  // ─── Prompts ─────────────────────────────────────────────────────────

  server.registerPrompt('security_review', {
    title: 'Security review',
    description: 'Scan a target, triage every finding, and report only what is genuinely exploitable.',
    argsSchema: {
      target: z.string().optional().describe('Path to review. Defaults to the whole project.'),
      minSeverity: z.string().optional().describe('Lowest severity worth reporting. Default medium.'),
    },
  }, ({ target, minSeverity }) => ({
    messages: [{
      role: 'user' as const,
      content: {
        type: 'text' as const,
        text: `Run a security review of ${target || 'this project'}.

1. Call scan with severity "${minSeverity || 'medium'}"${target ? ` and paths ["${target}"]` : ''}.
2. Call get_review_queue and read the source context in each packet.
3. For each finding decide whether it is genuinely exploitable *here* — is the input
   attacker-controlled, is there a sanitizer on the path, is this test-only code?
4. Call submit_triage with a verdict and specific reasoning for every finding.
5. Report only the confirmed issues, worst first. For each: what an attacker can do,
   and the concrete fix for this code. State separately how many you dismissed and why.

Do not pad the report with findings you judged false positives.`,
      },
    }],
  }));

  server.registerPrompt('review_my_changes', {
    title: 'Review current changes',
    description: 'Security review limited to the files changed on this branch.',
    argsSchema: { baseRef: z.string().optional().describe('Base ref to diff against. Default HEAD~1.') },
  }, ({ baseRef }) => ({
    messages: [{
      role: 'user' as const,
      content: {
        type: 'text' as const,
        text: `Review the security of my current changes.

Call scan_git_diff with baseRef "${baseRef || 'HEAD~1'}", then triage the findings with
get_review_queue and submit_triage. Report only issues my changes introduced — if a
finding is in code I did not touch, say so rather than blaming the diff.`,
      },
    }],
  }));

  server.registerPrompt('fix_vulnerability', {
    title: 'Fix a vulnerability',
    description: 'Fix one finding end to end, verifying the fix removes it.',
    argsSchema: { findingKey: z.string().describe('The findingKey from a scan or review packet.') },
  }, ({ findingKey }) => ({
    messages: [{
      role: 'user' as const,
      content: {
        type: 'text' as const,
        text: `Fix the vulnerability "${findingKey}".

1. suggest_fix to see the current code and a template.
2. Write a patch that fits this codebase's conventions — do not paste the template.
3. apply_fix with the exact old and new code.
4. Confirm from the re-scan that the finding is gone and no new one appeared.

If the fix needs a design change rather than a local edit, explain that instead of
applying a patch that only hides the pattern from the scanner.`,
      },
    }],
  }));

  return server;
}

/** Start the server on stdio. Used by the `throughline-mcp` bin and `throughline --mcp`. */
export async function startStdioServer(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // stdout is the protocol channel — status goes to stderr.
  console.error('[throughline-mcp] ready on stdio');
}

if (require.main === module) {
  startStdioServer().catch(err => {
    console.error('[throughline-mcp] fatal:', err);
    process.exit(1);
  });
}
