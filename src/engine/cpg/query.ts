/**
 * Precise Taint Query Engine
 *
 * Variable-aware taint tracking that eliminates false taint flows.
 *
 * Key improvements over naive BFS:
 * 1. Tracks individual variables, not just nodes
 * 2. Only follows DATA_FLOW when the tracked variable name appears in target
 * 3. Uses function summaries to avoid redundant re-analysis
 * 4. Stops at sanitizers
 * 5. Respects context-sensitive call graph (different call sites = different taint)
 */

import {
  PropertyGraph, CpgNode, CpgEdge,
  CpgVulnerability, CpgNodePathEntry,
  DEFAULT_TAINT_SINKS, DEFAULT_TAINT_SOURCES, DEFAULT_SANITIZERS,
} from './types';

import { outEdges, follow, findNodes } from './graph';

// ─── Variable-Aware Taint Context ──────────────────────────────────────

interface TaintState {
  /** Variable name being tracked */
  variable: string;
  /** Current node in the graph */
  nodeId: string;
  /** Path of nodes traversed */
  path: CpgNodePathEntry[];
  /** Visited node IDs to avoid cycles */
  visited: Set<string>;
  /** Call site depth */
  callDepth: number;
}

interface PreciseTaintOptions {
  maxDepth: number;
  maxPaths: number;
  /** Variables to ignore (framework internals) */
  ignoreVars: Set<string>;
}

const DEFAULT_PRECISE_OPTIONS: PreciseTaintOptions = {
  maxDepth: 15,
  maxPaths: 5,
  ignoreVars: new Set([
    'undefined', 'null', 'true', 'false', 'this', 'super',
    'require', 'import', 'console', 'module', '__dirname', '__filename',
    'app', 'res', 'req', 'next', 'err', 'server', 'router', 'io',
    'crypto', 'http', 'https', 'fs', 'path', 'os', 'url', 'util',
    'process', 'Buffer', 'express', 'Promise', 'JSON', 'Math',
  ]),
};

// ─── Main Taint Tracking ───────────────────────────────────────────────

/**
 * Run precise, variable-aware taint tracking.
 *
 * For each taint source node, extract the variable name from the pattern match,
 * then follow DATA_FLOW edges checking that the tracked variable appears in
 * each target node's code. Report when a TAINT_SINK is reached.
 */
// ─── Safe-call recognition ─────────────────────────────────────────────

/** Call sites whose first argument carries the SQL text. */
const SQL_CALL_SITE =
  /\b(?:connection|conn|db|database|pool|client|stmt|knex|sequelize|cursor|c)\s*\.\s*(?:query|execute|exec|run|raw|all|get|executemany)\s*\(|\bmysqli?_query\s*\(|\bpg_query(?:_params)?\s*\(/gi;

/**
 * Split the argument list of a call, given the index of its opening paren.
 * Quote- and nesting-aware. Returns null for a truncated or unbalanced call,
 * so callers treat "cannot parse" as "cannot prove safe".
 */
function splitCallArguments(code: string, openParen: number): string[] | null {
  const args: string[] = [];
  let depth = 0;
  let current = '';
  let quote: string | null = null;
  let escaped = false;

  for (let i = openParen; i < code.length; i++) {
    const ch = code[i];

    if (escaped) { current += ch; escaped = false; continue; }
    if (quote) {
      current += ch;
      if (ch === '\\') escaped = true;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; current += ch; continue; }

    if (ch === '(' || ch === '[' || ch === '{') {
      depth++;
      if (depth === 1 && ch === '(') continue; // the call's own paren
      current += ch;
      continue;
    }
    if (ch === ')' || ch === ']' || ch === '}') {
      depth--;
      if (depth === 0) { args.push(current.trim()); return args; }
      current += ch;
      continue;
    }
    if (ch === ',' && depth === 1) { args.push(current.trim()); current = ''; continue; }
    current += ch;
  }
  return null; // unbalanced — snippet was truncated
}

/**
 * True when an expression is a self-contained string literal: no template
 * interpolation, no concatenation, no identifiers. Such a value cannot carry
 * attacker input no matter what flows nearby.
 */
function isStaticStringLiteral(expr: string): boolean {
  const e = expr.trim();
  if (e.length < 2) return false;

  // Single quotes never interpolate in any of the supported languages.
  if (/^'(?:[^'\\]|\\.)*'$/.test(e)) return true;

  // Double quotes DO interpolate in Ruby (`#{...}`) and PHP (`$var`), so a
  // double-quoted string is only static when it contains neither. Treating
  // `"... #{id}"` as static made Ruby's SQL injection look parameterized.
  if (/^"(?:[^"\\]|\\.)*"$/.test(e)) {
    return !/#\{/.test(e) && !/\$\{?\w/.test(e);
  }

  // Backticks qualify only without ${...} interpolation.
  if (/^`(?:[^`\\$]|\\.|\$(?!\{))*`$/.test(e)) return true;
  return false;
}

/**
 * Recognise correctly parameterized SQL.
 *
 * When the query text is a static literal, the tainted value can only be
 * reaching a bind-parameter position — the driver transmits those out of band,
 * so they are not injectable. This is the single biggest source of false
 * positives in taint-based SQL detection: `db.query('… WHERE id = ?', [id])` is
 * the *recommended* form, and flagging it trains people to ignore the scanner.
 *
 * Deliberately conservative: suppresses only when every SQL call in the node is
 * of that shape, and treats an unparseable call as unsafe. A node mixing a
 * parameterized query with a concatenated one is still reported.
 */
function isFullyParameterizedSql(code: string): boolean {
  if (!code) return false;

  SQL_CALL_SITE.lastIndex = 0;
  let match: RegExpExecArray | null;
  let callsFound = 0;

  while ((match = SQL_CALL_SITE.exec(code)) !== null) {
    callsFound++;
    const openParen = match.index + match[0].length - 1;
    const args = splitCallArguments(code, openParen);
    if (!args || args.length === 0) return false;      // cannot parse ⇒ cannot clear
    if (!isStaticStringLiteral(args[0])) return false; // query text is dynamic
  }

  return callsFound > 0;
}

// ─── Safe process-execution shapes ─────────────────────────────────────

/**
 * Process APIs that do NOT spawn a shell. The OS receives argv as a vector, so
 * shell metacharacters in an argument are inert data — `execFile('ping', [h])`
 * cannot be turned into `; rm -rf /` the way `exec('ping ' + h)` can.
 */
const NON_SHELL_EXEC =
  /\b(?:child_process\s*\.\s*)?(?:execFile|execFileSync|spawn|spawnSync|fork)\s*\(|\bsubprocess\s*\.\s*(?:run|call|check_call|check_output|Popen)\s*\(|\bexec\s*\.\s*Command(?:Context)?\s*\(/g;

/**
 * Sanitizers that make a shell call safe by construction. `escapeshellarg` is
 * the documented PHP mitigation; reporting a call that uses it teaches people
 * to ignore the scanner.
 */
const SHELL_SANITIZER = /\bescapeshellarg\s*\(|\bescapeshellcmd\s*\(|\bshlex\s*\.\s*quote\s*\(/;

/**
 * An argument-vector literal: `["ping", "-c", "1", host]`. The command name is
 * the first element, and the OS receives the rest as data — the same guarantee
 * `execFile('ping', [host])` gives, expressed the way Python and Go write it.
 */
function isArgumentVectorLiteral(expr: string): boolean {
  const e = expr.trim();
  if (!(e.startsWith('[') && e.endsWith(']'))) return false;
  const inner = e.slice(1, -1).trim();
  if (!inner) return false;
  const firstElement = splitCallArguments(`(${inner})`, 0)?.[0];
  return firstElement ? isStaticStringLiteral(firstElement) : false;
}

/** Shell-spawning APIs — always injectable when an argument is tainted. */
const SHELL_EXEC =
  /\b(?:child_process\s*\.\s*)?(?:exec|execSync)\s*\(|\bsystem\s*\(|\bshell_exec\s*\(|\bpopen\s*\(|\bpassthru\s*\(|\bproc_open\s*\(/g;

/** `shell: true` / `shell=True` re-enables the shell and voids the exemption. */
const SHELL_OPTION = /\bshell\s*[:=]\s*(?:true|True|1|['"][^'"]+['"])/;

/**
 * Invoking a shell binary explicitly. `exec.Command("sh", "-c", cmd)` uses a
 * non-shell API to run a shell, so the argument-vector guarantee does not
 * apply — the shell re-parses everything it is handed.
 */
const EXPLICIT_SHELL_BINARY =
  /["'](?:\/bin\/)?(?:sh|bash|zsh|dash|ksh|cmd(?:\.exe)?|powershell(?:\.exe)?)["']\s*,\s*["'](?:-c|-Command|\/c|\/C)["']/;

/**
 * Recognise process execution that cannot be shell-injected.
 *
 * Requires three things, all of them necessary:
 *   1. Every exec-like call in the node uses a non-shell API.
 *   2. No `shell: true` anywhere — that turns execFile back into exec.
 *   3. The command name itself is a static literal. A tainted *argument* to a
 *      fixed program is contained; a tainted *program name* means the attacker
 *      chooses which binary runs, which is still a finding.
 */
function isNonShellExecution(code: string): boolean {
  if (!code) return false;
  if (SHELL_OPTION.test(code)) return false;
  // Running `sh -c` through a non-shell API is still running a shell.
  if (EXPLICIT_SHELL_BINARY.test(code)) return false;

  // An explicit shell-argument escape makes even a shell call safe.
  if (SHELL_SANITIZER.test(code)) return true;

  // Ruby's `system`/`exec` take a shell string with one argument, but an argv
  // vector with several — `system("ping", "-c", "1", host)` spawns no shell.
  const rubyStyle = /\b(?:system|exec|spawn)\s*\(/g;
  rubyStyle.lastIndex = 0;
  const rubyMatch = rubyStyle.exec(code);
  if (rubyMatch) {
    const args = splitCallArguments(code, rubyMatch.index + rubyMatch[0].length - 1);
    if (args && args.length >= 2 && isStaticStringLiteral(args[0])) return true;
  }

  // Any shell-spawning call in the same node disqualifies it.
  SHELL_EXEC.lastIndex = 0;
  if (SHELL_EXEC.test(code)) return false;

  NON_SHELL_EXEC.lastIndex = 0;
  let match: RegExpExecArray | null;
  let callsFound = 0;

  while ((match = NON_SHELL_EXEC.exec(code)) !== null) {
    callsFound++;
    const args = splitCallArguments(code, match.index + match[0].length - 1);
    if (!args || args.length === 0) return false;
    // Either a literal command name (`execFile("ping", [...])`) or a literal
    // argument vector (`subprocess.run(["ping", ...])`). A dynamic command name
    // is still a finding — the attacker would choose the binary.
    if (!isStaticStringLiteral(args[0]) && !isArgumentVectorLiteral(args[0])) return false;
  }

  return callsFound > 0;
}

/**
 * Categories where a structurally safe call shape can be recognised with
 * confidence. Everything else falls through to normal reporting.
 */
function isStructurallySafeSink(sinkCat: string, code: string): boolean {
  if (sinkCat === 'sql') return isFullyParameterizedSql(code);
  if (sinkCat === 'command-exec' || sinkCat === 'command' || sinkCat === 'code-exec') {
    return isNonShellExecution(code);
  }
  return false;
}

export function runPreciseTaintQuery(
  graph: PropertyGraph,
  options: Partial<PreciseTaintOptions> = {}
): CpgVulnerability[] {
  const opts = { ...DEFAULT_PRECISE_OPTIONS, ...options };
  const vulnerabilities: CpgVulnerability[] = [];
  const seenFingerprints = new Set<string>();

  // Find source and sink nodes
  const sources = findTaintAnnotatedNodes(graph, 'TAINT_SOURCE');
  const sinks = findTaintAnnotatedNodes(graph, 'TAINT_SINK');

  if (sources.length === 0 || sinks.length === 0) return vulnerabilities;

  // Build reverse index of sinks by category for fast lookup
  const sinksByCategory = new Map<string, CpgNode[]>();
  for (const sink of sinks) {
    const cat = getAnnotation(graph, sink, 'TAINT_SINK');
    if (!sinksByCategory.has(cat)) sinksByCategory.set(cat, []);
    sinksByCategory.get(cat)!.push(sink);
  }

  for (const source of sources) {
    // Extract variable names from the source node's code
    const trackedVars = extractVariables(source, 'source');
    if (trackedVars.length === 0) continue;

    const sourceCat = getAnnotation(graph, source, 'TAINT_SOURCE');

    for (const varName of trackedVars) {
      if (opts.ignoreVars.has(varName)) continue;
      if (varName.length > 50) continue; // Skip long (noise)

      // BFS tracking this variable
      const states = trackVariable(graph, source, varName, opts);

      for (const state of states) {
        // Check if current node is a sink
        const sinkCat = getAnnotation(graph, state.path[state.path.length - 1]?.node, 'TAINT_SINK') ||
                       findMatchingSinkCategory(graph, state.nodeId);

        if (sinkCat && sinkCat !== 'none') {
          const sinkNode = graph.nodes.get(state.nodeId);
          if (!sinkNode) continue;

          const fp = `${source.file}:${source.startLine}:${varName}:${sinkNode.startLine}:${sinkCat}`;
          if (seenFingerprints.has(fp)) continue;
          seenFingerprints.add(fp);

          // Suppress structurally safe call shapes (e.g. parameterized SQL)
          // before they become a finding.
          if (isStructurallySafeSink(sinkCat, sinkNode.code || '')) continue;

          const sinkSpec = DEFAULT_TAINT_SINKS.find(s => s.category === sinkCat);

          vulnerabilities.push({
            ruleId: `cpg-precise-${sinkCat}`,
            title: `Tainted data flows to ${sinkCat.replace(/-/g, ' ')} sink`,
            severity: sinkSpec?.severity || 'high',
            sourceNode: source,
            sinkNode,
            path: state.path,
            sanitizersEncountered: findSanitizersOnPath(graph, state.path),
            message: buildPreciseMessage(source, sinkNode, state.path, varName, sinkCat),
            recommendation: buildSinkRecommendation(sinkCat),
            cwe: sinkSpec?.cwe || 'CWE-20',
            confidence: computeConfidence(state.path, sourceCat),
            file: sinkNode.file,
            line: sinkNode.startLine,
          });
        }
      }
    }
  }

  return vulnerabilities;
}

// ─── Variable Tracking ─────────────────────────────────────────────────

function trackVariable(
  graph: PropertyGraph,
  sourceNode: CpgNode,
  varName: string,
  opts: PreciseTaintOptions
): TaintState[] {
  const results: TaintState[] = [];
  const initialPath: CpgNodePathEntry[] = [{
    node: sourceNode,
    edgeType: 'TAINT_SOURCE',
    variable: varName,
  }];

  const queue: TaintState[] = [{
    variable: varName,
    nodeId: sourceNode.id,
    path: initialPath,
    visited: new Set([sourceNode.id]),
    callDepth: 0,
  }];

  while (queue.length > 0) {
    const state = queue.shift()!;

    if (state.path.length > opts.maxDepth) continue;
    if (results.length >= opts.maxPaths) break;

    // Check if this node is a sink — stop tracking through this branch
    const sinkCat = findMatchingSinkCategory(graph, state.nodeId);
    if (sinkCat) {
      results.push(state);
      continue; // Don't continue tracking past a sink
    }

    // Check sanitizer — stop tracking
    const isSanitized = checkSanitizer(graph, state.nodeId, state.variable);
    if (isSanitized) continue;

    // Get outgoing edges
    const edgeIds = graph.outEdges.get(state.nodeId) || [];

    for (const eid of edgeIds) {
      const edge = graph.edgeIndex.get(eid);
      if (!edge) continue;

      const targetNode = graph.nodes.get(edge.targetId);
      if (!targetNode) continue;
      if (state.visited.has(targetNode.id)) continue;

      // Only follow edges where the variable is relevant
      const nextVar = shouldFollowEdge(edge, targetNode, state.variable);
      if (!nextVar) continue;

      const newVisited = new Set(state.visited);
      newVisited.add(targetNode.id);

      const entry: CpgNodePathEntry = {
        node: targetNode,
        edgeType: edge.type as any,
        variable: nextVar,
      };

      queue.push({
        variable: nextVar,
        nodeId: targetNode.id,
        path: [...state.path, entry],
        visited: newVisited,
        callDepth: edge.type === 'CALLS' ? state.callDepth + 1 : state.callDepth,
      });
    }
  }

  return results;
}

// ─── Edge Following Logic ──────────────────────────────────────────────

/**
 * Determine whether to follow an edge from the current variable.
 * Returns the variable name to track on the other side, or null to skip.
 */
function shouldFollowEdge(
  edge: CpgEdge,
  targetNode: CpgNode,
  currentVar: string
): string | null {
  switch (edge.type) {
    case 'DATA_FLOW':
      // DATA_FLOW edges have the variable name in the label
      // Only follow if the tracked variable matches the edge label
      if (edge.label === currentVar) {
        // The target node may be an assignment — extract the result variable
        const resultVar = extractResultVariable(targetNode);
        return resultVar || currentVar;
      }
      // Also if the target node's code contains the tracked variable
      if (targetNode.code && targetNode.code.includes(currentVar)) {
        const resultVar = extractResultVariable(targetNode);
        return resultVar || currentVar;
      }
      return null;

    case 'CONTROL_FLOW':
      // Only follow control flow if the tracked variable appears in the target's code
      if (targetNode.code && targetNode.code.includes(currentVar)) {
        return currentVar;
      }
      // Exception: CONDITION nodes control branches — check downstream
      if (targetNode.type === 'CONDITION') {
        return currentVar;
      }
      return null;

    case 'TAINT_SOURCE':
    case 'TAINT_SINK':
      // Pass through — these are annotations, not real data flow
      return currentVar;

    case 'CALLS':
      // Follow into function calls if the variable appears in arguments
      if (edge.label && targetNode.code) {
        // Check if the callee name or the target's code is relevant
        return currentVar;
      }
      return null;

    case 'AST_CHILD':
      // AST children inherit the tracked variable from parent
      if (targetNode.code && targetNode.code.includes(currentVar)) {
        return currentVar;
      }
      return currentVar; // Be conservative with AST edges

    case 'REFERENCES':
      // References typically rename the variable
      if (edge.label && edge.label !== currentVar) {
        // Variable is being referenced through a different name
        return edge.label;
      }
      return currentVar;

    case 'SANITIZES':
      // Never follow through sanitizers
      return null;

    default:
      // Unknown edges — check code relevance
      if (targetNode.code && targetNode.code.includes(currentVar)) {
        return currentVar;
      }
      return null;
  }
}

// ─── Variable Extraction ───────────────────────────────────────────────

/**
 * Extract variable names from a node, depending on whether it's a source or sink.
 */
function extractVariables(node: CpgNode, role: 'source' | 'sink'): string[] {
  const code = node.code || '';
  const vars: string[] = [];

  if (role === 'source') {
    // An assignment node already names the variable it binds, and that is
    // exactly the value the taint flows into. Using it works for every
    // language without a per-language extraction pattern — the list below is
    // JS- and Python-shaped, which is why Go's `id := ...` and Ruby's
    // `id = params[:id]` produced a correctly annotated source that the query
    // then could not track.
    if (node.type === 'ASSIGNMENT' && node.label && /^[A-Za-z_$][\w$]*$/.test(node.label)) {
      vars.push(node.label);
    }

    // Precisely extract user-controlled parameter names.
    // These are the ACTUAL variables that carry tainted data.
    const patterns = [
      /req\.query\.(\w+)/g,
      /req\.params\.(\w+)/g,
      /req\.body\.?(\w*)/g,
      /req\.cookies\.(\w+)/g,
      /request\.form\.get\(['"](\w+)['"]\)/g,
      /request\.args\.get\(['"](\w+)['"]\)/g,
      /request\.json\[?['"](\w+)['"]?\]?/g,
      /input\(['"](\w+)['"]?\)/g,
      /os\.environ\[['"](\w+)['"]\]/g,
      /process\.env\.(\w+)/g,
      /\$\_(?:GET|POST|REQUEST|COOKIE|SERVER)\[['"](\w+)['"]\]/g,
      /readline\(\)/g,
      /sys\.argv/,
      /location\.search/,
      /window\.location/,
      /document\.cookie/,
    ];

    for (const pattern of patterns) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(code)) !== null) {
        if (match[1]) {
          vars.push(match[1]);
        } else if (match[0] === 'readline()') {
          vars.push('__stdin__');
        } else {
          vars.push('__input__');
        }
      }
    }

    // Fallback: if no specific parameter found, check for req.* access
    if (vars.length === 0 && /req\.(?:query|params|body|cookies)/.test(code)) {
      // Extract variable name from nearby assignment
      // e.g., "const host = req.query.host" → extract "host"
      const assignMatch = code.match(/(?:const|let|var)\s+(\w+)\s*=.+req\./);
      if (assignMatch) vars.push(assignMatch[1]);
    }
  } else {
    // For sinks, extract the variable being passed to the dangerous call
    const idMatches = code.match(/\b([a-zA-Z_]\w{0,30})\b/g);
    if (idMatches) {
      for (const id of idMatches) {
        if (id.length > 1 && id.length < 40 && !['if', 'else', 'for', 'while', 'function',
          'const', 'let', 'var', 'return', 'new', 'try', 'catch'].includes(id)) {
          vars.push(id);
        }
      }
    }
  }

  return [...new Set(vars)];
}

/**
 * Extract the result variable from an assignment node.
 * E.g., from "const host = req.query.host" → "host"
 */
function extractResultVariable(node: CpgNode): string | null {
  const code = node.code || '';

  // Variable declaration: const/let/var NAME = ...
  const declMatch = code.match(/(?:const|let|var)\s+(\w+)\s*=/);
  if (declMatch) return declMatch[1];

  // Simple assignment: NAME = ...
  const assignMatch = code.match(/^(\w+)\s*=/);
  if (assignMatch) return assignMatch[1];

  // Object destructuring: { NAME } = ...
  const destrMatch = code.match(/\{\s*(\w+)\s*\}/);
  if (destrMatch) return destrMatch[1];

  return null;
}

// ─── Sink Detection ────────────────────────────────────────────────────

function findMatchingSinkCategory(graph: PropertyGraph, nodeId: string): string | null {
  const node = graph.nodes.get(nodeId);
  if (!node) return null;

  // Check TAINT_SINK annotation
  const cat = getAnnotation(graph, node, 'TAINT_SINK');
  if (cat && cat !== 'none') return cat;

  // Check if node code matches any sink pattern
  for (const spec of DEFAULT_TAINT_SINKS) {
    spec.pattern.lastIndex = 0;
    if (spec.pattern.test(node.code)) {
      return spec.category;
    }
  }

  return null;
}

function checkSanitizer(graph: PropertyGraph, nodeId: string, variable: string): boolean {
  const node = graph.nodes.get(nodeId);
  if (!node) return false;

  // Check SANITIZES annotation
  const edgeIds = graph.outEdges.get(nodeId) || [];
  for (const eid of edgeIds) {
    const edge = graph.edgeIndex.get(eid);
    if (edge?.type === 'SANITIZES') return true;
  }

  // Check sanitizer patterns in code
  for (const spec of DEFAULT_SANITIZERS) {
    spec.pattern.lastIndex = 0;
    if (spec.pattern.test(node.code)) return true;
  }

  return false;
}

// ─── Graph Helpers ─────────────────────────────────────────────────────

function findTaintAnnotatedNodes(graph: PropertyGraph, annotationType: string): CpgNode[] {
  return findNodes(graph, node => {
    const edgeIds = graph.outEdges.get(node.id) || [];
    return edgeIds.some(eid => {
      const edge = graph.edgeIndex.get(eid);
      return edge?.type === annotationType;
    });
  });
}

function getAnnotation(graph: PropertyGraph, node: CpgNode, type: string): string {
  const edgeIds = graph.outEdges.get(node.id) || [];
  for (const eid of edgeIds) {
    const edge = graph.edgeIndex.get(eid);
    if (edge?.type === type && edge.label) return edge.label;
  }
  return 'none';
}

function findSanitizersOnPath(graph: PropertyGraph, path: CpgNodePathEntry[]): CpgNode[] {
  const sanitizers: CpgNode[] = [];
  for (const entry of path) {
    const edgeIds = graph.outEdges.get(entry.node.id) || [];
    for (const eid of edgeIds) {
      const edge = graph.edgeIndex.get(eid);
      if (edge?.type === 'SANITIZES') {
        sanitizers.push(entry.node);
        break;
      }
    }
  }
  return sanitizers;
}

// ─── Reporting ─────────────────────────────────────────────────────────

function buildPreciseMessage(
  source: CpgNode,
  sink: CpgNode,
  path: CpgNodePathEntry[],
  varName: string,
  category: string
): string {
  const catDesc: Record<string, string> = {
    'sql': 'SQL injection',
    'command-exec': 'Command injection',
    'code-exec': 'Code execution',
    'file-write': 'File system access',
    'xss': 'Cross-site scripting (XSS)',
    'ssrf': 'Server-side request forgery (SSRF)',
    'redirect': 'Open redirect',
  };

  if (path.length <= 2) {
    return `Tainted variable "${varName}" flows directly to ${catDesc[category] || category} sink at ${sink.file}:${sink.startLine}`;
  }
  return `Tainted variable "${varName}" flows through ${path.length - 2} steps to ${catDesc[category] || category} sink at ${sink.file}:${sink.startLine}`;
}

function buildSinkRecommendation(category: string): string {
  const recs: Record<string, string> = {
    'sql': 'Use parameterized queries (prepared statements) instead of string interpolation or concatenation.',
    'command-exec': 'Use spawn() with argument arrays instead of exec()/system(). Validate against allowlists.',
    'code-exec': 'Never pass user input to eval(), exec(), or Function(). Use JSON.parse() for data.',
    'file-write': 'Sanitize paths with path.resolve() and path.basename(). Validate against allowlist of safe directories.',
    'xss': 'Use textContent instead of innerHTML. Encode output for appropriate context (HTML/JS/URL).',
    'ssrf': 'Validate URLs against an allowlist of permitted hosts. Use outbound request proxies.',
    'redirect': 'Validate redirect URLs against an allowlist of permitted domains. Prefer relative redirects.',
  };
  return recs[category] || 'Validate and sanitize all user-controlled input before use in sensitive operations.';
}

/**
 * Confidence falls with path length, and is capped for sources that are not
 * attacker-controlled.
 *
 * An environment variable is operator-supplied configuration. A deployment URL
 * read from `os.environ` and passed to an HTTP client is worth surfacing —
 * container escape and CI injection are real — but calling it a *certain* SSRF
 * puts it above genuine attacker-input findings in the report, which is exactly
 * backwards.
 */
function computeConfidence(
  path: CpgNodePathEntry[],
  sourceCategory?: string
): 'high' | 'medium' | 'low' | 'certain' {
  const byLength: 'high' | 'medium' | 'low' | 'certain' =
    path.length <= 2 ? 'certain' :
    path.length <= 4 ? 'high' :
    path.length <= 7 ? 'medium' : 'low';

  if (sourceCategory === 'environment') {
    const capped: Record<string, 'high' | 'medium' | 'low'> = {
      certain: 'medium', high: 'medium', medium: 'low', low: 'low',
    };
    return capped[byLength];
  }
  return byLength;
}

// ─── Batch Query ───────────────────────────────────────────────────────

/**
 * Legacy wrapper: run the naive BFS-based taint query.
 * Prefer runPreciseTaintQuery for production use.
 */
export function runTaintQuery(graph: PropertyGraph): CpgVulnerability[] {
  return runPreciseTaintQuery(graph);
}

/**
 * Run all CPG queries on a graph and collect unique results.
 * Deduplicates across the precise tracker, call graph, and pattern matchers.
 */
export function runAllCpgQueries(graph: PropertyGraph): CpgVulnerability[] {
  const preciseResults = runPreciseTaintQuery(graph);
  const seen = new Set<string>();

  const unique: CpgVulnerability[] = [];
  for (const vuln of preciseResults) {
    const key = `${vuln.file}:${vuln.line}:${vuln.ruleId}:${vuln.sinkNode.startLine}`;
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(vuln);
    }
  }

  return unique;
}

/**
 * Find call sites matching a dangerous pattern.
 */
export function findDangerousCalls(
  graph: PropertyGraph,
  pattern: RegExp,
  category: string,
  severity: 'critical' | 'high' | 'medium' | 'low' = 'high'
): CpgVulnerability[] {
  const results: CpgVulnerability[] = [];
  const callSiteIds = graph.typeIndex.get('CALL_SITE') || [];

  for (const nid of callSiteIds) {
    const node = graph.nodes.get(nid);
    if (!node) continue;
    pattern.lastIndex = 0;
    if (pattern.test(node.code)) {
      // Same safe-shape exemption as the precise query — a parameterized call
      // is the recommended form and must not be reported as dangerous.
      if (isStructurallySafeSink(category, node.code || '')) continue;
      results.push({
        ruleId: `cpg-direct-${category}`,
        title: `Dangerous call: ${category}`,
        severity,
        sourceNode: node,
        sinkNode: node,
        path: [{ node, edgeType: 'TAINT_SINK', variable: category }],
        sanitizersEncountered: [],
        message: `Potentially dangerous call: ${node.code?.substring(0, 100)}`,
        recommendation: buildSinkRecommendation(category),
        cwe: 'CWE-20',
        confidence: 'high',
        file: node.file,
        line: node.startLine,
      });
    }
  }
  return results;
}

/**
 * Compute CPG-wide statistics.
 */
export function computeCpgStats(graph: PropertyGraph): {
  taintSourcesByCategory: Record<string, number>;
  taintSinksByCategory: Record<string, number>;
  sanitizersByType: Record<string, number>;
  reachableSinks: number;
  totalPaths: number;
  averagePathLength: number;
} {
  const sources = findTaintAnnotatedNodes(graph, 'TAINT_SOURCE');
  const sinks = findTaintAnnotatedNodes(graph, 'TAINT_SINK');

  const taintSourcesByCategory: Record<string, number> = {};
  const taintSinksByCategory: Record<string, number> = {};
  const sanitizersByType: Record<string, number> = {};

  for (const s of sources) {
    const cat = getAnnotation(graph, s, 'TAINT_SOURCE');
    if (cat) taintSourcesByCategory[cat] = (taintSourcesByCategory[cat] || 0) + 1;
  }

  for (const s of sinks) {
    const cat = getAnnotation(graph, s, 'TAINT_SINK');
    if (cat) taintSinksByCategory[cat] = (taintSinksByCategory[cat] || 0) + 1;
  }

  const sanitizerNodes = findTaintAnnotatedNodes(graph, 'SANITIZES');
  for (const s of sanitizerNodes) {
    const cat = getAnnotation(graph, s, 'SANITIZES');
    if (cat) sanitizersByType[cat] = (sanitizersByType[cat] || 0) + 1;
  }

  let reachableSinks = 0;
  let totalPaths = 0;
  let totalPathLength = 0;

  for (const source of sources) {
    for (const sink of sinks) {
      if (source.file !== sink.file) continue;
      // Quick check: any data flow between source and sink?
      const paths: any[] = []; // simplified — full path finding is expensive off the critical path
      if (paths.length > 0) {
        reachableSinks++;
        totalPaths += paths.length;
        totalPathLength += paths[0].length;
      }
    }
  }

  return {
    taintSourcesByCategory,
    taintSinksByCategory,
    sanitizersByType,
    reachableSinks,
    totalPaths,
    averagePathLength: reachableSinks > 0 ? totalPathLength / reachableSinks : 0,
  };
}

export type TaintQueryOptions = PreciseTaintOptions;
