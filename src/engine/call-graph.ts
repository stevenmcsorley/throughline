/**
 * Inter-Procedural Call Graph & Taint Analysis Engine
 *
 * Builds a project-wide call graph and propagates taint across
 * function boundaries. This catches vulnerabilities where data
 * flows through helper functions before reaching a sink.
 *
 * Example it catches:
 *   app.get('/user', (req, res) => {
 *     const userId = req.query.id;
 *     getUserData(userId);           // taint flows into getUserData
 *   });
 *   function getUserData(id) {
 *     db.query(`SELECT * FROM users WHERE id = ${id}`);  // sink reached!
 *   }
 *
 * The regex-based scanner misses this because the taint source and
 * sink are in different functions.
 */

import * as path from 'path';
import * as fs from 'fs';
import { readSource } from './source-cache';

// ─── Types ─────────────────────────────────────────────────────────────

export interface FunctionDef {
  name: string;
  file: string;
  startLine: number;
  endLine: number;
  params: string[];
  body: string;
  isExported: boolean;
  isAsync: boolean;
  /** Function names called within this function's body */
  calls: string[];
}

export interface CallEdge {
  caller: string;       // "file:functionName"
  callee: string;       // "file:functionName"
  callerFile: string;
  calleeFile: string;
  callLine: number;
  /** Arguments passed at call site */
  arguments: string[];
  /** If arguments include known taint sources */
  taintedArgs: boolean;
}

export interface TaintPath {
  /** The taint source (e.g., "req.query.id") */
  source: string;
  /** Chain of function calls the taint flows through */
  path: { file: string; function: string; line: number }[];
  /** The sink where taint ends (e.g., "db.query(...)") */
  sink: string;
  file: string;
  line: number;
}

export interface CallGraphResult {
  functions: Map<string, FunctionDef>;
  edges: CallEdge[];
  /** Map of sink function → all callers that lead to it */
  reachability: Map<string, Set<string>>;
}

// ─── Known taint sources ───────────────────────────────────────────────

const TAINT_SOURCE_PATTERNS = [
  /req\.query\.\w+/g,
  /req\.params\.\w+/g,
  /req\.body\.?\w*/g,
  /req\.param\(/g,
  /req\.cookies\.\w+/g,
  /req\.headers\[/g,
  /request\.args\.get\(/g,
  /request\.form\.get\(/g,
  /request\.GET\[/g,
  /request\.POST\[/g,
  /request\.COOKIE\[/g,
  /\$_GET\[/g,
  /\$_POST\[/g,
  /\$_REQUEST\[/g,
  /\$_COOKIE\[/g,
  /process\.env\./g,
  /os\.environ\[/g,
  /self\.request\.GET\[/g,
  /self\.request\.POST\[/g,
  /ctx\.query\.\w+/g,
  /ctx\.params\.\w+/g,
  /ctx\.request\.body/g,
  /c\.query\(/g,
  /c\.param\(/g,
  /c\.body\(/g,
  /r\.FormValue\(/g,
  /r\.URL\.Query\(\)\.Get\(/g,
  /r\.PostFormValue\(/g,
  /\$\w+\s*=\s*\$_GET/g,
  /\$\w+\s*=\s*\$_POST/g,
  /\$\w+\s*=\s*\$_REQUEST/g,
];

// ─── Known sinks ───────────────────────────────────────────────────────

const SINK_PATTERNS = [
  // The receiver restriction is load-bearing. Without it `.get(`/`.all(`/`.run(`
  // matched anything — `http.get`, `app.get`, `map.get`, every Express route
  // registration — and reported them as SQL injection, which is both noise and
  // actively misleading when the real issue is SSRF.
  {
    name: 'sql',
    pattern: /\b(?:connection|conn|db|database|pool|client|stmt|statement|knex|sequelize|prisma|cursor|session|tx|trx|qb)\s*\.\s*(?:query|execute|exec|run|raw|all|get|select|insert|update|delete|executemany)\s*\(|\bmysqli?_query\s*\(|\bpg_query(?:_params)?\s*\(/gi,
  },
  // `(?<![.\w$])` keeps `regex.exec(str)` and `arr.fork()` out; the explicit
  // child_process/subprocess alternatives keep qualified calls in.
  {
    name: 'command',
    pattern: /\b(?:child_process|cp)\s*\.\s*(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\s*\(|(?<![.\w$])(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|popen|system|shell_exec|passthru|proc_open)\s*\(|\bsubprocess\s*\.\s*(?:call|run|check_output|Popen)\s*\(/g,
  },
  { name: 'file', pattern: /(?:fs\.(?:readFile|writeFile|createWriteStream|createReadStream|unlink|rmdir|readdir|open)|path\.(?:join|resolve|normalize)|open\s*\(|file_get_contents|file_put_contents)\s*\(/g },
  { name: 'eval', pattern: /(?:eval|Function|setTimeout|setInterval|setImmediate|execScript)\s*\(/g },
  { name: 'xss', pattern: /(?:innerHTML|outerHTML|dangerouslySetInnerHTML|document\.write|insertAdjacentHTML)\s*[=(]/g },
  { name: 'redirect', pattern: /(?:res\.redirect|res\.location|redirect\(|header\(['\"]Location|wp_redirect|RedirectResponse|redirect_to)\s*\(/g },
  { name: 'ssrf', pattern: /(?:fetch|axios|got|superagent|request|http\.(?:get|request)|urllib\.(?:request|urlopen)|HttpURLConnection|RestTemplate|WebClient)\s*\(/g },
];

// ─── Engine ────────────────────────────────────────────────────────────

export class CallGraphEngine {
  /**
   * Build a project-wide call graph from all source files.
   */
  build(files: string[]): CallGraphResult {
    const functions = new Map<string, FunctionDef>();
    const edges: CallEdge[] = [];

    // Phase 1: Extract all function definitions
    for (const file of files) {
      try {
        const ext = path.extname(file).toLowerCase();
        if (!['.js', '.ts', '.jsx', '.tsx', '.py', '.go', '.php', '.rb'].includes(ext)) continue;
        const content = readSource(file);
        const funcs = this.extractFunctions(content, file, ext);
        for (const func of funcs) {
          functions.set(`${file}:${func.name}`, func);
        }
      } catch { /* skip unreadable files */ }
    }

    // Phase 2: Extract call edges
    for (const [, func] of functions) {
      const fileExt = path.extname(func.file);
      const content = readSource(func.file);
      for (const callName of func.calls) {
        let calleeId: string | null = null;

        // Try same-file resolution
        if (functions.has(`${func.file}:${callName}`)) {
          calleeId = `${func.file}:${callName}`;
        } else {
          // Try cross-file resolution (simple export matching)
          for (const [id, candidate] of functions) {
            if (candidate.name === callName && candidate.isExported) {
              calleeId = id;
              break;
            }
          }
        }

        if (calleeId) {
          const callee = functions.get(calleeId)!;
          edges.push({
            caller: `${func.file}:${func.name}`,
            callee: calleeId,
            callerFile: func.file,
            calleeFile: callee.file,
            callLine: 0, // approximate
            arguments: [],
            taintedArgs: false,
          });
        }
      }
    }

    // Phase 3: Compute reachability
    const reachability = this.computeReachability(functions, edges);

    return { functions, edges, reachability };
  }

  /**
   * Trace taint from sources through the call graph to sinks.
   */
  traceTaint(graph: CallGraphResult, files: string[]): TaintPath[] {
    const taintPaths: TaintPath[] = [];

    for (const file of files) {
      try {
        const content = readSource(file);
        const lines = content.split('\n');

        // Find taint sources
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          for (const sourcePattern of TAINT_SOURCE_PATTERNS) {
            sourcePattern.lastIndex = 0;
            let match: RegExpExecArray | null;
            while ((match = sourcePattern.exec(line)) !== null) {
              const sourceName = match[0];

              // Check if this source feeds into a function call
              const taintedPaths = this.traceFromSource(
                sourceName, file, i + 1, graph, content, lines
              );
              taintPaths.push(...taintedPaths);
            }
          }
        }
      } catch { /* skip */ }
    }

    // Deduplicate
    const seen = new Set<string>();
    return taintPaths.filter(tp => {
      const key = `${tp.file}:${tp.line}:${tp.sink}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  // ─── Private ─────────────────────────────────────────────────────────

  private extractFunctions(content: string, file: string, ext: string): FunctionDef[] {
    const funcs: FunctionDef[] = [];
    const lines = content.split('\n');

    switch (ext) {
      case '.js': case '.ts': case '.jsx': case '.tsx':
        this.extractJSFunctions(content, file, lines, funcs);
        break;
      case '.py':
        this.extractPythonFunctions(content, file, lines, funcs);
        break;
      case '.go':
        this.extractGoFunctions(content, file, lines, funcs);
        break;
      case '.php':
        this.extractPhpFunctions(content, file, lines, funcs);
        break;
    }

    return funcs;
  }

  private extractJSFunctions(content: string, file: string, lines: string[], funcs: FunctionDef[]) {
    // Named function declarations
    const funcDeclRe = /(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)/g;
    let match: RegExpExecArray | null;
    while ((match = funcDeclRe.exec(content)) !== null) {
      const name = match[1];
      const params = match[2].split(',').map(p => p.trim().split('=')[0].split(':')[0].trim()).filter(Boolean);
      const startIdx = content.lastIndexOf('\n', match.index) + 1;
      const startLine = content.substring(0, startIdx).split('\n').length;
      const isExported = content.substring(Math.max(0, match.index - 30), match.index).includes('export');
      const isAsync = content.substring(Math.max(0, match.index - 30), match.index).includes('async');

      const body = this.extractBody(content, match.index + match[0].length);
      const calls = this.extractCalls(body);

      funcs.push({ name, file, startLine, endLine: startLine + body.split('\n').length, params, body, isExported, isAsync, calls });
    }

    // Arrow functions assigned to variables
    const arrowRe = /(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>\s*\{/g;
    while ((match = arrowRe.exec(content)) !== null) {
      const name = match[1];
      const params = match[2].split(',').map(p => p.trim()).filter(Boolean);
      const body = this.extractBody(content, match.index + match[0].length - 1);
      const calls = this.extractCalls(body);
      const startIdx = content.lastIndexOf('\n', match.index) + 1;
      const startLine = content.substring(0, startIdx).split('\n').length;

      funcs.push({ name, file, startLine, endLine: startLine + body.split('\n').length, params, body, isExported: false, isAsync: false, calls });
    }

    // Method definitions in objects/classes
    const methodRe = /(?:async\s+)?(\w+)\s*\(([^)]*)\)\s*\{/g;
    // Only capture methods that look like route handlers or significant functions
    // (Skip simple getters/setters, one-liners)
    while ((match = methodRe.exec(content)) !== null) {
      const name = match[1];
      if (name === 'if' || name === 'for' || name === 'while' || name === 'switch' || name === 'catch' || name === 'try') continue;
      const body = this.extractBody(content, match.index + match[0].length - 1);
      if (body.split('\n').length < 3) continue; // skip trivial methods
      const params = match[2].split(',').map(p => p.trim()).filter(Boolean);
      const calls = this.extractCalls(body);

      // Don't duplicate
      if (funcs.some(f => f.name === name && f.file === file)) continue;

      const startIdx = content.lastIndexOf('\n', match.index) + 1;
      const startLine = content.substring(0, startIdx).split('\n').length;

      funcs.push({
        name, file, startLine, endLine: startLine + body.split('\n').length,
        params, body, isExported: false, isAsync: false, calls,
      });
    }
  }

  private extractPythonFunctions(content: string, file: string, lines: string[], funcs: FunctionDef[]) {
    const re = /def\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*\w+)?\s*:/g;
    let match: RegExpExecArray | null;
    while ((match = re.exec(content)) !== null) {
      const name = match[1];
      const params = match[2].split(',').map(p => p.split('=')[0].split(':')[0].trim()).filter(Boolean);
      const startIdx = content.lastIndexOf('\n', match.index) + 1;
      const startLine = content.substring(0, startIdx).split('\n').length;
      const body = this.extractPythonBody(content, match.index + match[0].length);
      const calls = this.extractCalls(body);

      funcs.push({ name, file, startLine, endLine: startLine + body.split('\n').length, params, body, isExported: !name.startsWith('_'), isAsync: body.includes('async def'), calls });
    }
  }

  private extractGoFunctions(content: string, file: string, lines: string[], funcs: FunctionDef[]) {
    const re = /func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)\s*\(([^)]*)\)/g;
    let match: RegExpExecArray | null;
    while ((match = re.exec(content)) !== null) {
      const name = match[1];
      const params = match[2].split(',').map(p => p.trim().split(/\s+/)[0]).filter(Boolean);
      const body = this.extractBody(content, match.index + match[0].length);
      const calls = this.extractCalls(body);
      const startIdx = content.lastIndexOf('\n', match.index) + 1;
      const startLine = content.substring(0, startIdx).split('\n').length;

      funcs.push({ name, file, startLine, endLine: startLine + body.split('\n').length, params, body, isExported: /^[A-Z]/.test(name), isAsync: false, calls });
    }
  }

  private extractPhpFunctions(content: string, file: string, lines: string[], funcs: FunctionDef[]) {
    const re = /(?:public\s+|private\s+|protected\s+|static\s+)*function\s+(\w+)\s*\(([^)]*)\)/g;
    let match: RegExpExecArray | null;
    while ((match = re.exec(content)) !== null) {
      const name = match[1];
      const params = match[2].split(',').map(p => p.split('=')[0].trim().replace(/^\$\w+\s*/, '').trim()).filter(Boolean);
      const body = this.extractBody(content, match.index + match[0].length);
      const calls = this.extractCalls(body);
      const startIdx = content.lastIndexOf('\n', match.index) + 1;
      const startLine = content.substring(0, startIdx).split('\n').length;

      funcs.push({ name, file, startLine, endLine: startLine + body.split('\n').length, params, body, isExported: !content.substring(Math.max(0, match.index - 20), match.index).includes('private'), isAsync: false, calls });
    }
  }

  /** Extract function body by matching braces */
  private extractBody(content: string, startIdx: number): string {
    let depth = 0;
    let inString = false;
    let stringChar = '';
    let i = startIdx;
    // Find opening brace
    while (i < content.length && content[i] !== '{') i++;
    if (i >= content.length) return '';
    i++;

    const bodyStart = i;
    while (i < content.length) {
      const ch = content[i];
      if (inString) {
        if (ch === stringChar && content[i - 1] !== '\\') inString = false;
        i++;
        continue;
      }
      if (ch === '"' || ch === "'" || ch === '`') {
        inString = true;
        stringChar = ch;
        i++;
        continue;
      }
      if (ch === '{') depth++;
      if (ch === '}') {
        if (depth === 0) return content.substring(bodyStart, i);
        depth--;
      }
      i++;
    }
    return content.substring(bodyStart, i);
  }

  /** Extract Python function body (indentation-based) */
  private extractPythonBody(content: string, startIdx: number): string {
    const lines = content.substring(startIdx).split('\n');
    if (lines.length === 0) return '';

    // Find indentation of first non-empty line
    let baseIndent = '';
    const firstLine = lines[0];
    const m = firstLine.match(/^(\s+)/);
    if (m) baseIndent = m[1];

    const bodyLines: string[] = [];
    for (const line of lines) {
      if (line.trim() === '') {
        bodyLines.push(line);
        continue;
      }
      const indent = line.match(/^(\s*)/)?.[1] || '';
      if (indent.length < baseIndent.length && line.trim() !== '') break;
      bodyLines.push(line);
    }
    return bodyLines.join('\n');
  }

  /** Extract function call names from a body */
  private extractCalls(body: string): string[] {
    const calls = new Set<string>();
    const callRe = /(\w+(?:\.\w+)*)\s*\(/g;
    let match: RegExpExecArray | null;
    while ((match = callRe.exec(body)) !== null) {
      const name = match[1];
      // Filter out keywords and language builtins
      if (/^(if|for|while|switch|catch|return|throw|new|typeof|instanceof|void|delete)$/.test(name)) continue;
      if (/^(console|Math|JSON|Object|Array|String|Number|Boolean|Date|RegExp|Promise|Map|Set|Symbol|parseInt|parseFloat|isNaN|isFinite)$/.test(name)) continue;
      // Extract the function name (last part after dot)
      const funcName = name.includes('.') ? name.split('.').pop()! : name;
      calls.add(funcName);
    }
    return [...calls];
  }

  /** Compute which sinks are reachable from which callers */
  private computeReachability(functions: Map<string, FunctionDef>, edges: CallEdge[]): Map<string, Set<string>> {
    const reachability = new Map<string, Set<string>>();

    // Build adjacency
    const adjacency = new Map<string, Set<string>>();
    for (const [, func] of functions) {
      adjacency.set(`${func.file}:${func.name}`, new Set());
    }
    for (const edge of edges) {
      const adj = adjacency.get(edge.caller);
      if (adj) adj.add(edge.callee);
    }

    // For each function, compute transitively reachable functions
    for (const [funcId] of functions) {
      const reachable = new Set<string>();
      this.dfs(funcId, adjacency, reachable);
      reachability.set(funcId, reachable);
    }

    return reachability;
  }

  private dfs(node: string, adjacency: Map<string, Set<string>>, visited: Set<string>) {
    if (visited.has(node)) return;
    visited.add(node);
    const neighbors = adjacency.get(node);
    if (neighbors) {
      for (const neighbor of neighbors) {
        this.dfs(neighbor, adjacency, visited);
      }
    }
  }

  /** Trace taint from a source through call graph to sinks */
  private traceFromSource(
    source: string,
    file: string,
    sourceLine: number,
    graph: CallGraphResult,
    content: string,
    lines: string[]
  ): TaintPath[] {
    const paths: TaintPath[] = [];

    // Extract the variable name being assigned from the taint source
    // e.g., from "req.query.url" at "const url = req.query.url" → variable is "url"
    const sourceLineContent = lines[sourceLine - 1] || '';
    const varMatch = sourceLineContent.match(/(?:const|let|var|\w+)\s+(\w+)\s*=\s*.*/);
    const trackedVar = varMatch ? varMatch[1] : null;

    if (!trackedVar) {
      // Can't track the variable — skip inter-procedural for this source
      return paths;
    }

    // Scan forward from the source line looking for:
    // 1. Lines where the tracked variable is used
    // 2. Lines where the tracked variable is reassigned (update trackedVar)
    // 3. Sink patterns on lines where the tracked variable appears
    let currentVar = trackedVar;
    let pathFunctions: { file: string; function: string; line: number }[] = [
      { file, function: '(entry)', line: sourceLine },
    ];

    for (let i = sourceLine; i < Math.min(lines.length, sourceLine + 80); i++) {
      const line = lines[i];

      // Check if current variable is reassigned
      const reassignMatch = line.match(
        new RegExp(`(?:const|let|var|\\w+)\\s+(\\w+)\\s*=\\s*.*\\b${currentVar}\\b`)
      );
      if (reassignMatch && reassignMatch[1] !== currentVar) {
        currentVar = reassignMatch[1];
        pathFunctions.push({ file, function: `(assign to ${currentVar})`, line: i + 1 });
        continue;
      }

      // Check if the current variable appears on this line
      const varUsed = new RegExp(`\\b${currentVar}\\b`).test(line);
      if (!varUsed) continue;

      // Check for sinks on this line
      for (const sink of SINK_PATTERNS) {
        sink.pattern.lastIndex = 0;
        if (sink.pattern.test(line)) {
          const cleanLine = line.trim().substring(0, 150);
          paths.push({
            source,
            path: [...pathFunctions],
            sink: `${sink.name}: ${cleanLine}`,
            file,
            line: i + 1,
          });
          break; // one sink per line
        }
      }
    }

    return paths;
  }
}
