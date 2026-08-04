/**
 * Code Property Graph — Graph Schema & Types
 *
 * A CPG unifies AST, control flow, data flow, and call graph into
 * a single labeled property graph. Vulnerability detection becomes
 * graph traversal: "find paths from user input to SQL exec with
 * no sanitizer in between."
 */

// ─── Node Types ────────────────────────────────────────────────────────

export type CpgNodeType =
  | 'FILE'
  | 'FUNCTION'
  | 'METHOD'
  | 'CLASS'
  | 'BLOCK'
  | 'STATEMENT'
  | 'EXPRESSION'
  | 'CALL_SITE'
  | 'PARAMETER'
  | 'VARIABLE_DECL'
  | 'LITERAL'
  | 'IDENTIFIER'
  | 'RETURN'
  | 'CONDITION'
  | 'ASSIGNMENT'
  | 'MEMBER_EXPRESSION'
  | 'UNKNOWN';

// ─── Edge Types ────────────────────────────────────────────────────────

export type CpgEdgeType =
  | 'AST_CHILD'         // parent → child in syntax tree
  | 'CONTROL_FLOW'      // statement → next statement
  | 'TRUE_BRANCH'       // condition → true branch first statement
  | 'FALSE_BRANCH'      // condition → false branch first statement
  | 'DATA_FLOW'         // definition/use → use
  | 'CALLS'             // call site → function definition
  | 'RETURNS_TO'        // return stmt → call site
  | 'DECLARES'          // container → declared element
  | 'REFERENCES'        // identifier → its declaration
  | 'HAS_PARAMETER'     // function → parameter
  | 'TAINT_SOURCE'      // marks a node as a taint source
  | 'TAINT_SINK'        // marks a node as a taint sink
  | 'TAINT_PROPAGATES'  // taint flows from node → node
  | 'SANITIZES';        // node → sanitized variable

// ─── Graph Node ────────────────────────────────────────────────────────

export interface CpgNode {
  id: string;            // unique node ID
  type: CpgNodeType;
  label: string;         // human-readable label (var name, func name, etc.)
  file: string;
  startLine: number;
  endLine: number;
  startColumn: number;
  endColumn: number;
  code: string;          // source code snippet

  // Typed properties for queries
  properties: Record<string, any>;
}

// ─── Graph Edge ────────────────────────────────────────────────────────

export interface CpgEdge {
  id: string;
  type: CpgEdgeType;
  sourceId: string;      // from node
  targetId: string;      // to node
  label?: string;        // edge label (e.g., variable name for DATA_FLOW)
  properties: Record<string, any>;
}

// ─── Property Graph ────────────────────────────────────────────────────

export interface PropertyGraph {
  nodes: Map<string, CpgNode>;
  edges: CpgEdge[];

  // Indexes for fast querying
  /**
   * edgeId → edge. Without this every `edges.find(e => e.id === eid)` was a
   * linear scan of the whole edge array, run inside the taint BFS — which made
   * query time quadratic in graph size.
   */
  edgeIndex: Map<string, CpgEdge>;
  /** nodeId → outgoing edge IDs */
  outEdges: Map<string, string[]>;
  /** nodeId → incoming edge IDs */
  inEdges: Map<string, string[]>;
  /** file → node IDs */
  fileIndex: Map<string, string[]>;
  /** node type → node IDs */
  typeIndex: Map<CpgNodeType, string[]>;
}

// ─── Taint Result ──────────────────────────────────────────────────────

export interface CpgVulnerability {
  /** Rule ID */
  ruleId: string;
  /** Human readable title */
  title: string;
  /** Severity */
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** Source node (taint entry point) */
  sourceNode: CpgNode;
  /** Sink node (dangerous operation) */
  sinkNode: CpgNode;
  /** Path from source to sink (including intermediate nodes) */
  path: CpgNodePathEntry[];
  /** Any sanitizers found on the path */
  sanitizersEncountered: CpgNode[];
  /** Description */
  message: string;
  /** Fix recommendation */
  recommendation: string;
  /** CWE */
  cwe: string;
  /** Confidence */
  confidence: 'certain' | 'high' | 'medium' | 'low';
  /** File and line (from sink typically) */
  file: string;
  line: number;
}

export interface CpgNodePathEntry {
  node: CpgNode;
  edgeType: CpgEdgeType;
  /** Variable being tracked at this step */
  variable?: string;
}

// ─── Taint Sources ─────────────────────────────────────────────────────

export interface TaintSourceSpec {
  /** Pattern to match in node code */
  pattern: RegExp;
  /** Source category */
  category: 'user-input' | 'environment' | 'network' | 'database';
  /** Description */
  description: string;
}

export const DEFAULT_TAINT_SOURCES: TaintSourceSpec[] = [
  // Express / Node.js HTTP
  { pattern: /\breq\.query\b/, category: 'user-input', description: 'Express query parameter' },
  { pattern: /\breq\.params\b/, category: 'user-input', description: 'Express route parameter' },
  { pattern: /\breq\.body\b/, category: 'user-input', description: 'Express request body' },
  { pattern: /\breq\.param\(/, category: 'user-input', description: 'Express param() call' },
  { pattern: /\breq\.cookies\b/, category: 'user-input', description: 'Express cookies' },
  { pattern: /\breq\.headers\b/, category: 'user-input', description: 'HTTP headers' },
  { pattern: /\breq\.file\b/, category: 'user-input', description: 'File upload' },

  // Flask / Python
  { pattern: /\brequest\.args\b/, category: 'user-input', description: 'Flask query args' },
  { pattern: /\brequest\.form\b/, category: 'user-input', description: 'Flask form data' },
  { pattern: /\brequest\.get_json\(/, category: 'user-input', description: 'Flask JSON body' },

  // PHP
  { pattern: /\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b/, category: 'user-input', description: 'PHP superglobal' },

  // Go
  { pattern: /\br\.FormValue\(/, category: 'user-input', description: 'Go form value' },
  { pattern: /\br\.URL\.Query\(\)\.Get\(/, category: 'user-input', description: 'Go query param' },
  // Ruby had no taint source at all, so its sinks were unreachable.
  { pattern: /\bparams\s*\[/, category: 'user-input', description: 'Rails/Sinatra request parameter' },
  { pattern: /\brequest\s*\.\s*(?:params|query_parameters|request_parameters|POST|GET)\b/, category: 'user-input', description: 'Rack request input' },
  { pattern: /\br\.PostFormValue\(/, category: 'user-input', description: 'Go POST value' },

  // Environment
  { pattern: /\bprocess\.env\b/, category: 'environment', description: 'Environment variable' },
  { pattern: /\bos\.environ\b/, category: 'environment', description: 'Python OS env' },

  // Network
  { pattern: /\bfs\.readFile/, category: 'network', description: 'File read — may contain attacker-controlled data' },
  { pattern: /\bfetch\(/, category: 'network', description: 'HTTP fetch — response is attacker-controlled' },
];

// ─── Taint Sinks ───────────────────────────────────────────────────────

export interface TaintSinkSpec {
  /** Pattern to match in node code */
  pattern: RegExp;
  /** Sink category */
  category: 'sql' | 'command-exec' | 'code-exec' | 'file-write' | 'xss' | 'ssrf' | 'redirect' | 'crypto';
  /** Base severity */
  severity: 'critical' | 'high' | 'medium' | 'low';
  /** CWE */
  cwe: string;
  /** Description */
  description: string;
}

export const DEFAULT_TAINT_SINKS: TaintSinkSpec[] = [
  // SQL
  { pattern: /\b(?:connection|db|pool|client|stmt)\.(?:query|execute|exec|run|raw|all|get)\s*\(/, category: 'sql', severity: 'critical', cwe: 'CWE-89', description: 'SQL query execution' },
  { pattern: /\b(?:cursor|c)\.(?:execute|executemany)\s*\(/, category: 'sql', severity: 'critical', cwe: 'CWE-89', description: 'Python cursor execution' },
  { pattern: /\bmysqli?_query\s*\(/, category: 'sql', severity: 'critical', cwe: 'CWE-89', description: 'PHP MySQL query' },
  // Go's database/sql exports capitalised methods, so the lower-case pattern
  // above never matched `db.Query(...)` and Go had no SQL sink at all.
  { pattern: /\b(?:db|conn|tx|stmt|sqlDB|database)\s*\.\s*(?:Query|QueryRow|QueryContext|QueryRowContext|Exec|ExecContext|Prepare)\s*\(/, category: 'sql', severity: 'critical', cwe: 'CWE-89', description: 'Go database/sql query' },
  { pattern: /\bpg_query\s*\(/, category: 'sql', severity: 'critical', cwe: 'CWE-89', description: 'PostgreSQL query' },
  { pattern: /\bdatabase\/sql\b.*\.(?:Query|Exec)\s*\(/, category: 'sql', severity: 'critical', cwe: 'CWE-89', description: 'Go database/sql query' },

  // Command execution
  { pattern: /\b(?:exec|execSync|spawn|execFile|fork)\s*\(/, category: 'command-exec', severity: 'critical', cwe: 'CWE-78', description: 'Node.js command execution' },
  { pattern: /\b(?:popen|system|subprocess\.(?:call|run|check_output|Popen)|os\.system|commands\.getoutput)\s*\(/, category: 'command-exec', severity: 'critical', cwe: 'CWE-78', description: 'Python command execution' },
  { pattern: /\b(?:shell_exec|passthru|proc_open|popen|exec|system)\s*\(/, category: 'command-exec', severity: 'critical', cwe: 'CWE-78', description: 'PHP command execution' },
  // `exec.Command(...)` is the Go form; the bare-`exec(` pattern above does not
  // reach it because of the package qualifier.
  { pattern: /\bexec\s*\.\s*Command(?:Context)?\s*\(/, category: 'command-exec', severity: 'critical', cwe: 'CWE-78', description: 'Go process execution' },
  { pattern: /\bos\/exec\b.*\.(?:Command|Run|Output)\s*\(/, category: 'command-exec', severity: 'critical', cwe: 'CWE-78', description: 'Go command execution' },

  // Code execution
  { pattern: /\beval\s*\(/, category: 'code-exec', severity: 'critical', cwe: 'CWE-95', description: 'eval() execution' },
  { pattern: /\bnew Function\s*\(/, category: 'code-exec', severity: 'critical', cwe: 'CWE-95', description: 'Function constructor' },
  { pattern: /\bsetTimeout\s*\(\s*[\w`]/, category: 'code-exec', severity: 'high', cwe: 'CWE-95', description: 'setTimeout with string' },
  { pattern: /\bsetInterval\s*\(\s*[\w`]/, category: 'code-exec', severity: 'high', cwe: 'CWE-95', description: 'setInterval with string' },
  { pattern: /\bexec\s*\(\s*[`'"]/, category: 'code-exec', severity: 'critical', cwe: 'CWE-95', description: 'Python exec()' },

  // File operations
  { pattern: /\bfs\.(?:writeFile|createWriteStream|appendFile|write)\s*\(/, category: 'file-write', severity: 'high', cwe: 'CWE-22', description: 'Node.js file write' },
  { pattern: /\bfs\.(?:readFile|createReadStream|readFileSync)\s*\(/, category: 'file-write', severity: 'medium', cwe: 'CWE-22', description: 'Node.js file read' },
  { pattern: /\bopen\s*\(\s*[\w`'"]/, category: 'file-write', severity: 'medium', cwe: 'CWE-22', description: 'Python file open' },
  { pattern: /\bfile_(?:get|put)_contents\s*\(/, category: 'file-write', severity: 'high', cwe: 'CWE-22', description: 'PHP file read/write' },
  { pattern: /\bfopen\s*\(/, category: 'file-write', severity: 'medium', cwe: 'CWE-22', description: 'C/PHP file open' },

  // XSS
  { pattern: /\b(?:innerHTML|outerHTML)\s*=/, category: 'xss', severity: 'medium', cwe: 'CWE-79', description: 'innerHTML assignment' },
  { pattern: /\bdangerouslySetInnerHTML\b/, category: 'xss', severity: 'medium', cwe: 'CWE-79', description: 'React dangerouslySetInnerHTML' },
  { pattern: /\bdocument\.write\s*\(/, category: 'xss', severity: 'medium', cwe: 'CWE-79', description: 'document.write()' },

  // SSRF
  { pattern: /\b(?:fetch|axios|got|superagent|request|needle)\s*\(/, category: 'ssrf', severity: 'high', cwe: 'CWE-918', description: 'HTTP client request' },
  { pattern: /\bhttp\.(?:get|request)\s*\(/, category: 'ssrf', severity: 'high', cwe: 'CWE-918', description: 'Node.js HTTP request' },
  { pattern: /\b(?:urllib|httpx|aiohttp)\s*\.\s*(?:request|urlopen|get|post)/, category: 'ssrf', severity: 'high', cwe: 'CWE-918', description: 'Python HTTP client' },

  // Redirect
  { pattern: /\bres\.redirect\s*\(/, category: 'redirect', severity: 'medium', cwe: 'CWE-601', description: 'Express redirect' },
  { pattern: /\b(?:redirect|redirect_to|wp_redirect)\s*\(/, category: 'redirect', severity: 'medium', cwe: 'CWE-601', description: 'Redirect function' },
];

// ─── Sanitizers ────────────────────────────────────────────────────────

export interface SanitizerSpec {
  pattern: RegExp;
  /** What it sanitizes against */
  protects: string; // sink category or 'all'
  description: string;
}

export const DEFAULT_SANITIZERS: SanitizerSpec[] = [
  // SQL sanitizers
  { pattern: /\b(?:escape|mysql\.escape|pg\.escape|sqlstring\.escape)\s*\(/, protects: 'sql', description: 'SQL escape' },
  { pattern: /\.(?:toUpperCase|toLowerCase)\s*\(\)\s*\.\s*replace\s*\(\s*\/['"]/, protects: 'sql', description: 'Basic SQL sanitization' },

  // HTML/XSS sanitizers
  { pattern: /\bDOMPurify\.sanitize\s*\(/, protects: 'xss', description: 'DOMPurify' },
  { pattern: /\b(?:sanitizeHtml|sanitize-html|escapeHtml|htmlspecialchars|htmlescape|html\.escape|encodeURIComponent|encodeURI)\s*\(/, protects: 'xss', description: 'HTML encoding' },
  { pattern: /\btextContent\s*=/, protects: 'xss', description: 'textContent (safe)' },

  // Command sanitizers
  { pattern: /\b(?:shellescape|shell-escape|escapeShellArg|escapeshellarg|escapeShellCmd|escapeshellcmd)\s*\(/, protects: 'command-exec', description: 'Shell escaping' },
  { pattern: /\.map\s*\(\s*\w+\s*=>\s*['"]/, protects: 'command-exec', description: 'Argument quoting' },

  // File path sanitizers
  { pattern: /\bpath\.(?:resolve|normalize|basename)\s*\(/, protects: 'file-write', description: 'Path normalization' },
  { pattern: /\.replace\s*\(\s*\/\.\.\//, protects: 'file-write', description: 'Path traversal filter' },

  // General input validation
  { pattern: /\b(?:parseInt|parseFloat|Number|intval|floatval)\s*\(/, protects: 'all', description: 'Type coercion' },
  { pattern: /\b(?:validator\.is|joi\.|z\.|yup\.|express-validator|check\s*\(|validationResult|isValid|sanitize)/, protects: 'all', description: 'Input validation library' },
  { pattern: /\bif\s*\(.+?(?:validate|check|verify)/, protects: 'all', description: 'Validation condition' },
];
