/**
 * Tree-sitter AST Engine — Multi-language semantic code analysis.
 * Replaces regex-only matching with real parse trees for:
 *   JavaScript, TypeScript, Python, Go, PHP, Ruby
 *
 * Uses tree-sitter's S-expression query language to match code patterns
 * semantically rather than textually, eliminating false positives from
 * pattern strings in source code.
 */

import Parser from 'tree-sitter';

// Lazy-load grammar modules
let _grammars: Record<string, any> | null = null;
function getGrammars(): Record<string, any> {
  if (_grammars) return _grammars;
  try {
    _grammars = {
      '.js': require('tree-sitter-javascript'),
      '.mjs': require('tree-sitter-javascript'),
      '.cjs': require('tree-sitter-javascript'),
      '.jsx': require('tree-sitter-javascript'),
      '.ts': require('tree-sitter-typescript').typescript,
      '.tsx': require('tree-sitter-typescript').tsx,
      '.py': require('tree-sitter-python'),
      '.pyi': require('tree-sitter-python'),
      '.go': require('tree-sitter-go'),
      // tree-sitter-php exports { php, php_only } rather than a bare Language.
      // Passing the module object made setLanguage throw, init() return false,
      // and PHP silently lose its AST path while still claiming support.
      '.php': require('tree-sitter-php').php,
      '.phtml': require('tree-sitter-php').php,
      '.rb': require('tree-sitter-ruby'),
    };
  } catch {
    _grammars = {};
  }
  return _grammars;
}

// ─── Semantic Pattern ─────────────────────────────────────────────────

/** A semantic query pattern — tree-sitter S-expression + metadata */
export interface SemanticPattern {
  /** Tree-sitter query string (S-expression) */
  query: string;
  /** Human-readable message when matched */
  message: string;
  /** Recommendation for fixing */
  recommendation: string;
  /** Severity override (uses rule severity by default) */
  severity?: string;
  /** Confidence level for this specific pattern */
  confidence: 'certain' | 'high' | 'medium' | 'low';
  /** Risk of false positive */
  falsePositiveRisk: 'low' | 'medium' | 'high';
  /** Fix example code */
  fixExample?: string;
  /** Variable name in query to extract as the matched snippet target */
  snippetCapture?: string;
}

// ─── AST Node ──────────────────────────────────────────────────────────

export interface AstNode {
  type: string;
  startPosition: { row: number; column: number };
  endPosition: { row: number; column: number };
  text: string;
  children: AstNode[];
}

export interface AstMatch {
  pattern: SemanticPattern;
  line: number;
  column: number;
  endLine?: number;
  endColumn?: number;
  snippet: string;
  captures: Record<string, string>;
}

// ─── Engine ────────────────────────────────────────────────────────────

/**
 * Parsers and compiled queries are reusable, and both hold native memory that
 * V8 only reclaims via finalizers — so churning them inflates RSS in a way the
 * JS heap never shows.
 *
 * A Parser was being constructed per *file* and a Query per *pattern per file*,
 * which on a 700-file scan meant thousands of native allocations of objects
 * that are immutable once built. Keyed by grammar and by query text, both are
 * built once and shared.
 */
const parserCache = new Map<unknown, Parser>();
const queryCache = new Map<string, any>();
/** (grammar, query) -> does this query compile for that grammar. */
const applicabilityCache = new Map<string, boolean>();

export function parserFor(grammar: unknown): Parser {
  let parser = parserCache.get(grammar);
  if (!parser) {
    parser = new Parser();
    parser.setLanguage(grammar as any);
    parserCache.set(grammar, parser);
  }
  return parser;
}

export function queryFor(grammar: unknown, source: string, grammarKey: string): any {
  const key = `${grammarKey} ${source}`;
  let query = queryCache.get(key);
  if (!query) {
    query = new (Parser as any).Query(grammar, source);
    queryCache.set(key, query);
  }
  return query;
}

/** Release cached parsers and queries. Used by long-running hosts (MCP, watch). */
export function clearTreeSitterCaches(): void {
  parserCache.clear();
  queryCache.clear();
  applicabilityCache.clear();
}

/**
 * Cache occupancy. Both counts must stay proportional to the number of distinct
 * grammars and query strings — never to the number of files scanned. Tests
 * assert this, because "allocates per file" is invisible until it is measured
 * on a corpus large enough to run out of memory.
 */
export function treeSitterCacheStats(): { parsers: number; queries: number } {
  return { parsers: parserCache.size, queries: queryCache.size };
}

export class TreeSitterEngine {
  private parser: Parser | null = null;
  private initialized = false;
  /** Identifies the active grammar for query cache keys. */
  private grammarKey = '';

  /** Initialize parser for a specific language grammar */
  init(extension: string): boolean {
    const grammars = getGrammars();
    const grammarModule = grammars[extension];
    if (!grammarModule) return false;

    try {
      this.parser = parserFor(grammarModule);
      this.grammarKey = extension;
      this.initialized = true;
      return true;
    } catch {
      this.initialized = false;
      return false;
    }
  }

  /**
   * Which of these patterns can actually run against the currently initialised
   * grammar.
   *
   * SEMANTIC_RULES holds a flat list per rule, mixing JS-syntax queries
   * (`call_expression`, `member_expression`) with Python-syntax ones (`call`,
   * `attribute`). A query naming node types a grammar does not have fails to
   * compile — which is exactly the signal for "this pattern does not apply to
   * this language", and needs no per-language tagging to stay correct as
   * patterns are added.
   *
   * This matters beyond efficiency: the caller uses an empty result to decide
   * that the regex rules must run instead. Without it, Go, PHP and Ruby got
   * neither path — the AST queries could not match their grammars, and the
   * regex fallback was skipped because the rule "had" semantic patterns.
   */
  applicablePatterns(patterns: SemanticPattern[]): SemanticPattern[] {
    if (!this.parser || !this.initialized) return [];
    const grammar = this.parser.getLanguage();
    return patterns.filter(p => {
      // Cache the verdict both ways: a query that does not compile would
      // otherwise throw again for every file of that language.
      const key = `${this.grammarKey} ${p.query}`;
      const known = applicabilityCache.get(key);
      if (known !== undefined) return known;

      let ok = false;
      try {
        queryFor(grammar, p.query, this.grammarKey);
        ok = true;
      } catch {
        ok = false;
      }
      applicabilityCache.set(key, ok);
      return ok;
    });
  }

  /** Check if tree-sitter supports this file extension */
  supports(extension: string): boolean {
    const grammars = getGrammars();
    return extension in grammars;
  }

  /** Get all supported extensions */
  static supportedExtensions(): string[] {
    return Object.keys(getGrammars());
  }

  /**
   * Parse source code and run semantic patterns against it.
   * Returns matches — these are real AST-level matches, not regex.
   */
  analyze(content: string, patterns: SemanticPattern[]): AstMatch[] {
    if (!this.parser || !this.initialized) return [];

    const tree = this.parser.parse(content);
    const rootNode = tree.rootNode;
    const matches: AstMatch[] = [];
    const lines = content.split('\n');

    for (const pattern of patterns) {
      try {
        const query = queryFor(this.parser.getLanguage(), pattern.query, this.grammarKey);
        const queryMatches = query.matches(rootNode);

        for (const match of queryMatches) {
          // Determine the primary capture for line/snippet
          let primaryCapture = match.captures[0];
          if (pattern.snippetCapture) {
            const named = match.captures.find(
              (c: any) => c.name === pattern.snippetCapture
            );
            if (named) primaryCapture = named;
          }

          const node = primaryCapture.node;
          const startRow = node.startPosition.row;
          const endRow = node.endPosition.row;

          // Build capture map
          const captures: Record<string, string> = {};
          for (const cap of match.captures) {
            captures[cap.name] = content.slice(
              cap.node.startIndex,
              cap.node.endIndex
            );
          }

          // Get snippet (surrounding line)
          const snippet =
            startRow < lines.length
              ? lines[startRow].trim()
              : content.slice(node.startIndex, node.endIndex);

          // Skip matches inside string literals / comments (false positives from tool source)
          if (this.isInsideLiteralOrComment(node)) continue;

          matches.push({
            pattern,
            line: startRow + 1,
            column: node.startPosition.column + 1,
            endLine: endRow + 1,
            endColumn: node.endPosition.column + 1,
            snippet: snippet.substring(0, 200),
            captures,
          });
        }
      } catch {
        // Invalid query string — skip
      }
    }

    return matches;
  }

  /**
   * Walk the AST and return all nodes of a given type.
   * Useful for custom analysis beyond pattern matching.
   */
  collectNodes(content: string, nodeTypes: string[]): AstNode[] {
    if (!this.parser || !this.initialized) return [];

    const tree = this.parser.parse(content);
    const nodes: AstNode[] = [];
    const typeSet = new Set(nodeTypes);

    function walk(node: any) {
      if (typeSet.has(node.type)) {
        nodes.push({
          type: node.type,
          startPosition: node.startPosition,
          endPosition: node.endPosition,
          text: content.slice(node.startIndex, node.endIndex),
          children: node.namedChildren.map((c: any) => ({
            type: c.type,
            startPosition: c.startPosition,
            endPosition: c.endPosition,
            text: content.slice(c.startIndex, c.endIndex),
            children: [],
          })),
        });
      }
      for (const child of node.namedChildren) {
        walk(child);
      }
    }

    walk(tree.rootNode);
    return nodes;
  }

  /**
   * Check if a node is inside a string literal or comment — these are
   * almost certainly false positives when scanning tool source code.
   */
  private isInsideLiteralOrComment(node: any): boolean {
    let current = node;
    while (current) {
      const type = current.type;
      if (
        type === 'string' ||
        type === 'template_string' ||
        type === 'string_fragment' ||
        type === 'comment' ||
        type === 'block_comment' ||
        type === 'line_comment' ||
        type === 'heredoc_body' ||
        type === 'string_content'
      ) {
        return true;
      }
      current = current.parent;
    }
    return false;
  }

  /** Get the AST root for custom traversal */
  getRoot(content: string): any {
    if (!this.parser || !this.initialized) return null;
    return this.parser.parse(content).rootNode;
  }
}

// ─── Pre-built Semantic Patterns ──────────────────────────────────────

/**
 * Semantic patterns that replace regex-based rules with AST-level matching.
 * These use tree-sitter's query language — not regex — so they match
 * actual code constructs, not arbitrary strings.
 */

export const SEMANTIC_SQL_INJECTION: SemanticPattern[] = [
  // JS/TS: template literal in query/execute call
  {
    query: `
      (call_expression
        function: (member_expression
          property: (property_identifier) @method
          (#match? @method "^(query|execute|exec|run|raw|all|get|select|insert|update|delete)$"))
        arguments: (arguments
          (template_string) @sink
          (#not-match? @sink "SQLITE")))
    `,
    message: 'SQL query built with template literal — SQL injection risk',
    recommendation: 'Use parameterized queries with placeholders (?, $1, :name). Never interpolate user input into SQL strings.',
    confidence: 'high',
    falsePositiveRisk: 'low',
    fixExample: '// Instead of: db.query(`SELECT * FROM users WHERE id = ${userId}`)\n// Use: db.query(\'SELECT * FROM users WHERE id = ?\', [userId])',
    snippetCapture: 'sink',
  },
  // JS/TS: string concatenation in query call
  {
    query: `
      (call_expression
        function: (member_expression
          property: (property_identifier) @method
          (#match? @method "^(query|execute|exec|run|raw|all)$"))
        arguments: (arguments
          (binary_expression
            left: (string) @left
            operator: "+")))
    `,
    message: 'SQL query built with string concatenation — SQL injection',
    recommendation: 'Use parameterized queries. Concatenation of user input into SQL is the #1 injection vector.',
    confidence: 'high',
    falsePositiveRisk: 'low',
    snippetCapture: 'left',
  },
  // Python: f-string in cursor.execute() / .raw()
  {
    query: `
      (call
        function: (attribute
          object: (identifier) @obj
          attribute: (identifier) @method
          (#match? @method "^(execute|executemany|raw|exec_driver_sql)$"))
        arguments: (argument_list
          (string) @sink
          (#match? @sink "^f[\"']")))
    `,
    message: 'Python f-string in database execute() — SQL injection',
    recommendation: 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
    confidence: 'high',
    falsePositiveRisk: 'low',
    snippetCapture: 'sink',
  },
];

export const SEMANTIC_COMMAND_INJECTION: SemanticPattern[] = [
  // JS/TS: exec()/spawn()/execSync() with template literal or string concat
  {
    query: `
      (call_expression
        function: (identifier) @func
        (#match? @func "^(exec|execSync|spawn|popen|system)$")
        arguments: (arguments
          (template_string) @cmd))
    `,
    message: 'Shell command built with template literal — command injection',
    recommendation: 'Use spawn() with separate arguments array. Never interpolate user input into shell commands.',
    confidence: 'high',
    falsePositiveRisk: 'low',
    snippetCapture: 'cmd',
  },
  // Python: os.system() / subprocess with f-string or concatenation
  {
    query: `
      (call
        function: (attribute
          object: (identifier) @mod
          (#match? @mod "^(os|subprocess)$")
          attribute: (identifier) @func
          (#match? @func "^(system|popen|call|check_output|run)$"))
        arguments: (argument_list
          (string) @cmd
          (#match? @cmd "^f[\"']")))
    `,
    message: 'Python subprocess with f-string — command injection',
    recommendation: 'Use subprocess.run(["cmd", "arg"], ...) with argument list. Never use shell=True with user input.',
    confidence: 'high',
    falsePositiveRisk: 'low',
    snippetCapture: 'cmd',
  },
  // Python: os.system with concatenation
  {
    query: `
      (call
        function: (attribute
          object: (identifier) @mod
          (#match? @mod "^(os|subprocess)$")
          attribute: (identifier) @func
          (#match? @func "^(system|popen|call)$"))
        arguments: (argument_list
          (binary_expression
            operator: "+")))
    `,
    message: 'Python shell command built with string concatenation — command injection',
    recommendation: 'Use subprocess.run() with a list of arguments. Never concatenate strings for shell commands.',
    confidence: 'high',
    falsePositiveRisk: 'low',
  },
];

export const SEMANTIC_XSS: SemanticPattern[] = [
  // JS: innerHTML assignment
  {
    query: `
      (expression_statement
        (assignment_expression
          left: (member_expression
            property: (property_identifier) @prop
            (#match? @prop "^(innerHTML|outerHTML)$"))
          right: (_) @value))
    `,
    message: 'innerHTML/outerHTML assignment — XSS vector',
    recommendation: 'Use textContent or innerText. If HTML is necessary, sanitize with DOMPurify.',
    confidence: 'high',
    falsePositiveRisk: 'medium',
    snippetCapture: 'value',
  },
  // JS: dangerouslySetInnerHTML (React)
  {
    query: `
      (jsx_attribute
        (property_identifier) @prop
        (#eq? @prop "dangerouslySetInnerHTML"))
    `,
    message: 'React dangerouslySetInnerHTML — XSS if content is user-controlled',
    recommendation: 'Use DOMPurify to sanitize HTML before passing to dangerouslySetInnerHTML. Consider using React children instead.',
    confidence: 'high',
    falsePositiveRisk: 'medium',
  },
  // Python Django: mark_safe()
  {
    query: `
      (call
        function: (identifier) @func
        (#match? @func "^(mark_safe|SafeString|safe)$"))
    `,
    message: 'Django mark_safe() used — verify content is trusted',
    recommendation: 'Only mark content as safe if it is guaranteed to be sanitized. Use Django template auto-escaping.',
    confidence: 'medium',
    falsePositiveRisk: 'medium',
  },
];

export const SEMANTIC_PATH_TRAVERSAL: SemanticPattern[] = [
  // JS: path.join with req.query/req.params/req.body
  {
    query: `
      (call_expression
        function: (member_expression
          object: (identifier) @mod
          (#match? @mod "^(path|Path|posix)$")
          property: (property_identifier) @func
          (#match? @func "^(join|resolve|normalize)$"))
        arguments: (arguments
          (member_expression
            object: (member_expression
              object: (identifier) @src
              (#match? @src "^(req|request|ctx|c|params)$"))
            property: (property_identifier) @field
            (#match? @field "^(query|params|body|param|cookies|headers)$"))))
    `,
    message: 'File path built from user input — path traversal risk',
    recommendation: 'Validate and sanitize user-supplied path components. Reject paths containing ../, ..\\, or absolute paths.',
    confidence: 'high',
    falsePositiveRisk: 'low',
  },
  // Python: open() with request data
  {
    query: `
      (call
        function: (identifier) @func
        (#match? @func "^(open|Path)$")
        arguments: (argument_list
          (subscript
            value: (identifier) @src
            (#match? @src "^(request|self\.request)$"))))
    `,
    message: 'File opened with request data — path traversal risk',
    recommendation: 'Validate file paths against an allowlist. Use secure filename generation (uuid).',
    confidence: 'high',
    falsePositiveRisk: 'low',
  },
];

export const SEMANTIC_SSRF: SemanticPattern[] = [
  // JS: fetch/axios/http.get with user-controlled URL
  {
    query: `
      (call_expression
        function: (identifier) @func
        (#match? @func "^(fetch|axios|got|superagent|request)$")
        arguments: (arguments
          (member_expression
            object: (member_expression
              object: (identifier) @src
              (#match? @src "^(req|request|ctx|c|params)$"))
            property: (property_identifier) @field
            (#match? @field "^(query|params|body|param)$"))))
    `,
    message: 'HTTP request to user-controlled URL — SSRF risk',
    recommendation: 'Validate and sanitize URLs. Block internal/private IP ranges. Use an allowlist of permitted domains.',
    confidence: 'high',
    falsePositiveRisk: 'low',
  },
];

export const SEMANTIC_INSECURE_DESERIALIZATION: SemanticPattern[] = [
  // Python: pickle/yaml.load with request data
  {
    query: `
      (call
        function: (attribute
          object: (identifier) @mod
          (#match? @mod "^(pickle|yaml|marshal|dill)$")
          attribute: (identifier) @func
          (#match? @func "^(load|loads|Unpickler)$")))
    `,
    message: 'Deserialization of untrusted data — RCE risk',
    recommendation: 'Never deserialize untrusted data. Use JSON for data interchange. If pickle is required, use hmac signing.',
    confidence: 'high',
    falsePositiveRisk: 'low',
  },
  // JS: eval() / new Function() — but skip known safe usages
  {
    query: `
      (call_expression
        function: (identifier) @func
        (#match? @func "^(eval|Function)$")
        arguments: (arguments (_) @arg))
    `,
    message: 'Dynamic code execution — if input is user-controlled, this is RCE',
    recommendation: 'Avoid eval() and new Function(). Use JSON.parse() for data, or a sandboxed VM for code.',
    confidence: 'high',
    falsePositiveRisk: 'medium',
    snippetCapture: 'arg',
  },
];

// ─── All semantic patterns by rule ─────────────────────────────────────

export const SEMANTIC_RULES: Record<string, SemanticPattern[]> = {
  'sql-injection': SEMANTIC_SQL_INJECTION,
  'command-injection': SEMANTIC_COMMAND_INJECTION,
  'xss': SEMANTIC_XSS,
  'path-traversal': SEMANTIC_PATH_TRAVERSAL,
  'ssrf': SEMANTIC_SSRF,
  'insecure-deserialization': SEMANTIC_INSECURE_DESERIALIZATION,
};
