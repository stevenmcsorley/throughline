/**
 * Multi-Language CPG Builder (Tree-Sitter Based)
 *
 * Extends CPG construction beyond JS/TS to Python, Go, PHP, and Ruby
 * using tree-sitter grammars and S-expression queries.
 *
 * For each language, we extract:
 * - Function/method definitions with parameters
 * - Call sites with arguments
 * - Variable declarations and assignments
 * - Return statements
 * - Member access expressions
 */

import * as fs from 'fs';
import * as path from 'path';
import Parser from 'tree-sitter';
import { readSource } from '../source-cache';
import { parserFor, queryFor } from '../tree-sitter-engine';

import {
  CpgNode, PropertyGraph,
  DEFAULT_TAINT_SOURCES, DEFAULT_TAINT_SINKS, DEFAULT_SANITIZERS,
} from './types';

import {
  createGraph, addNode, addEdge, getNodesByType, resetIdCounter,
} from './graph';

// ─── Language Configuration ────────────────────────────────────────────

interface LanguageConfig {
  name: string;
  extensions: string[];
  grammar: Parser.Language;
  /** S-expression queries for extraction */
  queries: {
    functionDecl: string;
    callExpression: string;
    variableDecl: string;
    assignment: string;
    returnStatement: string;
    memberExpression: string;
  };
  /** Node type identifying string literals (for false positive filtering) */
  stringTypes: string[];
  commentTypes: string[];
}

// ─── Load tree-sitter grammars ─────────────────────────────────────────

function loadJsGrammar() {
  try { return require('tree-sitter-javascript'); } catch { return null; }
}
function loadTsGrammar() {
  try { return require('tree-sitter-typescript').typescript; } catch { return null; }
}
function loadPythonGrammar() {
  try { return require('tree-sitter-python'); } catch { return null; }
}
function loadGoGrammar() {
  try { return require('tree-sitter-go'); } catch { return null; }
}
function loadPhpGrammar() {
  // tree-sitter-php exports { php, php_only }, not a bare Language. Passing the
  // module object made every query throw, so PHP built an empty graph.
  try { return require('tree-sitter-php').php; } catch { return null; }
}
function loadRubyGrammar() {
  try { return require('tree-sitter-ruby'); } catch { return null; }
}

// ─── Query Patterns ────────────────────────────────────────────────────

const JS_QUERIES = {
  functionDecl: `(function_declaration name: (identifier) @name) (arrow_function) (method_definition name: (property_identifier) @name)`,
  callExpression: `(call_expression function: [(identifier) @callee (member_expression) @callee])`,
  variableDecl: `(variable_declarator name: (identifier) @name) (lexical_declaration (variable_declarator name: (identifier) @name))`,
  assignment: `(assignment_expression left: (identifier) @target)`,
  returnStatement: `(return_statement) @return`,
  memberExpression: `(member_expression object: (identifier) @object property: [(property_identifier) (string)] @property)`,
};

const PYTHON_QUERIES = {
  functionDecl: `(function_definition name: (identifier) @name)`,
  callExpression: `(call function: [(identifier) @callee (attribute) @callee])`,
  variableDecl: `(assignment left: (identifier) @name)`,
  assignment: `(assignment left: (identifier) @target)`,
  returnStatement: `(return_statement) @return`,
  memberExpression: `(attribute object: (identifier) @object attribute: (identifier) @property)`,
};

const GO_QUERIES = {
  functionDecl: `(function_declaration name: (identifier) @name) (method_declaration name: (field_identifier) @name)`,
  callExpression: `(call_expression function: [(identifier) @callee (selector_expression) @callee])`,
  variableDecl: `(short_var_declaration left: (identifier) @name) (var_spec name: (identifier) @name)`,
  // Go's idiomatic `x := expr` is a short_var_declaration, not an assignment,
  // so matching only assignment_statement found no data flow in real Go code.
  assignment: `(short_var_declaration left: (expression_list (identifier) @target)) (assignment_statement left: (expression_list (identifier) @target))`,
  returnStatement: `(return_statement) @return`,
  memberExpression: `(selector_expression operand: (identifier) @object field: (field_identifier) @property)`,
};

const PHP_QUERIES = {
  functionDecl: `(function_definition name: (name) @name) (method_declaration name: (name) @name)`,
  callExpression: `(function_call_expression function: [(name) @callee (qualified_name) @callee])`,
  variableDecl: `(assignment_expression left: (variable_name) @name)`,
  assignment: `(assignment_expression left: (variable_name) @target)`,
  returnStatement: `(return_statement) @return`,
  memberExpression: `(member_access_expression object: (variable_name) @object name: (name) @property)`,
};

const RUBY_QUERIES = {
  functionDecl: `(method name: (identifier) @name)`,
  callExpression: `(call method: (identifier) @callee)`,
  variableDecl: `(assignment left: (identifier) @name)`,
  assignment: `(assignment left: (identifier) @target)`,
  returnStatement: `(return) @return`,
  memberExpression: `(call receiver: (identifier) @object method: (identifier) @property)`,
};

/** Escape a captured identifier for safe embedding in a RegExp. */
function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ─── Language Configs ──────────────────────────────────────────────────

function buildConfigs(): Map<string, LanguageConfig> {
  const configs = new Map<string, LanguageConfig>();

  const js = loadJsGrammar();
  const ts = loadTsGrammar();
  const py = loadPythonGrammar();
  const go = loadGoGrammar();
  const php = loadPhpGrammar();
  const ruby = loadRubyGrammar();

  if (js) configs.set('javascript', {
    name: 'JavaScript', extensions: ['.js', '.mjs', '.cjs'],
    grammar: js, queries: JS_QUERIES,
    stringTypes: ['string', 'template_string', 'template_substitution'],
    commentTypes: ['comment', 'html_comment'],
  });

  if (ts) configs.set('typescript', {
    name: 'TypeScript', extensions: ['.ts', '.tsx', '.mts', '.cts'],
    grammar: ts, queries: JS_QUERIES,
    stringTypes: ['string', 'template_string', 'template_substitution'],
    commentTypes: ['comment', 'html_comment'],
  });

  if (py) configs.set('python', {
    name: 'Python', extensions: ['.py', '.pyw', '.pyi'],
    grammar: py, queries: PYTHON_QUERIES,
    stringTypes: ['string', 'string_content'],
    commentTypes: ['comment'],
  });

  if (go) configs.set('go', {
    name: 'Go', extensions: ['.go'],
    grammar: go, queries: GO_QUERIES,
    stringTypes: ['interpreted_string_literal', 'raw_string_literal', 'rune_literal'],
    commentTypes: ['comment'],
  });

  if (php) configs.set('php', {
    name: 'PHP', extensions: ['.php', '.phtml', '.php3', '.php4', '.php5', '.phps'],
    grammar: php, queries: PHP_QUERIES,
    stringTypes: ['string', 'encapsed_string', 'string_content'],
    commentTypes: ['comment'],
  });

  if (ruby) configs.set('ruby', {
    name: 'Ruby', extensions: ['.rb', '.rake', '.gemspec'],
    grammar: ruby, queries: RUBY_QUERIES,
    stringTypes: ['string', 'string_content', 'string_array'],
    commentTypes: ['comment'],
  });

  return configs;
}

// ─── Multi-Language Builder ────────────────────────────────────────────

interface BuilderContext {
  graph: PropertyGraph;
  config: LanguageConfig;
  content: string;
  file: string;
  fileNodeId: string;
  variableDecls: Map<string, string>;
  functionDecls: Map<string, string>;
  sourceSnippets: Map<string, string>; // nodeId → source snippet
}

export class MultiLangBuilder {
  private configs: Map<string, LanguageConfig>;

  constructor() {
    this.configs = buildConfigs();
  }

  /** Available language configurations */
  getSupportedLanguages(): string[] {
    return [...this.configs.keys()];
  }

  /** Check if a file is supported */
  supportsFile(filePath: string): boolean {
    const ext = path.extname(filePath).toLowerCase();
    for (const [, config] of this.configs) {
      if (config.extensions.includes(ext)) return true;
    }
    return false;
  }

  /** Get language config for a file */
  getConfigForFile(filePath: string): LanguageConfig | undefined {
    const ext = path.extname(filePath).toLowerCase();
    for (const [lang, config] of this.configs) {
      if (config.extensions.includes(ext)) return config;
    }
    return undefined;
  }

  /**
   * Build a CPG for the given file using tree-sitter.
   * Returns map of file node ID to graph updates, or null if unsupported.
   */
  buildFile(filePath: string, graph: PropertyGraph): boolean {
    const ext = path.extname(filePath).toLowerCase();
    let config: LanguageConfig | undefined;

    for (const [, cfg] of this.configs) {
      if (cfg.extensions.includes(ext)) {
        config = cfg;
        break;
      }
    }

    if (!config) return false;

    try {
      const content = readSource(filePath);
      // Shared parser/query caches — see tree-sitter-engine. Building these per
      // file allocated native memory that only a finalizer would reclaim.
      const parser = parserFor(config.grammar);
      const tree = parser.parse(content);

      const fileNode = addNode(graph, 'FILE', path.basename(filePath), filePath,
        1, content.split('\n').length, 0, 0, '');

      const ctx: BuilderContext = {
        graph,
        config,
        content,
        file: filePath,
        fileNodeId: fileNode.id,
        variableDecls: new Map(),
        functionDecls: new Map(),
        sourceSnippets: new Map(),
      };

      this.extractFunctions(ctx, tree.rootNode);
      this.extractCallSites(ctx, tree.rootNode);
      // Must follow call-site extraction: data flow links assignments to the
      // call sites that consume them.
      this.buildDataFlow(ctx, tree.rootNode);

      // Annotate taint on ALL nodes
      this.annotateTaint(ctx);

      return true;
    } catch {
      return false;
    }
  }

  // ─── Function Extraction ─────────────────────────────────────────────

  private extractFunctions(ctx: BuilderContext, node: Parser.SyntaxNode) {
    try {
      const query = queryFor(ctx.config.grammar, ctx.config.queries.functionDecl, ctx.config.name + ':fn');
      const matches = query.matches(node);

      for (const match of matches) {
        const nameNode = match.captures.find((c: any) => c.name === 'name')?.node;
        if (!nameNode) continue;

        const funcName = this.nodeText(ctx, nameNode);
        const loc = nameNode.startPosition;

        const funcNode = addNode(ctx.graph, 'FUNCTION', funcName,
          ctx.file, loc.row + 1, nameNode.endPosition.row + 1,
          loc.column, nameNode.endPosition.column,
          this.nodeText(ctx, match.captures[0].node).substring(0, 200)
        );

        addEdge(ctx.graph, 'AST_CHILD', ctx.fileNodeId, funcNode.id);
        ctx.functionDecls.set(funcName, funcNode.id);
        ctx.sourceSnippets.set(funcNode.id, this.nodeText(ctx, match.captures[0].node));
      }
    } catch { /* query construction may fail for some grammars */ }
  }

  // ─── Call Site Extraction ────────────────────────────────────────────

  private extractCallSites(ctx: BuilderContext, node: Parser.SyntaxNode) {
    try {
      const query = queryFor(ctx.config.grammar, ctx.config.queries.callExpression, ctx.config.name + ':call');
      const matches = query.matches(node);

      for (const match of matches) {
        const calleeNode = match.captures.find((c: any) => c.name === 'callee')?.node;
        if (!calleeNode) continue;

        const calleeName = this.nodeText(ctx, calleeNode);
        const start = calleeNode.startPosition;
        const end = calleeNode.endPosition;

        // Find the full call expression node (parent of callee)
        let callNode = calleeNode;
        while (callNode.parent && !['call_expression', 'call', 'function_call_expression', 'method_call'].includes(callNode.parent.type)) {
          callNode = callNode.parent!;
        }
        if (callNode.parent) callNode = callNode.parent;

        const csNode = addNode(ctx.graph, 'CALL_SITE', calleeName,
          ctx.file, start.row + 1, end.row + 1,
          start.column, end.column,
          this.nodeText(ctx, callNode).substring(0, 200)
        );

        addEdge(ctx.graph, 'AST_CHILD', ctx.fileNodeId, csNode.id);
        ctx.sourceSnippets.set(csNode.id, this.nodeText(ctx, callNode));

        // Link to function definition
        const funcNodeId = ctx.functionDecls.get(calleeName);
        if (funcNodeId) {
          addEdge(ctx.graph, 'CALLS', csNode.id, funcNodeId, calleeName);
        }
      }
    } catch { /* skip */ }
  }

  // ─── Data Flow ───────────────────────────────────────────────────────

  /**
   * Link assignments to the later code that reads them.
   *
   * The precise taint query traverses DATA_FLOW edges, and this builder emitted
   * none — only AST_CHILD, CALLS and the taint self-annotations. Sources and
   * sinks were both being marked, but nothing connected them, so the
   * multi-language CPG could not report a finding no matter what it scanned.
   *
   * The `assignment` query in each language config already existed for this and
   * had never been wired up.
   *
   * Scope is intra-procedural and name-based: an assignment to `v` flows to any
   * later node in the same file whose code mentions `v`. That is deliberately
   * approximate — the precise query re-checks the variable at each hop, and the
   * alternative (no edges at all) finds nothing.
   */
  private buildDataFlow(ctx: BuilderContext, root: Parser.SyntaxNode) {
    const assignQuery = ctx.config.queries.assignment;
    if (!assignQuery) return;

    let matches: any[];
    try {
      matches = queryFor(ctx.config.grammar, assignQuery, ctx.config.name + ':assign').matches(root);
    } catch {
      return; // query does not compile for this grammar
    }

    // Every node that could consume a value, ordered by position.
    const consumers = getNodesByType(ctx.graph, 'CALL_SITE')
      .filter(n => n.file === ctx.file)
      .sort((a, b) => a.startLine - b.startLine);

    for (const match of matches) {
      const target = match.captures.find((c: any) => c.name === 'target')?.node;
      if (!target) continue;

      // PHP variable_name includes the `$`; strip it so the name matches usage.
      const varName = this.nodeText(ctx, target).replace(/^\$/, '').trim();
      if (!varName || varName.length > 60) continue;

      // The whole assignment statement, so the right-hand side is visible to
      // taint-source matching.
      let stmt: Parser.SyntaxNode = target;
      while (stmt.parent && !/assignment|expression_statement|short_var_declaration|variable_declaration/.test(stmt.parent.type)) {
        stmt = stmt.parent;
      }
      if (stmt.parent) stmt = stmt.parent;

      const start = stmt.startPosition;
      const assignNode = addNode(ctx.graph, 'ASSIGNMENT', varName,
        ctx.file, start.row + 1, stmt.endPosition.row + 1,
        start.column, stmt.endPosition.column,
        this.nodeText(ctx, stmt).substring(0, 200)
      );
      addEdge(ctx.graph, 'AST_CHILD', ctx.fileNodeId, assignNode.id);

      // Flow forward only: a use before the assignment is a different value.
      const usePattern = new RegExp(`(?:^|[^\\w$])\\$?${escapeRegExp(varName)}(?![\\w$])`);
      for (const consumer of consumers) {
        if (consumer.startLine < assignNode.startLine) continue;
        if (!usePattern.test(consumer.code)) continue;
        addEdge(ctx.graph, 'DATA_FLOW', assignNode.id, consumer.id, varName);
      }
    }
  }

  // ─── Taint Annotation ────────────────────────────────────────────────

  private annotateTaint(ctx: BuilderContext) {
    for (const [, node] of ctx.graph.nodes) {
      if (node.type === 'FILE') continue;

      // Sources
      for (const spec of DEFAULT_TAINT_SOURCES) {
        spec.pattern.lastIndex = 0;
        if (spec.pattern.test(node.code)) {
          addEdge(ctx.graph, 'TAINT_SOURCE', node.id, node.id, spec.category);
          break;
        }
      }

      // Sinks
      for (const spec of DEFAULT_TAINT_SINKS) {
        spec.pattern.lastIndex = 0;
        if (spec.pattern.test(node.code)) {
          addEdge(ctx.graph, 'TAINT_SINK', node.id, node.id, spec.category);
          break;
        }
      }

      // Sanitizers
      for (const spec of DEFAULT_SANITIZERS) {
        spec.pattern.lastIndex = 0;
        if (spec.pattern.test(node.code)) {
          addEdge(ctx.graph, 'SANITIZES', node.id, node.id, spec.protects);
          break;
        }
      }
    }
  }

  // ─── Utility ─────────────────────────────────────────────────────────

  private nodeText(ctx: BuilderContext, node: Parser.SyntaxNode): string {
    return ctx.content.substring(node.startIndex, node.endIndex);
  }

  /**
   * Build CPG for multiple files.
   */
  buildAll(files: string[]): PropertyGraph {
    resetIdCounter();
    const graph = createGraph();

    for (const file of files) {
      this.buildFile(file, graph);
    }

    return graph;
  }
}

// ─── Singleton ─────────────────────────────────────────────────────────

let defaultBuilder: MultiLangBuilder | null = null;

export function getMultiLangBuilder(): MultiLangBuilder {
  if (!defaultBuilder) {
    defaultBuilder = new MultiLangBuilder();
  }
  return defaultBuilder;
}
