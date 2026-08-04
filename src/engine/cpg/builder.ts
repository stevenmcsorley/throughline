/**
 * Code Property Graph Builder (Simplified)
 *
 * Multi-pass analysis that constructs a unified graph from source code.
 * Pass 1: AST construction — parse into syntax tree nodes
 * Pass 2: Control flow edges — connect statements in execution order
 * Pass 3: Data flow edges — track variable definitions to uses
 * Pass 4: Call graph edges — connect call sites to function definitions
 * Pass 5: Taint annotation — mark sources and sinks
 */

import * as fs from 'fs';
import * as path from 'path';
import * as babelParser from '@babel/parser';
import traverse from '@babel/traverse';
import * as t from '@babel/types';
import { readSource } from '../source-cache';

import {
  CpgNode, PropertyGraph, CpgNodeType,
  TaintSourceSpec, TaintSinkSpec, SanitizerSpec,
  DEFAULT_TAINT_SOURCES, DEFAULT_TAINT_SINKS, DEFAULT_SANITIZERS,
} from './types';

import {
  createGraph, addNode, addEdge, getNode, getNodesByType, resetIdCounter,
} from './graph';

// ─── Config ────────────────────────────────────────────────────────────

export interface CpgBuilderConfig {
  taintSources?: TaintSourceSpec[];
  taintSinks?: TaintSinkSpec[];
  sanitizers?: SanitizerSpec[];
  maxNodes?: number;
}

// ─── Utility: source snippet ───────────────────────────────────────────

function sourceSnippet(content: string, start: number, end: number): string {
  if (start == null || end == null) return '';
  const len = Math.min(end - start, 200);
  return content.substring(start, start + len).replace(/\n/g, ' ').trim();
}

// ─── Builder ───────────────────────────────────────────────────────────

export class CpgBuilder {
  private config: Required<CpgBuilderConfig>;
  private graph!: PropertyGraph;
  private fileContent: Map<string, string> = new Map();
  private variableDecls: Map<string, string> = new Map();     // varName → nodeId
  private functionDecls: Map<string, { nodeId: string; file: string }> = new Map();
  private statementOrder: string[] = [];
  private assignsVar: Map<string, string> = new Map();         // nodeId → varName
  private taintSourceNodes = new Map<string, CpgNode>();
  private taintSinkNodes = new Map<string, CpgNode>();
  private currentFile = '';
  private currentContent = '';

  constructor(config: CpgBuilderConfig = {}) {
    this.config = {
      taintSources: config.taintSources || DEFAULT_TAINT_SOURCES,
      taintSinks: config.taintSinks || DEFAULT_TAINT_SINKS,
      sanitizers: config.sanitizers || DEFAULT_SANITIZERS,
      maxNodes: config.maxNodes || 500000,
    };
  }

  build(files: string[]): PropertyGraph {
    resetIdCounter();
    this.graph = createGraph();
    this.functionDecls = new Map();
    this.fileContent = new Map();

    // Load all files
    for (const file of files) {
      try {
        const ext = path.extname(file).toLowerCase();
        if (!['.js', '.ts', '.jsx', '.tsx'].includes(ext)) continue;
        this.fileContent.set(file, readSource(file));
      } catch { /* skip */ }
    }

    // Phase 1: Parse each file
    for (const [file, content] of this.fileContent) {
      this.processFile(file, content);
    }

    // Phase 2: Annotate taint sources and sinks across the whole graph, once.
    //
    // This used to run at the end of every file. Because it scans every node in
    // the graph, file N re-annotated all N-1 files before it — O(files x nodes)
    // work, and a duplicate self-edge added on each pass. On an 840-file corpus
    // that produced 1.9M SANITIZES edges where ~2.3k were meaningful, 93% of the
    // entire graph, and left nodes with an out-degree in the thousands that the
    // taint BFS then walked repeatedly.
    this.annotateTaint();

    // Phase 3: Cross-file call graph
    this.buildCrossFileCalls();

    return this.graph;
  }

  // ─── File Processing ─────────────────────────────────────────────────

  private processFile(file: string, content: string) {
    this.currentFile = file;
    this.currentContent = content;
    this.variableDecls = new Map();
    this.statementOrder = [];
    this.assignsVar = new Map();

    const fileNode = addNode(this.graph, 'FILE', path.basename(file), file, 1, content.split('\n').length, 0, 0, '');
    const fileParentId = fileNode.id;

    // Parse AST
    let ast: t.File;
    try {
      ast = babelParser.parse(content, {
        sourceType: 'module',
        plugins: ['typescript', 'jsx', 'decorators-legacy'],
        errorRecovery: true,
      });
    } catch {
      try {
        ast = babelParser.parse(content, {
          sourceType: 'script',
          plugins: ['typescript', 'jsx', 'decorators-legacy'],
          errorRecovery: true,
        });
      } catch {
        return;
      }
    }

    // Pass 1a: Collect function/class declarations
    this.collectDecls(ast, fileParentId);

    // Pass 1b: Walk statements for control flow nodes
    this.walkBody(ast.program.body, fileParentId);

    // Pass 1c: Build control flow edges.
    // Correct to run per file: statementOrder is reset for each one, so this
    // links consecutive statements within a file and never across files.
    this.buildControlFlow();

    // Taint annotation is deliberately NOT run here — it scans the whole graph,
    // so calling it per file re-annotated every previously parsed file. See
    // build(), which runs it once after all files are parsed.
  }

  // ─── Declaration Collection ──────────────────────────────────────────

  private collectDecls(ast: t.File, fileParentId: string) {
    traverse(ast, {
      FunctionDeclaration: (p) => {
        const node = p.node;
        const name = node.id?.name;
        if (!name || !node.loc) return;

        const funcNode = addNode(this.graph, 'FUNCTION', name,
          this.currentFile, node.loc.start.line, node.loc.end.line,
          node.loc.start.column, node.loc.end.column,
          sourceSnippet(this.currentContent, node.start!, node.end!)
        );
        addEdge(this.graph, 'AST_CHILD', fileParentId, funcNode.id);

        const isExported = p.parent.type === 'ExportNamedDeclaration' ||
          p.parent.type === 'ExportDefaultDeclaration';
        this.functionDecls.set(name, { nodeId: funcNode.id, file: this.currentFile });
        if (isExported) {
          this.functionDecls.set(name, { nodeId: funcNode.id, file: this.currentFile });
        }

        // Parameters
        for (const param of node.params) {
          if (param.type === 'Identifier' && param.loc) {
            const pn = addNode(this.graph, 'PARAMETER', param.name,
              this.currentFile, param.loc.start.line, param.loc.end.line,
              param.loc.start.column, param.loc.end.column, param.name
            );
            addEdge(this.graph, 'HAS_PARAMETER', funcNode.id, pn.id);
            this.variableDecls.set(param.name, pn.id);
          }
        }
      },
    });
  }

  // ─── Body Walking ────────────────────────────────────────────────────

  private walkBody(body: t.Statement[], parentId: string) {
    for (const stmt of body) {
      if (!stmt.loc) continue;

      const snode = addNode(this.graph, 'STATEMENT', stmt.type,
        this.currentFile, stmt.loc.start.line, stmt.loc.end.line,
        stmt.loc.start.column, stmt.loc.end.column,
        sourceSnippet(this.currentContent, stmt.start!, stmt.end!)
      );

      addEdge(this.graph, 'AST_CHILD', parentId, snode.id);
      this.statementOrder.push(snode.id);

      // Recurse into blocks
      if (stmt.type === 'BlockStatement') {
        this.walkBody(stmt.body, snode.id);
      }
      if (stmt.type === 'IfStatement') {
        if (stmt.consequent.type === 'BlockStatement') {
          this.walkBody(stmt.consequent.body, snode.id);
        }
        if (stmt.alternate) {
          if (stmt.alternate.type === 'BlockStatement') {
            this.walkBody(stmt.alternate.body, snode.id);
          }
        }
      }
      if (stmt.type === 'ExpressionStatement') {
        this.processExpression(stmt.expression, snode.id);
      }
      if (stmt.type === 'VariableDeclaration') {
        for (const decl of stmt.declarations) {
          if (decl.id.type === 'Identifier' && decl.loc) {
            const dn = addNode(this.graph, 'VARIABLE_DECL', decl.id.name,
              this.currentFile, decl.loc.start.line, decl.loc.end.line,
              decl.loc.start.column, decl.loc.end.column,
              sourceSnippet(this.currentContent, decl.start!, decl.end!)
            );
            addEdge(this.graph, 'DECLARES', snode.id, dn.id);
            this.variableDecls.set(decl.id.name, dn.id);

            if (decl.init) {
              this.processExpression(decl.init, dn.id);
              if (decl.init.type === 'Identifier') {
                const srcId = this.variableDecls.get(decl.init.name);
                if (srcId) {
                  addEdge(this.graph, 'DATA_FLOW', srcId, dn.id, decl.init.name);
                }
              }
            }
          }
        }
      }
      if (stmt.type === 'ReturnStatement' && stmt.argument) {
        this.processExpression(stmt.argument, snode.id);
      }
    }
  }

  private processExpression(expr: t.Expression, parentId: string) {
    if (!expr.loc) return;

    if (expr.type === 'CallExpression') {
      let calleeName = '';
      if (expr.callee.type === 'Identifier') {
        calleeName = expr.callee.name;
      } else if (expr.callee.type === 'MemberExpression') {
        calleeName = this.memberName(expr.callee);
      }

      const cn = addNode(this.graph, 'CALL_SITE', calleeName || 'call',
        this.currentFile, expr.loc.start.line, expr.loc.end.line,
        expr.loc.start.column, expr.loc.end.column,
        sourceSnippet(this.currentContent, expr.start!, expr.end!)
      );
      addEdge(this.graph, 'AST_CHILD', parentId, cn.id);

      // Track argument flow
      for (const arg of expr.arguments) {
        if (arg.type === 'Identifier') {
          const varId = this.variableDecls.get(arg.name);
          if (varId) {
            addEdge(this.graph, 'DATA_FLOW', varId, cn.id, arg.name);
          }
        }
      }
    }

    if (expr.type === 'AssignmentExpression') {
      const an = addNode(this.graph, 'ASSIGNMENT', '=',
        this.currentFile, expr.loc.start.line, expr.loc.end.line,
        expr.loc.start.column, expr.loc.end.column,
        sourceSnippet(this.currentContent, expr.start!, expr.end!)
      );
      addEdge(this.graph, 'AST_CHILD', parentId, an.id);

      if (expr.left.type === 'Identifier') {
        this.assignsVar.set(an.id, expr.left.name);
      }

      if (expr.right.type === 'CallExpression') {
        this.processExpression(expr.right, an.id);
      }
      if (expr.right.type === 'Identifier') {
        const varId = this.variableDecls.get(expr.right.name);
        if (varId) {
          addEdge(this.graph, 'DATA_FLOW', varId, an.id, expr.right.name);
        }
      }
    }

    // Recurse into member-expressions-with-calls
    if (expr.type === 'MemberExpression' && expr.object.type === 'Identifier') {
      const mn = addNode(this.graph, 'MEMBER_EXPRESSION',
        this.memberName(expr),
        this.currentFile, expr.loc.start.line, expr.loc.end.line,
        expr.loc.start.column, expr.loc.end.column,
        sourceSnippet(this.currentContent, expr.start!, expr.end!)
      );
      addEdge(this.graph, 'AST_CHILD', parentId, mn.id);
      const varId = this.variableDecls.get(expr.object.name);
      if (varId) {
        addEdge(this.graph, 'REFERENCES', mn.id, varId, expr.object.name);
      }
    }
  }

  private memberName(node: t.MemberExpression): string {
    const parts: string[] = [];
    let cur: any = node;
    while (cur) {
      if (cur.type === 'MemberExpression') {
        if (cur.property.type === 'Identifier') parts.unshift(cur.property.name);
        else if (cur.property.type === 'StringLiteral') parts.unshift(cur.property.value);
        cur = cur.object;
      } else if (cur.type === 'Identifier') {
        parts.unshift(cur.name);
        break;
      } else break;
    }
    return parts.join('.');
  }

  // ─── Control Flow ────────────────────────────────────────────────────

  private buildControlFlow() {
    for (let i = 0; i < this.statementOrder.length - 1; i++) {
      const fromId = this.statementOrder[i];
      const toId = this.statementOrder[i + 1];
      addEdge(this.graph, 'CONTROL_FLOW', fromId, toId);

      // Data flow from assignment to next statement if variable is used
      const varName = this.assignsVar.get(fromId);
      if (varName) {
        const toNode = getNode(this.graph, toId);
        if (toNode && toNode.code.includes(varName)) {
          addEdge(this.graph, 'DATA_FLOW', fromId, toId, varName);
        }
      }
    }
  }

  // ─── Taint Annotation ────────────────────────────────────────────────

  private annotateTaint() {
    // Scan ALL nodes in the graph for taint source/sink patterns
    for (const [, node] of this.graph.nodes) {
      if (node.type === 'FILE') continue;

      // Sources
      for (const spec of this.config.taintSources) {
        spec.pattern.lastIndex = 0;
        if (spec.pattern.test(node.code)) {
          addEdge(this.graph, 'TAINT_SOURCE', node.id, node.id, spec.category);
          this.taintSourceNodes.set(node.id, node);
          break;
        }
      }

      // Sinks
      for (const spec of this.config.taintSinks) {
        spec.pattern.lastIndex = 0;
        if (spec.pattern.test(node.code)) {
          addEdge(this.graph, 'TAINT_SINK', node.id, node.id, spec.category);
          this.taintSinkNodes.set(node.id, node);
          break;
        }
      }

      // Sanitizers
      for (const spec of this.config.sanitizers) {
        spec.pattern.lastIndex = 0;
        if (spec.pattern.test(node.code)) {
          addEdge(this.graph, 'SANITIZES', node.id, node.id, spec.protects);
          break;
        }
      }
    }
  }

  // ─── Cross-File Call Graph ───────────────────────────────────────────

  private buildCrossFileCalls() {
    const callSites = getNodesByType(this.graph, 'CALL_SITE');

    for (const call of callSites) {
      const name = call.label;
      if (!name || name === 'call') continue;

      const decl = this.functionDecls.get(name);
      if (decl) {
        addEdge(this.graph, 'CALLS', call.id, decl.nodeId, name);
      }
    }
  }
}
