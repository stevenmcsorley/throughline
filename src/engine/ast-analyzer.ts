import * as fs from 'fs';
import * as path from 'path';
import { AstContext, TaintFlow, TaintSource, TaintSink, Confidence } from '../types';

// Lazy-load babel to avoid requiring it for non-JS files
let babelParser: any = null;
let babelTraverse: any = null;
let babelTypes: any = null;

function ensureBabel(): boolean {
  if (babelParser) return true;
  try {
    babelParser = require('@babel/parser');
    babelTraverse = require('@babel/traverse').default;
    babelTypes = require('@babel/types');
    return true;
  } catch {
    return false;
  }
}

export function canAnalyzeAst(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts'].includes(ext);
}

// ─── Known taint sources ───
const DEFAULT_TAINT_SOURCES: TaintSource[] = [
  // Express/Node.js
  { name: 'req.body', category: 'user-input', pattern: 'req\\.body', description: 'Express request body' },
  { name: 'req.query', category: 'user-input', pattern: 'req\\.query', description: 'Express query params' },
  { name: 'req.params', category: 'user-input', pattern: 'req\\.params', description: 'Express route params' },
  { name: 'req.cookies', category: 'user-input', pattern: 'req\\.cookies', description: 'Request cookies' },
  { name: 'req.headers', category: 'user-input', pattern: 'req\\.headers', description: 'Request headers' },
  // Koa
  { name: 'ctx.request.body', category: 'user-input', pattern: 'ctx\\.request\\.body', description: 'Koa request body' },
  { name: 'ctx.query', category: 'user-input', pattern: 'ctx\\.query', description: 'Koa query params' },
  { name: 'ctx.params', category: 'user-input', pattern: 'ctx\\.params', description: 'Koa route params' },
  // Fastify
  { name: 'request.body', category: 'user-input', pattern: 'request\\.body', description: 'Fastify request body' },
  // Next.js
  { name: 'req.body (Next)', category: 'user-input', pattern: 'req\\.body', description: 'Next.js API route body' },
  { name: 'req.query (Next)', category: 'user-input', pattern: 'req\\.query', description: 'Next.js API route query' },
  // Generic
  { name: 'URLSearchParams', category: 'user-input', pattern: 'URLSearchParams', description: 'URL search params' },
  { name: 'window.location', category: 'user-input', pattern: 'window\\.location', description: 'Browser location' },
  { name: 'localStorage', category: 'user-input', pattern: 'localStorage\\.getItem', description: 'Local storage' },
  { name: 'process.env', category: 'environment', pattern: 'process\\.env', description: 'Environment variables' },
  { name: 'fs.readFileSync', category: 'file', pattern: 'readFileSync', description: 'File system read' },
  { name: 'fetch response', category: 'network', pattern: 'fetch\\(', description: 'Network fetch response' },
];

// ─── Known taint sinks ───
const DEFAULT_TAINT_SINKS: TaintSink[] = [
  // Code execution
  { name: 'eval', category: 'code-exec', pattern: 'eval\\(', description: 'JavaScript eval' },
  { name: 'Function constructor', category: 'code-exec', pattern: 'new Function\\(', description: 'Function constructor' },
  { name: 'setTimeout string', category: 'code-exec', pattern: 'setTimeout\\(', description: 'setTimeout with string' },
  { name: 'setInterval string', category: 'code-exec', pattern: 'setInterval\\(', description: 'setInterval with string' },
  // SQL
  { name: 'connection.query', category: 'sql', pattern: '(?:connection|db|pool)\\.query\\(', description: 'SQL query' },
  { name: 'connection.execute', category: 'sql', pattern: '(?:connection|db|pool)\\.execute\\(', description: 'SQL execute' },
  { name: 'sequelize.query', category: 'sql', pattern: 'sequelize\\.query\\(', description: 'Sequelize raw query' },
  { name: 'knex.raw', category: 'sql', pattern: 'knex\\.raw\\(', description: 'Knex raw query' },
  // NoSQL
  { name: 'collection.find', category: 'sql', pattern: '\\.find\\(', description: 'MongoDB find' },
  { name: 'Model.find (Mongoose)', category: 'sql', pattern: '\\.findOne\\(', description: 'Mongoose find' },
  // Command
  { name: 'exec', category: 'command', pattern: 'exec\\(', description: 'Shell exec' },
  { name: 'execSync', category: 'command', pattern: 'execSync\\(', description: 'Shell execSync' },
  { name: 'spawn', category: 'command', pattern: 'spawn\\(', description: 'Process spawn' },
  // File operations
  { name: 'fs.writeFile', category: 'file-op', pattern: 'writeFile\\(', description: 'File write' },
  { name: 'fs.readFile', category: 'file-op', pattern: 'readFile\\(', description: 'File read' },
  { name: 'fs.unlink', category: 'file-op', pattern: 'unlink\\(', description: 'File delete' },
  // Network
  { name: 'fetch', category: 'network-req', pattern: 'fetch\\(', description: 'HTTP fetch' },
  { name: 'axios', category: 'network-req', pattern: 'axios\\(', description: 'Axios request' },
  { name: 'http.request', category: 'network-req', pattern: 'https?\\.(?:get|request)\\(', description: 'Node.js HTTP request' },
  // HTML rendering
  { name: 'innerHTML', category: 'html-render', pattern: '\\.innerHTML\\s*=', description: 'innerHTML assignment' },
  { name: 'outerHTML', category: 'html-render', pattern: '\\.outerHTML\\s*=', description: 'outerHTML assignment' },
  { name: 'document.write', category: 'html-render', pattern: 'document\\.write\\(', description: 'document.write' },
  { name: 'dangerouslySetInnerHTML', category: 'html-render', pattern: 'dangerouslySetInnerHTML', description: 'React unsafe HTML' },
  // Redirect
  { name: 'res.redirect', category: 'redirect', pattern: 'res\\.redirect\\(', description: 'Express redirect' },
  { name: 'location.href', category: 'redirect', pattern: 'location\\.href\\s*=', description: 'Location redirect' },
  // Crypto
  { name: 'createHash', category: 'crypto', pattern: 'createHash\\(', description: 'Crypto hash' },
  { name: 'createCipher', category: 'crypto', pattern: 'createCipher\\(', description: 'Crypto cipher' },
  // Deserialize
  { name: 'JSON.parse', category: 'deserialize', pattern: 'JSON\\.parse\\(', description: 'JSON parse' },
  { name: 'jwt.decode', category: 'auth', pattern: 'jwt\\.decode\\(', description: 'JWT decode' },
  // Template
  { name: 'res.render', category: 'template', pattern: 'res\\.render\\(', description: 'Express template render' },
];

// ─── Known sanitizers ───
const SANITIZER_PATTERNS = [
  'escape\\(', 'sanitizeHtml\\(', 'DOMPurify\\.sanitize\\(', 'htmlspecialchars\\(', 'htmlentities\\(',
  'encodeURIComponent\\(', 'mongo-sanitize\\(', 'validator\\.escape\\(', 'sanitize\\(', '\\$sanitize\\(',
  'stripTags\\(', 'xss\\(', 'he\\.encode\\(', 'escapeHtml\\(', 'purify\\(', 'clean\\(',
  '_.escape\\(', 'lodash\\.escape\\(', '\\bescapeHtml\\b',
];

export function analyzeAst(filePath: string): AstContext | null {
  if (!canAnalyzeAst(filePath) || !ensureBabel()) return null;

  const ctx: AstContext = {
    imports: new Map(),
    variableTypes: new Map(),
    functionCalls: new Map(),
    taintedVariables: new Set(),
    sanitizerCalls: new Set(),
    scopeChain: new Map(),
  };

  try {
    const code = fs.readFileSync(filePath, 'utf-8');
    const isTsx = filePath.endsWith('.tsx') || filePath.endsWith('.ts') || filePath.endsWith('.mts') || filePath.endsWith('.cts');

    const ast = babelParser.parse(code, {
      sourceType: 'module',
      plugins: [
        'jsx',
        ...(isTsx ? ['typescript'] : []),
        'decorators-legacy',
        'classProperties',
        'optionalChaining',
        'nullishCoalescingOperator',
      ],
      errorRecovery: true,
    });

    // Track variables and their sources
    babelTraverse(ast, {
      // Track imports
      ImportDeclaration(nodePath: any) {
        const source = nodePath.node.source.value;
        for (const spec of nodePath.node.specifiers || []) {
          if (spec.type === 'ImportDefaultSpecifier' || spec.type === 'ImportSpecifier') {
            ctx.imports.set(spec.local.name, source);
          }
        }
      },

      // Track function calls for data flow
      CallExpression(nodePath: any) {
        const callee = nodePath.node.callee;
        const args = nodePath.node.arguments || [];

        // Get callee name
        let calleeName = '';
        if (callee.type === 'Identifier') {
          calleeName = callee.name;
        } else if (callee.type === 'MemberExpression' && callee.property && callee.property.type === 'Identifier') {
          calleeName = callee.property.name;
        }

        // Check for sanitizer calls
        for (const sanitizer of SANITIZER_PATTERNS) {
          if (new RegExp(sanitizer).test(code.slice(nodePath.node.start, nodePath.node.end))) {
            ctx.sanitizerCalls.add(calleeName || sanitizer);
          }
        }

        // Track argument names that are variables
        const argNames: string[] = [];
        for (const arg of args) {
          if (arg.type === 'Identifier') {
            argNames.push(arg.name);
          } else if (arg.type === 'MemberExpression' && arg.object && arg.object.type === 'Identifier') {
            argNames.push(`${arg.object.name}.${arg.property?.name || '?'}`);
          }
        }
        if (calleeName && argNames.length > 0) {
          ctx.functionCalls.set(calleeName, argNames);
        }
      },

      // Track assignments from known taint sources
      AssignmentExpression(nodePath: any) {
        const right = nodePath.node.right;
        let sourceText = code.slice(right.start, right.end);

        for (const source of DEFAULT_TAINT_SOURCES) {
          if (new RegExp(source.pattern).test(sourceText)) {
            const left = nodePath.node.left;
            if (left.type === 'Identifier') {
              ctx.taintedVariables.add(left.name);
            } else if (left.type === 'MemberExpression' && left.object.type === 'Identifier') {
              ctx.taintedVariables.add(`${left.object.name}.${left.property?.name || '?'}`);
            }
          }
        }
      },

      // Track variable declarations from taint sources
      VariableDeclarator(nodePath: any) {
        const id = nodePath.node.id;
        const init = nodePath.node.init;
        
        // Track type annotations
        if (id && id.name && init && id.typeAnnotation) {
          ctx.variableTypes.set(id.name, code.slice(id.typeAnnotation.start, id.typeAnnotation.end));
        }
        
        if (!init) return;
        const initText = code.slice(init.start, init.end);

        for (const source of DEFAULT_TAINT_SOURCES) {
          if (new RegExp(source.pattern).test(initText)) {
            const id = nodePath.node.id;
            if (id.type === 'Identifier') {
              ctx.taintedVariables.add(id.name);
            }
          }
        }

        // Track property destructuring from req
        if (init.type === 'MemberExpression') {
          const objText = code.slice(init.start, init.end);
          if (/req\.(?:body|query|params|cookies|headers)/.test(objText)) {
            const id = nodePath.node.id;
            if (id.type === 'Identifier') {
              ctx.taintedVariables.add(id.name);
            }
          }
        }
      },
    });

  } catch (err) {
    // Parse error — return what we have
  }

  return ctx;
}

export function traceTaint(
  variableName: string,
  astCtx: AstContext,
  sinks: TaintSink[],
  fileContent: string,
  line: number,
): TaintFlow | null {
  // Check if this variable is tainted
  if (!astCtx.taintedVariables.has(variableName)) {
    // Check partial names (e.g., "req.body" matches "body" destructured)
    for (const tainted of astCtx.taintedVariables) {
      if (variableName.includes(tainted) || tainted.includes(variableName)) {
        return {
          source: tainted,
          sinks: sinks.filter(s => {
            const lineText = fileContent.split('\n')[line - 1] || '';
            return new RegExp(s.pattern).test(lineText);
          }).map(s => s.pattern),
          variableChain: [variableName],
          sanitizers: [...astCtx.sanitizerCalls],
          confidence: astCtx.sanitizerCalls.size > 0 ? 'low' : 'high',
        };
      }
    }
    return null;
  }

  return {
    source: variableName,
    sinks: sinks.filter(s => {
      const lineText = fileContent.split('\n')[line - 1] || '';
      return new RegExp(s.pattern).test(lineText);
    }).map(s => s.pattern),
    variableChain: [variableName],
    sanitizers: [...astCtx.sanitizerCalls],
    confidence: astCtx.sanitizerCalls.size > 0 ? 'low' : 'high',
  };
}

export { DEFAULT_TAINT_SOURCES, DEFAULT_TAINT_SINKS, SANITIZER_PATTERNS };
