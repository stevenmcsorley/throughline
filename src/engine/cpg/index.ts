/**
 * Code Property Graph Engine — Professional-Grade Static Analysis
 *
 * Architecture:
 *   1. IR (Intermediate Representation) — language-agnostic three-address code
 *   2. SSA (Static Single Assignment) — precise def-use chains
 *   3. Points-To Analysis (Andersen-style) — alias resolution
 *   4. Function Summaries — modular taint propagation
 *   5. Multi-Language Builder — tree-sitter for JS/TS/Python/Go/PHP/Ruby
 *   6. Precise Taint Query — variable-aware, sanitizer-aware tracking
 *
 * The CPG unifies AST, control flow, data flow, and call graph into a
 * single labeled property graph. Vulnerability detection becomes graph
 * traversal queries with mathematical precision.
 */

// Graph infrastructure
export {
  createGraph, addNode, addEdge, getNode,
  getNodesByType, getFileNodes, findNodes, findNodesByPattern,
  outEdges, inEdges, follow, followReverse,
  findPaths, toDot, graphStats, resetIdCounter,
} from './graph';

// IR types and builder
export {
  createIrBuilder, nextIrId, nextBlockId, newTemp, newBlock,
} from './ir';
export type {
  IrOpcode, IrOperand, IrInstruction, IrBinaryOp, IrUnaryOp,
  BasicBlock, IrFunction, IrBuilder, PhiSource,
  SsaFunction, PointsToResult, PointsToSet,
  FunctionSummary, TaintBehavior,
} from './ir';

// SSA construction
export {
  buildSsa, computeDominators, computeDominanceFrontiers,
  traceTaint, getDefs, getUses,
} from './ssa';

// Points-to analysis
export { PointsToAnalyzer, getPointsToAnalyzer } from './points-to';
export type { PointsToConstraint } from './points-to';

// Function summaries
export {
  computeFunctionSummary, getFunctionSummary,
  propagatesTaint, sanitizesCategory, isPure,
  resolveCallSummary, computeAllSummaries,
  clearSummaryCache, summaryCacheSize, getCachedFunctionNames,
  serializeSummaries, deserializeSummaries,
} from './summaries';
export type { SummaryOptions } from './summaries';

// Multi-language builder
export { MultiLangBuilder, getMultiLangBuilder } from './multi-lang-builder';

// Babel-based JS/TS builder (fast path)
export { CpgBuilder } from './builder';
export type { CpgBuilderConfig } from './builder';

// Query engines
export {
  runPreciseTaintQuery,
  runAllCpgQueries,
  runTaintQuery,
  findDangerousCalls,
  computeCpgStats,
} from './query';
export type { TaintQueryOptions } from './query';

// Re-export types from parent
export type * from './types';
