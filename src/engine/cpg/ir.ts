/**
 * Unified Intermediate Representation (IR)
 *
 * Language-agnostic IR between AST and analysis.
 * All languages lower to this IR before SSA construction and taint analysis.
 *
 * Based on a simplified three-address code model with explicit
 * basic blocks, phi nodes, and type annotation.
 */

// ─── IR Instructions ───────────────────────────────────────────────────

export type IrOpcode =
  | 'ASSIGN'       // dest := src
  | 'CALL'         // dest := callee(args...)
  | 'RETURN'       // return val
  | 'BINARY'       // dest := left op right
  | 'UNARY'        // dest := op operand
  | 'LOAD_PROP'    // dest := obj[prop]
  | 'STORE_PROP'   // obj[prop] := val
  | 'LOAD_ELEMENT' // dest := obj[index]
  | 'STORE_ELEMENT'// obj[index] := val
  | 'NEW'          // dest := new constructor(args...)
  | 'PHI'          // dest := φ(src1 from block1, src2 from block2, ...)
  | 'BRANCH'       // if cond goto trueBlock else falseBlock
  | 'JUMP'         // goto targetBlock
  | 'LITERAL'      // dest := literalValue
  | 'NOP';         // no operation (placeholder)

export type IrBinaryOp =
  | '+' | '-' | '*' | '/' | '%'
  | '===' | '!==' | '==' | '!=' | '<' | '>' | '<=' | '>='
  | '&&' | '||' | '&' | '|' | '^' | '<<' | '>>';

export type IrUnaryOp =
  | '-' | '!' | '~' | 'typeof' | 'void';

export interface IrOperand {
  kind: 'var' | 'literal' | 'temp' | 'undefined';
  name: string;
  type?: 'string' | 'number' | 'boolean' | 'object' | 'function' | 'unknown';
}

export interface PhiSource {
  value: IrOperand;
  blockId: number;
}

export interface IrInstruction {
  id: number;
  opcode: IrOpcode;
  dest?: IrOperand;
  op?: IrBinaryOp | IrUnaryOp;
  operands: IrOperand[];
  phiSources?: PhiSource[];
  callee?: IrOperand;
  arguments?: IrOperand[];
  branchCond?: IrOperand;
  trueBlock?: number;
  falseBlock?: number;
  jumpTarget?: number;
  literalValue?: string | number | boolean;
  /** Source location */
  file: string;
  line: number;
  column: number;
  /** Original source code snippet */
  code: string;
  /** Metadata */
  isTaintSource?: boolean;
  taintCategory?: string;
  isTaintSink?: boolean;
  sinkCategory?: string;
  isSanitizer?: boolean;
  sanitizerProtects?: string;
}

// ─── Basic Block ───────────────────────────────────────────────────────

export interface BasicBlock {
  id: number;
  label: string;
  instructions: IrInstruction[];
  /** Predecessor block IDs */
  predecessors: number[];
  /** Successor block IDs */
  successors: number[];
  /** Dominator tree parent */
  idom?: number;
  /** Dominator tree children */
  dominatorChildren: number[];
  /** Dominance frontier */
  dominanceFrontier: number[];
}

// ─── IR Function ───────────────────────────────────────────────────────

export interface IrFunction {
  name: string;
  file: string;
  parameters: IrOperand[];
  blocks: BasicBlock[];
  entryBlock: number;
  exitBlock: number;
  /** Variable → set of block IDs where defined */
  defSites: Map<string, Set<number>>;
  /** Variable → set of block IDs where used */
  useSites: Map<string, Set<number>>;
  /** Variables live at entry to each block */
  liveIn: Map<number, Set<string>>;
  /** Variables live at exit from each block */
  liveOut: Map<number, Set<string>>;
}

// ─── SSA Form ──────────────────────────────────────────────────────────

export interface SsaFunction extends IrFunction {
  /** Original variable name → list of SSA version names */
  versions: Map<string, string[]>;
  /** For each φ node, the merged variable name */
  phiVars: Map<number, string>;
  /** Def-use chains: SSA var → set of instruction IDs that use it */
  defUse: Map<string, Set<number>>;
  /** Use-def chains: instruction ID → SSA var it uses */
  useDef: Map<number, string>;
}

// ─── Points-To ─────────────────────────────────────────────────────────

export type PointsToSet = Set<string>; // set of allocation site IDs

export interface PointsToResult {
  /** Variable → set of allocation sites it may point to */
  varPointsTo: Map<string, PointsToSet>;
  /** Allocation site → set of allocation sites it may point to */
  allocPointsTo: Map<string, PointsToSet>;
}

// ─── Function Summary ──────────────────────────────────────────────────

export interface FunctionSummary {
  functionName: string;
  file: string;
  /** Parameter index → taint behavior */
  paramTaint: Map<number, TaintBehavior>;
  /** Whether this function sanitizes specific sink categories */
  sanitizes: Set<string>;
  /** Whether return value carries taint from params */
  returnTaint: Set<number>; // parameter indices that flow to return
  /** Sinks reached within this function */
  internalSinks: { category: string; line: number }[];
  /** Whether this is a pure function (no side effects) */
  isPure: boolean;
}

export type TaintBehavior =
  | 'propagates'    // Taint flows through unchanged
  | 'sanitizes'     // Taint is removed/escaped
  | 'blocks'        // Function never reaches sinks with this param
  | 'transforms';   // Taint is transformed (e.g., converted to safe type)

// ─── IR Builder Context ────────────────────────────────────────────────

export interface IrBuilder {
  functions: Map<string, IrFunction>;
  nextId: number;
  nextBlockId: number;
  currentFile: string;
  /** Mapping from source variable names to IR operands */
  varMap: Map<string, IrOperand>;
  /** Temporary counter */
  tempCounter: number;
}

export function createIrBuilder(): IrBuilder {
  return {
    functions: new Map(),
    nextId: 1,
    nextBlockId: 1,
    currentFile: '',
    varMap: new Map(),
    tempCounter: 1,
  };
}

export function nextIrId(builder: IrBuilder): number {
  return builder.nextId++;
}

export function nextBlockId(builder: IrBuilder): number {
  return builder.nextBlockId++;
}

export function newTemp(builder: IrBuilder, type?: string): IrOperand {
  return {
    kind: 'temp',
    name: `%t${builder.tempCounter++}`,
    type: type as any || 'unknown',
  };
}

export function newBlock(builder: IrBuilder, label: string = ''): BasicBlock {
  return {
    id: nextBlockId(builder),
    label: label || `B${builder.nextBlockId - 1}`,
    instructions: [],
    predecessors: [],
    successors: [],
    dominatorChildren: [],
    dominanceFrontier: [],
  };
}
