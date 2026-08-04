/**
 * Function Summary Analysis
 *
 * Pre-computes taint propagation behavior for each function.
 * Enables modular analysis: when a function is called at multiple
 * sites, the summary is reused rather than re-analyzing the body.
 *
 * Summary captures:
 * - Which parameters propagate taint to the return value
 * - Which parameters reach internal sinks
 * - Whether the function sanitizes input
 * - Side effects (purity)
 */

import { SsaFunction, IrInstruction, IrOpcode, FunctionSummary, TaintBehavior } from './ir';
import { traceTaint } from './ssa';
import { DEFAULT_TAINT_SOURCES, DEFAULT_TAINT_SINKS, DEFAULT_SANITIZERS } from './types';

// ─── Summary Cache ─────────────────────────────────────────────────────

const summaryCache = new Map<string, FunctionSummary>();
// Key format: "file::functionName"

function cacheKey(file: string, funcName: string): string {
  return `${file}::${funcName}`;
}

// ─── Summary Computation ───────────────────────────────────────────────

export interface SummaryOptions {
  /** File path being analyzed */
  file: string;
  /** Function name */
  functionName: string;
}

/**
 * Compute a function summary from its SSA form.
 */
export function computeFunctionSummary(
  ssaFunc: SsaFunction,
  options: SummaryOptions
): FunctionSummary {
  const key = cacheKey(options.file, options.functionName);

  // Check cache
  const cached = summaryCache.get(key);
  if (cached) return cached;

  const summary: FunctionSummary = {
    functionName: options.functionName,
    file: options.file,
    paramTaint: new Map(),
    sanitizes: new Set(),
    returnTaint: new Set(),
    internalSinks: [],
    isPure: true,
  };

  // Analyze each parameter
  for (let i = 0; i < ssaFunc.parameters.length; i++) {
    const param = ssaFunc.parameters[i];

    // Find the instruction that first defines this parameter
    const entryBlock = ssaFunc.blocks.find(b => b.id === ssaFunc.entryBlock);
    if (!entryBlock) continue;

    const paramInstrs = entryBlock.instructions
      .filter(instr => instr.dest && instr.dest.name === param.name);

    if (paramInstrs.length === 0) {
      summary.paramTaint.set(i, 'propagates');
      continue;
    }

    // Trace taint from parameter definition
    const reached = traceTaint(param.name, ssaFunc, paramInstrs[0].id);

    // Check if parameter reaches any return statements
    let reachesReturn = false;
    let reachesSink = false;
    for (const block of ssaFunc.blocks) {
      for (const instr of block.instructions) {
        if (!reached.has(instr.id)) continue;

        if (instr.opcode === 'RETURN') {
          reachesReturn = true;
          summary.returnTaint.add(i);
        }

        // Check for sinks
        if (instr.isTaintSink && instr.sinkCategory) {
          reachesSink = true;
          summary.internalSinks.push({
            category: instr.sinkCategory,
            line: instr.line,
          });
        }

        // Check for sanitizers
        if (instr.isSanitizer && instr.sanitizerProtects) {
          summary.sanitizes.add(instr.sanitizerProtects);
        }
      }
    }

    // Determine taint behavior
    if (reachesSink) {
      summary.paramTaint.set(i, 'propagates');
      summary.isPure = false;
    } else if (summary.sanitizes.size > 0 && !reachesReturn) {
      summary.paramTaint.set(i, 'sanitizes');
    } else if (!reachesReturn) {
      summary.paramTaint.set(i, 'blocks');
    } else {
      summary.paramTaint.set(i, 'propagates');
    }
  }

  // Cache and return
  summaryCache.set(key, summary);
  return summary;
}

// ─── Summary Query API ─────────────────────────────────────────────────

/**
 * Get a previously computed function summary.
 */
export function getFunctionSummary(file: string, funcName: string): FunctionSummary | undefined {
  return summaryCache.get(cacheKey(file, funcName));
}

/**
 * Check if a function call propagates taint from a specific argument index
 * to the return value.
 */
export function propagatesTaint(
  file: string,
  funcName: string,
  argIndex: number
): boolean {
  const summary = getFunctionSummary(file, funcName);
  if (!summary) return true; // Conservative: assume taint propagates
  return summary.returnTaint.has(argIndex);
}

/**
 * Check if a function call sanitizes input against a specific sink category.
 */
export function sanitizesCategory(
  file: string,
  funcName: string,
  category: string
): boolean {
  const summary = getFunctionSummary(file, funcName);
  if (!summary) return false;
  return summary.sanitizes.has(category);
}

/**
 * Check if a function is pure (no side effects, no sinks reached).
 */
export function isPure(file: string, funcName: string): boolean {
  const summary = getFunctionSummary(file, funcName);
  if (!summary) return false;
  return summary.isPure;
}

// ─── Cache Management ──────────────────────────────────────────────────

export function clearSummaryCache(): void {
  summaryCache.clear();
}

export function summaryCacheSize(): number {
  return summaryCache.size;
}

export function getCachedFunctionNames(): string[] {
  return [...summaryCache.keys()];
}

// ─── Cross-File Summary Resolution ─────────────────────────────────────

/**
 * Resolve a function call across the summary cache.
 * Returns the taint behavior for the result of the call.
 */
export function resolveCallSummary(
  calleeName: string,
  argTaints: Map<number, boolean>,
  sourceFile: string
): {
  resultTainted: boolean;
  sanitizedCategories: Set<string>;
  reachedSinks: { category: string; line: number }[];
} {
  const result = {
    resultTainted: false,
    sanitizedCategories: new Set<string>(),
    reachedSinks: [] as { category: string; line: number }[],
  };

  // Search summary cache for any matching function name (cross-file)
  for (const [key, summary] of summaryCache) {
    if (key.endsWith(`::${calleeName}`)) {
      // Check each tainted argument
      for (const [argIdx, isTainted] of argTaints) {
        if (isTainted) {
          const behavior = summary.paramTaint.get(argIdx);
          if (behavior === 'propagates') {
            if (summary.returnTaint.has(argIdx)) {
              result.resultTainted = true;
            }
            result.reachedSinks.push(...summary.internalSinks);
          }
        }
      }

      // Always include the function's sanitizer info
      for (const cat of summary.sanitizes) {
        result.sanitizedCategories.add(cat);
      }

      return result;
    }
  }

  // No summary found: conservative — assume taint propagates
  result.resultTainted = true;
  return result;
}

// ─── Batch Summary Computation ─────────────────────────────────────────

/**
 * Compute summaries for all functions in a set of SSA functions.
 */
export function computeAllSummaries(
  ssaFuncs: Map<string, SsaFunction>,
  file: string
): void {
  for (const [name, ssaFunc] of ssaFuncs) {
    computeFunctionSummary(ssaFunc, { file, functionName: name });
  }
}

// ─── Summary Serialization ─────────────────────────────────────────────

export function serializeSummaries(): string {
  const data: any[] = [];
  for (const [key, summary] of summaryCache) {
    data.push({
      key,
      functionName: summary.functionName,
      file: summary.file,
      paramTaint: [...summary.paramTaint].map(([k, v]) => [k, v]),
      sanitizes: [...summary.sanitizes],
      returnTaint: [...summary.returnTaint],
      internalSinks: summary.internalSinks,
      isPure: summary.isPure,
    });
  }
  return JSON.stringify(data, null, 2);
}

export function deserializeSummaries(json: string): void {
  try {
    const data = JSON.parse(json);
    for (const entry of data) {
      const summary: FunctionSummary = {
        functionName: entry.functionName,
        file: entry.file,
        paramTaint: new Map(entry.paramTaint),
        sanitizes: new Set(entry.sanitizes),
        returnTaint: new Set(entry.returnTaint),
        internalSinks: entry.internalSinks,
        isPure: entry.isPure,
      };
      summaryCache.set(entry.key, summary);
    }
  } catch { /* ignore */ }
}
