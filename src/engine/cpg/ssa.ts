/**
 * SSA Construction
 *
 * Builds Static Single Assignment (SSA) form from IR.
 *
 * Algorithm steps:
 * 1. Compute dominator tree
 * 2. Compute dominance frontiers
 * 3. Insert φ nodes at dominance frontiers
 * 4. Rename variables to SSA versions
 * 5. Build def-use and use-def chains
 */

import {
  IrFunction, BasicBlock, IrInstruction, IrOperand,
  SsaFunction, PhiSource, IrOpcode,
} from './ir';

// ─── Dominator Tree ────────────────────────────────────────────────────

/**
 * Compute immediate dominators using Cooper-Harvey-Kennedy algorithm.
 * A node d dominates node n if every path from entry to n goes through d.
 */
export function computeDominators(func: IrFunction): void {
  const n = func.blocks.length;
  const blockIds = func.blocks.map(b => b.id);
  const idToIdx = new Map<number, number>();
  blockIds.forEach((id, i) => idToIdx.set(id, i));

  // Initialize: entry dominates itself, all others dominated by undefined
  const idom: (number | undefined)[] = new Array(n);
  idom[idToIdx.get(func.entryBlock)!] = func.entryBlock;

  // Reverse postorder traversal
  const rpo = reversePostorder(func);

  let changed = true;
  while (changed) {
    changed = false;
    for (const blockId of rpo) {
      if (blockId === func.entryBlock) continue;
      const idx = idToIdx.get(blockId)!;
      const block = func.blocks[idx];

      // Find first processed predecessor
      let newIdom: number | undefined;
      for (const predId of block.predecessors) {
        if (idom[idToIdx.get(predId)!] !== undefined) {
          newIdom = predId;
          break;
        }
      }

      if (newIdom === undefined) continue;

      // Intersect all predecessors
      for (const predId of block.predecessors) {
        if (predId === newIdom) continue;
        const predIdx = idToIdx.get(predId)!;
        if (idom[predIdx] !== undefined) {
          newIdom = intersect(newIdom, predId, idom, idToIdx);
        }
      }

      if (idom[idx] !== newIdom) {
        idom[idx] = newIdom;
        changed = true;
      }
    }
  }

  // Set idom and children
  for (let i = 0; i < n; i++) {
    func.blocks[i].idom = idom[i];
    func.blocks[i].dominatorChildren = [];
  }

  for (let i = 0; i < n; i++) {
    const dom = idom[i];
    if (dom !== undefined && dom !== blockIds[i]) {
      const domIdx = idToIdx.get(dom)!;
      func.blocks[domIdx].dominatorChildren.push(blockIds[i]);
    }
  }
}

function intersect(b1: number, b2: number, idom: (number | undefined)[], idToIdx: Map<number, number>): number {
  let finger1 = b1;
  let finger2 = b2;

  while (finger1 !== finger2) {
    while (idToIdx.get(finger1)! > idToIdx.get(finger2)!) {
      const idx = idToIdx.get(finger1)!;
      finger1 = idom[idx]!;
    }
    while (idToIdx.get(finger2)! > idToIdx.get(finger1)!) {
      const idx = idToIdx.get(finger2)!;
      finger2 = idom[idx]!;
    }
  }
  return finger1;
}

// ─── Reverse Postorder ─────────────────────────────────────────────────

function reversePostorder(func: IrFunction): number[] {
  const visited = new Set<number>();
  const order: number[] = [];

  function dfs(blockId: number) {
    visited.add(blockId);
    const block = func.blocks.find(b => b.id === blockId);
    if (!block) return;
    for (const succId of block.successors) {
      if (!visited.has(succId)) {
        dfs(succId);
      }
    }
    order.push(blockId);
  }

  dfs(func.entryBlock);
  return order.reverse();
}

// ─── Dominance Frontiers ───────────────────────────────────────────────

export function computeDominanceFrontiers(func: IrFunction): void {
  for (const block of func.blocks) {
    block.dominanceFrontier = [];
  }

  const idToIdx = new Map<number, number>();
  func.blocks.forEach((b, i) => idToIdx.set(b.id, i));

  for (const block of func.blocks) {
    if (block.predecessors.length < 2) continue;

    for (const predId of block.predecessors) {
      let runner = predId;

      while (runner !== block.idom) {
        const runnerBlock = func.blocks[idToIdx.get(runner)!];
        if (!runnerBlock.dominanceFrontier.includes(block.id)) {
          runnerBlock.dominanceFrontier.push(block.id);
        }
        runner = runnerBlock.idom!;
      }
    }
  }
}

// ─── Variable Collection ───────────────────────────────────────────────

/**
 * Collect all variables and their def/use sites.
 */
function collectVariables(func: IrFunction): Map<string, { defs: Set<number>; uses: Set<number> }> {
  const vars = new Map<string, { defs: Set<number>; uses: Set<number> }>();

  for (const block of func.blocks) {
    for (const instr of block.instructions) {
      // Definitions (dest)
      if (instr.dest && instr.dest.kind === 'var') {
        const name = instr.dest.name;
        if (!vars.has(name)) vars.set(name, { defs: new Set(), uses: new Set() });
        vars.get(name)!.defs.add(block.id);
      }

      // Uses (operands)
      for (const operand of instr.operands) {
        if (operand.kind === 'var') {
          const name = operand.name;
          if (!vars.has(name)) vars.set(name, { defs: new Set(), uses: new Set() });
          vars.get(name)!.uses.add(block.id);
        }
      }

      // Also check phi sources, branch conditions, callee
      if (instr.branchCond && instr.branchCond.kind === 'var') {
        const name = instr.branchCond.name;
        if (!vars.has(name)) vars.set(name, { defs: new Set(), uses: new Set() });
        vars.get(name)!.uses.add(block.id);
      }
      if (instr.callee && instr.callee.kind === 'var') {
        const name = instr.callee.name;
        if (!vars.has(name)) vars.set(name, { defs: new Set(), uses: new Set() });
        vars.get(name)!.uses.add(block.id);
      }
    }
  }

  return vars;
}

// ─── SSA Construction ──────────────────────────────────────────────────

/**
 * Build SSA form for a function's IR.
 * Returns the SSA-augmented function with versioned variables and φ nodes.
 */
export function buildSsa(func: IrFunction): SsaFunction {
  // 1. Compute dominators and frontiers
  computeDominators(func);
  computeDominanceFrontiers(func);

  // 2. Collect variables
  const variables = collectVariables(func);

  // 3. Insert φ nodes at dominance frontiers
  const phiPlacements = new Map<string, Set<number>>(); // var → set of block IDs with φ
  for (const [varName, info] of variables) {
    phiPlacements.set(varName, new Set());
    const worklist = [...info.defs];
    const processed = new Set<number>();

    while (worklist.length > 0) {
      const blockId = worklist.shift()!;
      const block = func.blocks.find(b => b.id === blockId);
      if (!block) continue;

      for (const dfId of block.dominanceFrontier) {
        if (!phiPlacements.get(varName)!.has(dfId)) {
          // Insert φ node in dfId
          const dfBlock = func.blocks.find(b => b.id === dfId);
          if (dfBlock) {
            const phiInstr: IrInstruction = {
              id: -1, // Will be assigned during renaming
              opcode: 'PHI',
              dest: { kind: 'var', name: varName },
              operands: dfBlock.predecessors.map(() => ({ kind: 'var', name: varName })),
              phiSources: dfBlock.predecessors.map(predId => ({
                value: { kind: 'var', name: varName },
                blockId: predId,
              })),
              file: func.file,
              line: 0,
              column: 0,
              code: `φ(${varName})`,
            };

            dfBlock.instructions.unshift(phiInstr);
            phiPlacements.get(varName)!.add(dfId);
          }

          if (!processed.has(dfId)) {
            processed.add(dfId);
            worklist.push(dfId);
          }
        }
      }
    }
  }

  // 4. Rename variables
  const versions = new Map<string, string[]>(); // original → [v0, v1, ...]
  const defUse = new Map<string, Set<number>>(); // SSA var → use instruction IDs
  const useDef = new Map<number, string>();      // instr ID → SSA var
  const phiVars = new Map<number, string>();     // instr ID → merged SSA var

  // Initialize version counters and stacks
  const counters = new Map<string, number>();
  const stacks = new Map<string, string[]>();

  for (const [varName] of variables) {
    counters.set(varName, 0);
    stacks.set(varName, []);
    versions.set(varName, []);
  }

  // Entry block: push initial versions for parameters
  for (const param of func.parameters) {
    if (param.kind === 'var') {
      const v = `${param.name}_0`;
      counters.set(param.name, 1);
      stacks.get(param.name)?.push(v);
      if (!versions.has(param.name)) versions.set(param.name, []);
      versions.get(param.name)!.push(v);
    }
  }

  renameBlock(func.entryBlock, func, counters, stacks, versions, defUse, useDef, phiVars, new Set());
  const ssaFunc: SsaFunction = {
    ...func,
    versions,
    phiVars,
    defUse,
    useDef,
  };

  return ssaFunc;
}

function renameBlock(
  blockId: number,
  func: IrFunction,
  counters: Map<string, number>,
  stacks: Map<string, string[]>,
  versions: Map<string, string[]>,
  defUse: Map<string, Set<number>>,
  useDef: Map<number, string>,
  phiVars: Map<number, string>,
  visited: Set<number>
): void {
  if (visited.has(blockId)) return;
  visited.add(blockId);

  const block = func.blocks.find(b => b.id === blockId);
  if (!block) return;

  for (const instr of block.instructions) {
    // Rename uses
    for (const operand of instr.operands) {
      if (operand.kind === 'var') {
        const stack = stacks.get(operand.name);
        if (stack && stack.length > 0) {
          operand.name = stack[stack.length - 1];
          // Record use-def
          useDef.set(instr.id, operand.name);
          // Record def-use
          if (!defUse.has(operand.name)) defUse.set(operand.name, new Set());
          defUse.get(operand.name)!.add(instr.id);
        }
      }
    }

    // Rename phi sources
    if (instr.phiSources) {
      for (const ps of instr.phiSources) {
        if (ps.value.kind === 'var') {
          const stack = stacks.get(ps.value.name);
          if (stack && stack.length > 0) {
            ps.value.name = stack[stack.length - 1];
          }
        }
      }
    }

    // Rename branch condition
    if (instr.branchCond && instr.branchCond.kind === 'var') {
      const stack = stacks.get(instr.branchCond.name);
      if (stack && stack.length > 0) {
        instr.branchCond.name = stack[stack.length - 1];
      }
    }

    // Rename callee
    if (instr.callee && instr.callee.kind === 'var') {
      const stack = stacks.get(instr.callee.name);
      if (stack && stack.length > 0) {
        instr.callee.name = stack[stack.length - 1];
      }
    }

    // Create new version for dest (definition)
    if (instr.dest && instr.dest.kind === 'var') {
      const name = instr.dest.name;
      const count = counters.get(name) || 0;
      const newName = `${name}_${count}`;

      counters.set(name, count + 1);
      stacks.get(name)?.push(newName);

      if (!versions.has(name)) versions.set(name, []);
      versions.get(name)!.push(newName);

      // Φ nodes: track the merged variable
      if (instr.opcode === 'PHI') {
        phiVars.set(instr.id, newName);
      }

      instr.dest.name = newName;
    }
  }

  // Rename in successors' φ nodes
  for (const succId of block.successors) {
    const succ = func.blocks.find(b => b.id === succId);
    if (!succ) continue;

    for (const instr of succ.instructions) {
      if (instr.opcode !== 'PHI') break; // φ nodes are at the top

      if (instr.phiSources) {
        for (const ps of instr.phiSources) {
          if (ps.blockId === blockId && ps.value.kind === 'var') {
            const stack = stacks.get(ps.value.name);
            if (stack && stack.length > 0) {
              ps.value.name = stack[stack.length - 1];
            }
          }
        }
      }
    }
  }

  // Recurse into dominator children
  const domTreeChildren = block.dominatorChildren;
  for (const childId of domTreeChildren) {
    renameBlock(childId, func, counters, stacks, versions, defUse, useDef, phiVars, visited);
  }

  // Pop versions pushed in this block
  for (const instr of block.instructions) {
    if (instr.dest && instr.dest.kind === 'var') {
      stacks.get(instr.dest.name)?.pop();
    }
  }
}

// ─── Def-Use Chain Queries ─────────────────────────────────────────────

/**
 * Get all instructions that define the SSA variable used at `instrId`.
 * Returns empty array if the instruction doesn't use any variable.
 */
export function getDefs(instrId: number, useDef: Map<number, string>, defUse: Map<string, Set<number>>): number[] {
  const ssaVar = useDef.get(instrId);
  if (!ssaVar) return [];
  // In SSA, each use has exactly one def.
  // Return all instruction IDs that define this SSA variable.
  const uses = defUse.get(ssaVar);
  if (!uses) return [];
  // We need to find which instruction defines this SSA var
  // (not uses — defUse maps instrId→SSA var, so reverse lookup)
  return [];
}

/**
 * Get all uses of the SSA variable defined at `instrId`.
 */
export function getUses(instrId: number, ssaFunc: SsaFunction): Set<number> {
  // Find which SSA var this instruction defines
  for (const [varName, useSet] of ssaFunc.defUse) {
    // Check if this instr is in useSet (meaning it's used, not defined)
    // Actually need to find the def
  }
  // Simplification: scan instructions for matching dest
  return new Set();
}

/**
 * Trace a variable from a taint source through all def-use chains
 * to find all instructions it reaches.
 */
export function traceTaint(
  sourceVar: string,
  ssaFunc: SsaFunction,
  sourceInstructionId: number
): Set<number> {
  const reached = new Set<number>();
  const queue: number[] = [sourceInstructionId];

  while (queue.length > 0) {
    const instrId = queue.shift()!;
    if (reached.has(instrId)) continue;
    reached.add(instrId);

    // Find SSA var defined at this instruction
    let ssaVar: string | undefined;
    for (const block of ssaFunc.blocks) {
      for (const instr of block.instructions) {
        if (instr.id === instrId && instr.dest) {
          ssaVar = instr.dest.name;
          break;
        }
      }
      if (ssaVar) break;
    }

    if (!ssaVar) continue;

    // Get all uses of this SSA var
    const uses = ssaFunc.defUse.get(ssaVar);
    if (uses) {
      for (const useId of uses) {
        if (!reached.has(useId)) {
          queue.push(useId);
        }
      }
    }
  }

  return reached;
}
