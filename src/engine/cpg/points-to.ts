/**
 * Points-To Analysis (Andersen-style, inclusion-based)
 *
 * Determines what each variable pointer may reference.
 * Used to resolve indirect function calls, object property accesses,
 * and to eliminate false data-flow paths through unrelated objects.
 *
 * Constraint types:
 *   p = &q        — p points to q (address-of)
 *   p = q         — p includes q's points-to set (copy)
 *   p = *q        — p includes points-to of what q points to (load)
 *   *p = q        — what p points to includes q's points-to set (store)
 */

import { SsaFunction, IrInstruction, PointsToResult, PointsToSet, IrOpcode } from './ir';

export interface PointsToConstraint {
  kind: 'addr-of' | 'copy' | 'load' | 'store';
  lhs: string;  // Variable or allocation site
  rhs: string;  // Variable or allocation site
}

export class PointsToAnalyzer {
  private constraints: PointsToConstraint[] = [];
  private variables: Set<string> = new Set();
  private allocSites: Set<string> = new Set();
  /** Solver result */
  private result: PointsToResult = {
    varPointsTo: new Map(),
    allocPointsTo: new Map(),
  };

  /** Reset for a new analysis */
  reset(): void {
    this.constraints = [];
    this.variables = new Set();
    this.allocSites = new Set();
    this.result = {
      varPointsTo: new Map(),
      allocPointsTo: new Map(),
    };
  }

  /**
   * Generate points-to constraints from SSA function.
   */
  generateConstraints(ssaFunc: SsaFunction): void {
    for (const block of ssaFunc.blocks) {
      for (const instr of block.instructions) {
        this.processInstruction(instr);
      }
    }
  }

  private processInstruction(instr: IrInstruction): void {
    switch (instr.opcode) {
      case 'ASSIGN':
        if (instr.dest && instr.operands.length > 0) {
          const rhs = instr.operands[0];
          if (rhs.kind === 'var') {
            this.addConstraint('copy', instr.dest.name, rhs.name);
          }
          // Literal creates allocation site
          if (rhs.kind === 'literal') {
            const alloc = `alloc_${instr.id}`;
            this.allocSites.add(alloc);
            this.addConstraint('addr-of', instr.dest.name, alloc);
          }
        }
        break;

      case 'CALL':
        // Call site: result may point to anything the callee returns
        // Arguments flow into callee params (handled by interprocedural)
        if (instr.dest && instr.operands.length > 0) {
          // dest = callee(...args) → dest ⊇ return_alloc_{instr.id}
          const retAlloc = `ret_alloc_${instr.id}`;
          this.allocSites.add(retAlloc);
          this.addConstraint('addr-of', instr.dest.name, retAlloc);

          // args flow into call
          for (const arg of instr.operands) {
            if (arg.kind === 'var') {
              // param_{instr.id}_{idx} ⊇ arg
              const paramAlloc = `param_alloc_${instr.id}_${instr.operands.indexOf(arg)}`;
              this.allocSites.add(paramAlloc);
              this.addConstraint('copy', paramAlloc, arg.name);
            }
          }
        }
        break;

      case 'LOAD_PROP':
        // dest = obj[prop] → dest ⊇ *obj
        if (instr.dest && instr.operands.length >= 1) {
          const obj = instr.operands[0];
          if (obj.kind === 'var') {
            this.addConstraint('load', instr.dest.name, obj.name);
          }
        }
        break;

      case 'STORE_PROP':
        // obj[prop] = val → *obj ⊇ val
        if (instr.operands.length >= 2) {
          const obj = instr.operands[0];
          const val = instr.operands[1];
          if (obj.kind === 'var' && val.kind === 'var') {
            this.addConstraint('store', obj.name, val.name);
          }
        }
        break;

      case 'NEW':
        // dest = new constructor → dest ⊇ new_alloc_{instr.id}
        if (instr.dest) {
          const newAlloc = `new_alloc_${instr.id}`;
          this.allocSites.add(newAlloc);
          this.addConstraint('addr-of', instr.dest.name, newAlloc);
        }
        break;

      case 'PHI':
        // dest = φ(src1, src2, ...) → dest ⊇ src1 ∪ src2 ∪ ...
        if (instr.dest && instr.phiSources) {
          for (const ps of instr.phiSources) {
            if (ps.value.kind === 'var') {
              this.addConstraint('copy', instr.dest.name, ps.value.name);
            }
          }
        }
        break;

      case 'LITERAL':
        if (instr.dest) {
          const alloc = `alloc_${instr.id}`;
          this.allocSites.add(alloc);
          this.addConstraint('addr-of', instr.dest.name, alloc);
        }
        break;
    }
  }

  private addConstraint(kind: PointsToConstraint['kind'], lhs: string, rhs: string): void {
    this.constraints.push({ kind, lhs, rhs });
    this.variables.add(lhs);
    this.variables.add(rhs);
  }

  /**
   * Solve the points-to constraint system using worklist algorithm.
   */
  solve(): PointsToResult {
    // Initialize points-to sets
    this.result = {
      varPointsTo: new Map(),
      allocPointsTo: new Map(),
    };

    for (const v of this.variables) {
      this.result.varPointsTo.set(v, new Set());
    }
    for (const a of this.allocSites) {
      this.result.allocPointsTo.set(a, new Set());
    }

    // Build adjacency for efficient propagation
    // copy edges: src → dst    (when src's pts-to changes, update dst)
    const copyEdges = new Map<string, string[]>();  // src → [dsts...]
    const loadEdges = new Map<string, string[]>();  // src → [dsts...] (load from src)
    const storeEdges = new Map<string, string[]>();  // src → [dsts...] (store into src)

    for (const c of this.constraints) {
      switch (c.kind) {
        case 'addr-of': {
          // lhs ⊇ {rhs}
          const pts = this.result.varPointsTo.get(c.lhs) || new Set();
          pts.add(c.rhs);
          this.result.varPointsTo.set(c.lhs, pts);

          // Alloc points-to itself
          const allocPts = this.result.allocPointsTo.get(c.rhs) || new Set();
          allocPts.add(c.rhs);
          this.result.allocPointsTo.set(c.rhs, allocPts);
          break;
        }
        case 'copy': {
          // lhs ⊇ rhs
          if (!copyEdges.has(c.rhs)) copyEdges.set(c.rhs, []);
          copyEdges.get(c.rhs)!.push(c.lhs);
          break;
        }
        case 'load': {
          // lhs ⊇ *rhs  →  for each x ∈ pts(rhs), lhs ⊇ x
          if (!loadEdges.has(c.rhs)) loadEdges.set(c.rhs, []);
          loadEdges.get(c.rhs)!.push(c.lhs);
          break;
        }
        case 'store': {
          // *lhs ⊇ rhs  →  for each x ∈ pts(lhs), x ⊇ rhs
          if (!storeEdges.has(c.rhs)) storeEdges.set(c.rhs, []);
          storeEdges.get(c.rhs)!.push(c.lhs);
          break;
        }
      }
    }

    // Worklist algorithm
    const worklist: string[] = [...this.variables];

    while (worklist.length > 0) {
      const v = worklist.shift()!;
      const vPts = this.result.varPointsTo.get(v) || new Set();

      // Propagate copy edges: for each copy target u, merge v's pts into u
      for (const u of (copyEdges.get(v) || [])) {
        const uPts = this.result.varPointsTo.get(u) || new Set();
        const before = uPts.size;
        for (const a of vPts) uPts.add(a);
        if (uPts.size > before) {
          this.result.varPointsTo.set(u, uPts);
          worklist.push(u);
        }
      }

      // Propagate load edges: for each load target w, merge *v into w
      for (const w of (loadEdges.get(v) || [])) {
        const wPts = this.result.varPointsTo.get(w) || new Set();
        const before = wPts.size;
        for (const a of vPts) {
          const aPts = this.result.allocPointsTo.get(a) || new Set();
          for (const x of aPts) wPts.add(x);
        }
        if (wPts.size > before) {
          this.result.varPointsTo.set(w, wPts);
          worklist.push(w);
        }
      }

      // Propagate store edges: for each store target x, if v ⊇ y, then merge y into *x
      for (const x of (storeEdges.get(v) || [])) {
        const xPts = this.result.varPointsTo.get(x) || new Set();
        const before = new Set<number>();
        for (const a of xPts) before.add(a as any);

        for (const a of xPts) {
          const aPts = this.result.allocPointsTo.get(a) || new Set();
          for (const y of vPts) aPts.add(y);
          if (aPts.size > before.size) {
            this.result.allocPointsTo.set(a, aPts);
            worklist.push(a);
          }
        }
      }
    }

    return this.result;
  }

  /**
   * Run full analysis on SSA function.
   */
  analyze(ssaFunc: SsaFunction): PointsToResult {
    this.reset();
    this.generateConstraints(ssaFunc);
    return this.solve();
  }

  /**
   * Get points-to set for a variable name.
   */
  getPointsTo(varName: string): PointsToSet {
    return this.result.varPointsTo.get(varName) || new Set();
  }

  /**
   * Check if two variables may alias (their points-to sets intersect).
   */
  mayAlias(var1: string, var2: string): boolean {
    const pts1 = this.getPointsTo(var1);
    const pts2 = this.getPointsTo(var2);
    for (const a of pts1) {
      if (pts2.has(a)) return true;
    }
    return false;
  }
}

// ─── Singleton ─────────────────────────────────────────────────────────

let defaultAnalyzer: PointsToAnalyzer | null = null;

export function getPointsToAnalyzer(): PointsToAnalyzer {
  if (!defaultAnalyzer) {
    defaultAnalyzer = new PointsToAnalyzer();
  }
  return defaultAnalyzer;
}
