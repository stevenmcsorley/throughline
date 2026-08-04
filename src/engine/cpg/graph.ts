/**
 * In-Memory Labeled Property Graph
 *
 * Stores CPG nodes and edges with indexes for sub-millisecond queries.
 * Designed for single-project analysis (10K–500K nodes), not Neo4j-scale.
 */

import {
  CpgNode, CpgEdge, CpgNodeType, CpgEdgeType,
  PropertyGraph,
} from './types';

let _nextId = 1;
function nextId(): string { return `n${_nextId++}`; }
function nextEdgeId(): string { return `e${_nextId++}`; }

// ─── Graph Creation ────────────────────────────────────────────────────

export function createGraph(): PropertyGraph {
  return {
    nodes: new Map(),
    edges: [],
    edgeIndex: new Map(),
    outEdges: new Map(),
    inEdges: new Map(),
    fileIndex: new Map(),
    typeIndex: new Map(),
  };
}

export function resetIdCounter(): void {
  _nextId = 1;
}

// ─── Node Operations ───────────────────────────────────────────────────

export function addNode(
  graph: PropertyGraph,
  type: CpgNodeType,
  label: string,
  file: string,
  startLine: number,
  endLine: number,
  startColumn: number,
  endColumn: number,
  code: string,
  properties: Record<string, any> = {}
): CpgNode {
  const node: CpgNode = {
    id: nextId(),
    type,
    label,
    file,
    startLine,
    endLine,
    startColumn,
    endColumn,
    code,
    properties,
  };

  graph.nodes.set(node.id, node);
  graph.outEdges.set(node.id, []);
  graph.inEdges.set(node.id, []);

  // Update file index
  if (!graph.fileIndex.has(file)) {
    graph.fileIndex.set(file, []);
  }
  graph.fileIndex.get(file)!.push(node.id);

  // Update type index
  if (!graph.typeIndex.has(type)) {
    graph.typeIndex.set(type, []);
  }
  graph.typeIndex.get(type)!.push(node.id);

  return node;
}

/** Create node from TS compiler AST node data */
export function addNodeFromAst(
  graph: PropertyGraph,
  type: CpgNodeType,
  label: string,
  file: string,
  startLine: number,
  endLine: number,
  startColumn: number,
  endColumn: number,
  code: string,
  properties: Record<string, any> = {}
): CpgNode {
  return addNode(graph, type, label, file, startLine, endLine, startColumn, endColumn, code, properties);
}

/** Get node by ID */
export function getNode(graph: PropertyGraph, id: string): CpgNode | undefined {
  return graph.nodes.get(id);
}

/** Get all nodes in a file */
export function getFileNodes(graph: PropertyGraph, file: string): CpgNode[] {
  const ids = graph.fileIndex.get(file) || [];
  return ids.map(id => graph.nodes.get(id)!).filter(Boolean);
}

/** Get all nodes of a specific type */
export function getNodesByType(graph: PropertyGraph, type: CpgNodeType): CpgNode[] {
  const ids = graph.typeIndex.get(type) || [];
  return ids.map(id => graph.nodes.get(id)!).filter(Boolean);
}

// ─── Edge Operations ───────────────────────────────────────────────────

export function addEdge(
  graph: PropertyGraph,
  type: CpgEdgeType,
  sourceId: string,
  targetId: string,
  label?: string,
  properties: Record<string, any> = {}
): CpgEdge {
  const edge: CpgEdge = {
    id: nextEdgeId(),
    type,
    sourceId,
    targetId,
    label,
    properties,
  };

  graph.edges.push(edge);
  graph.edgeIndex.set(edge.id, edge);

  // Update adjacency
  graph.outEdges.get(sourceId)?.push(edge.id);
  graph.inEdges.get(targetId)?.push(edge.id);

  return edge;
}

// ─── Graph Queries ─────────────────────────────────────────────────────

/** Get outgoing edges from a node */
export function outEdges(graph: PropertyGraph, nodeId: string, edgeType?: CpgEdgeType): { edge: CpgEdge; target: CpgNode }[] {
  const edgeIds = graph.outEdges.get(nodeId) || [];
  const results: { edge: CpgEdge; target: CpgNode }[] = [];

  for (const eid of edgeIds) {
    const edge = graph.edgeIndex.get(eid);
    if (!edge) continue;
    if (edgeType && edge.type !== edgeType) continue;
    const target = graph.nodes.get(edge.targetId);
    if (target) {
      results.push({ edge, target });
    }
  }
  return results;
}

/** Get incoming edges to a node */
export function inEdges(graph: PropertyGraph, nodeId: string, edgeType?: CpgEdgeType): { edge: CpgEdge; source: CpgNode }[] {
  const edgeIds = graph.inEdges.get(nodeId) || [];
  const results: { edge: CpgEdge; source: CpgNode }[] = [];

  for (const eid of edgeIds) {
    const edge = graph.edgeIndex.get(eid);
    if (!edge) continue;
    if (edgeType && edge.type !== edgeType) continue;
    const source = graph.nodes.get(edge.sourceId);
    if (source) {
      results.push({ edge, source });
    }
  }
  return results;
}

/** Follow edges of a specific type, returns target nodes */
export function follow(graph: PropertyGraph, nodeId: string, edgeType: CpgEdgeType): CpgNode[] {
  return outEdges(graph, nodeId, edgeType).map(e => e.target);
}

/** Follow edges backwards of a specific type, returns source nodes */
export function followReverse(graph: PropertyGraph, nodeId: string, edgeType: CpgEdgeType): CpgNode[] {
  return inEdges(graph, nodeId, edgeType).map(e => e.source);
}

// ─── Path Finding ──────────────────────────────────────────────────────

export interface PathEntry {
  node: CpgNode;
  edge: CpgEdge;
}

/**
 * Find all paths between source and sink nodes using BFS.
 * Returns up to `maxPaths` paths.
 */
export function findPaths(
  graph: PropertyGraph,
  sourceId: string,
  sinkId: string,
  allowedEdgeTypes: CpgEdgeType[],
  maxPaths: number = 10,
  maxDepth: number = 10
): PathEntry[][] {
  const paths: PathEntry[][] = [];
  const queue: { nodeId: string; path: PathEntry[] }[] = [
    { nodeId: sourceId, path: [] },
  ];
  const visited = new Set<string>();
  visited.add(sourceId);

  while (queue.length > 0 && paths.length < maxPaths) {
    const { nodeId, path } = queue.shift()!;

    if (path.length > maxDepth) continue;

    const outgoing = graph.outEdges.get(nodeId) || [];
    for (const eid of outgoing) {
      const edge = graph.edgeIndex.get(eid);
      if (!edge || !allowedEdgeTypes.includes(edge.type)) continue;

      if (edge.targetId === sinkId) {
        paths.push([...path, { node: getNode(graph, edge.targetId)!, edge }]);
        if (paths.length >= maxPaths) break;
        continue;
      }

      if (!visited.has(edge.targetId)) {
        visited.add(edge.targetId);
        const target = getNode(graph, edge.targetId);
        if (target) {
          queue.push({
            nodeId: edge.targetId,
            path: [...path, { node: target, edge }],
          });
        }
      }
    }
  }

  return paths;
}

// ─── Node Search ───────────────────────────────────────────────────────

/**
 * Find nodes matching a predicate.
 * Uses type index for efficiency if type filter is specified.
 */
export function findNodes(
  graph: PropertyGraph,
  predicate: (node: CpgNode) => boolean,
  typeFilter?: CpgNodeType
): CpgNode[] {
  const results: CpgNode[] = [];

  if (typeFilter) {
    const ids = graph.typeIndex.get(typeFilter) || [];
    for (const id of ids) {
      const node = graph.nodes.get(id);
      if (node && predicate(node)) results.push(node);
    }
  } else {
    for (const node of graph.nodes.values()) {
      if (predicate(node)) results.push(node);
    }
  }

  return results;
}

/**
 * Find nodes whose code or label matches a regex.
 */
export function findNodesByPattern(
  graph: PropertyGraph,
  pattern: RegExp,
  field: 'code' | 'label' = 'code'
): CpgNode[] {
  return findNodes(graph, node => {
    const target = field === 'code' ? node.code : node.label;
    const lastIndex = pattern.lastIndex;
    const result = pattern.test(target);
    pattern.lastIndex = lastIndex; // reset — prevent stateful regex issues
    return result;
  });
}

// ─── Graph Statistics ──────────────────────────────────────────────────

export function graphStats(graph: PropertyGraph): {
  totalNodes: number;
  totalEdges: number;
  nodeTypes: Record<string, number>;
  edgeTypes: Record<string, number>;
  files: number;
} {
  const nodeTypes: Record<string, number> = {};
  const edgeTypes: Record<string, number> = {};
  const files = new Set<string>();

  for (const node of graph.nodes.values()) {
    nodeTypes[node.type] = (nodeTypes[node.type] || 0) + 1;
    files.add(node.file);
  }

  for (const edge of graph.edges) {
    edgeTypes[edge.type] = (edgeTypes[edge.type] || 0) + 1;
  }

  return {
    totalNodes: graph.nodes.size,
    totalEdges: graph.edges.length,
    nodeTypes,
    edgeTypes,
    files: files.size,
  };
}

/** Get a DOT representation for visualization */
export function toDot(graph: PropertyGraph, title: string = 'CPG'): string {
  const lines: string[] = [`digraph "${title}" {`, '  rankdir=LR;', '  node [shape=box, style=filled, fontname="Consolas"];', ''];

  // Node colors by type
  const colors: Record<string, string> = {
    FILE: '#e0e0e0', FUNCTION: '#bbdefb', METHOD: '#90caf9',
    CLASS: '#ce93d8', BLOCK: '#f5f5f5', STATEMENT: '#ffffff',
    EXPRESSION: '#fff9c4', CALL_SITE: '#ffcc80', PARAMETER: '#a5d6a7',
    VARIABLE_DECL: '#81c784', LITERAL: '#e0e0e0', IDENTIFIER: '#b3e5fc',
    RETURN: '#ef9a9a', CONDITION: '#fff59d', ASSIGNMENT: '#c5e1a5',
    MEMBER_EXPRESSION: '#bcaaa4', UNKNOWN: '#f5f5f5',
  };

  for (const node of graph.nodes.values()) {
    const color = colors[node.type] || '#ffffff';
    const label = `${node.type}\\n${node.label.replace(/"/g, '\\"')}`;
    lines.push(`  "${node.id}" [label="${label}", fillcolor="${color}"];`);
  }

  lines.push('');

  const edgeStyles: Record<string, string> = {
    AST_CHILD: 'solid', CONTROL_FLOW: 'bold',
    TRUE_BRANCH: 'dashed,color=green', FALSE_BRANCH: 'dashed,color=red',
    DATA_FLOW: 'dotted,color=blue', CALLS: 'bold,color=orange',
    TAINT_SOURCE: 'bold,color=red', TAINT_SINK: 'bold,color=red',
    REFERENCES: 'dotted', SANITIZES: 'bold,color=green',
    DECLARES: 'dashed', HAS_PARAMETER: 'dashed',
  };

  for (const edge of graph.edges) {
    const style = edgeStyles[edge.type] || 'solid';
    const elabel = edge.label ? ` [label="${edge.label}"]` : '';
    lines.push(`  "${edge.sourceId}" -> "${edge.targetId}" [style="${style}"${elabel}];`);
  }

  lines.push('}');
  return lines.join('\n');
}
