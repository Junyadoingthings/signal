import "@xyflow/react/dist/style.css";
import {
  Background,
  Handle,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import { clsx } from "clsx";
import { useMemo } from "react";
import { useTheme } from "@/lib/theme";
import { layout } from "./layout";
import type { EntityType, GraphEdge, GraphNode } from "@/lib/types";

const GLYPH: Record<EntityType, string> = {
  host: "H",
  user: "U",
  ip: "IP",
  process: "P",
  domain: "D",
};

interface NodeData extends Record<string, unknown> {
  node: GraphNode;
  dim: boolean;
  selected: boolean;
}

function EntityNode({ data }: NodeProps<Node<NodeData>>) {
  const { node, dim, selected } = data;
  return (
    <div
      className={clsx(
        "flex max-w-48 items-center gap-2 rounded-sm border bg-surface-2 px-2 py-1.5 transition-opacity duration-[var(--dur-base)]",
        node.hop === 0 ? "border-accent" : selected ? "border-fg" : "border-border-strong",
        dim && "opacity-20",
      )}
    >
      <Handle type="target" position={Position.Top} className={HANDLE} />
      <span className="grid size-5 shrink-0 place-items-center rounded-xs bg-surface-3 font-mono text-[9px] text-fg-muted">
        {GLYPH[node.type]}
      </span>
      <span className="truncate font-mono text-xs" title={node.value}>
        {node.value}
      </span>
      <Handle type="source" position={Position.Bottom} className={HANDLE} />
    </div>
  );
}

// Both handles sit at the node's centre so edges run straight centre-to-centre.
const HANDLE =
  "!top-1/2 !left-1/2 !size-1 !-translate-x-1/2 !-translate-y-1/2 !border-0 !bg-transparent";

const nodeTypes = { entity: EntityNode };

export function EntityGraph({
  nodes,
  edges,
  selectedId,
  onSelect,
  onOpen,
}: {
  nodes: GraphNode[];
  edges: GraphEdge[];
  selectedId: string | null;
  onSelect: (id: string | null) => void;
  onOpen: (n: GraphNode) => void;
}) {
  const { resolved } = useTheme();
  const positions = useMemo(() => layout(nodes, edges), [nodes, edges]);
  const neighbours = useMemo(() => {
    if (!selectedId) return null;
    const s = new Set([selectedId]);
    for (const e of edges) {
      if (e.source === selectedId) s.add(e.target);
      if (e.target === selectedId) s.add(e.source);
    }
    return s;
  }, [selectedId, edges]);

  const rfNodes: Node<NodeData>[] = nodes.map((n) => ({
    id: n.id,
    type: "entity",
    position: positions.get(n.id) ?? { x: 0, y: 0 },
    data: {
      node: n,
      dim: neighbours ? !neighbours.has(n.id) : false,
      selected: n.id === selectedId,
    },
    draggable: true,
  }));
  const rfEdges: Edge[] = edges.map((e, i) => {
    const hot = selectedId ? e.source === selectedId || e.target === selectedId : false;
    const dim = selectedId ? !hot : false;
    return {
      id: `${e.source}-${e.target}-${e.relation}-${String(i)}`,
      type: "straight",
      source: e.source,
      target: e.target,
      label: hot ? `${e.relation} ×${String(e.count)}` : undefined,
      style: {
        stroke: hot ? "var(--accent)" : "var(--border-strong)",
        strokeWidth: hot ? 2 : 1,
        opacity: dim ? 0.1 : hot ? 1 : 0.55,
      },
      labelStyle: { fill: "var(--fg-muted)", fontSize: 10, fontFamily: "var(--font-data)" },
      labelBgStyle: { fill: "var(--surface-1)" },
    };
  });

  return (
    <div
      className="h-[32rem] w-full"
      role="group"
      aria-label="Entity relationship graph. Use Tab to move between nodes and Enter to select."
    >
      <ReactFlow
        nodes={rfNodes}
        edges={rfEdges}
        nodeTypes={nodeTypes}
        colorMode={resolved}
        fitView
        fitViewOptions={{ padding: 0.15 }}
        minZoom={0.3}
        maxZoom={1.8}
        nodesConnectable={false}
        proOptions={{ hideAttribution: true }}
        onNodeClick={(_, n) => {
          onSelect(n.id === selectedId ? null : n.id);
        }}
        onNodeDoubleClick={(_, n) => {
          const g = nodes.find((x) => x.id === n.id);
          if (g) onOpen(g);
        }}
        onPaneClick={() => {
          onSelect(null);
        }}
      >
        <Background gap={16} size={1} color="var(--grid-dot)" />
      </ReactFlow>
    </div>
  );
}
