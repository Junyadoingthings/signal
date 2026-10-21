import type { GraphEdge, GraphNode } from "@/lib/types";

const R1 = 150;
const R2 = 270;

/** Concentric layout: the entity in the middle, direct neighbours on a ring, their
 * neighbours on an outer ring near the parent they hang off. */
export function layout(
  nodes: GraphNode[],
  edges: GraphEdge[],
): Map<string, { x: number; y: number }> {
  const pos = new Map<string, { x: number; y: number }>();
  const center = nodes.find((n) => n.hop === 0);
  if (center) pos.set(center.id, { x: 0, y: 0 });
  const ring1 = nodes.filter((n) => n.hop === 1);
  const angle1 = new Map<string, number>();
  ring1.forEach((n, i) => {
    const a = (2 * Math.PI * i) / Math.max(1, ring1.length) - Math.PI / 2;
    angle1.set(n.id, a);
    pos.set(n.id, { x: Math.cos(a) * R1 * 1.5, y: Math.sin(a) * R1 });
  });
  const kids = new Map<string, GraphNode[]>();
  for (const n of nodes.filter((x) => x.hop === 2)) {
    const e = edges.find(
      (ed) =>
        (ed.source === n.id && angle1.has(ed.target)) ||
        (ed.target === n.id && angle1.has(ed.source)),
    );
    const parent = e ? (e.source === n.id ? e.target : e.source) : (ring1[0]?.id ?? "");
    kids.set(parent, [...(kids.get(parent) ?? []), n]);
  }
  for (const [parent, list] of kids) {
    const base = angle1.get(parent) ?? 0;
    const spread = Math.min(0.9, 0.22 * list.length);
    list.forEach((n, i) => {
      const a = base + (list.length === 1 ? 0 : -spread / 2 + (spread * i) / (list.length - 1));
      pos.set(n.id, { x: Math.cos(a) * R2 * 1.5, y: Math.sin(a) * R2 });
    });
  }
  return pos;
}
