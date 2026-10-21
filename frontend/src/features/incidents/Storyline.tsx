import { clsx } from "clsx";
import { useLayoutEffect, useMemo, useRef, useState } from "react";
import { formatTimestamp } from "@/lib/format";
import type { AttackTactic, Severity, StoryStep } from "@/lib/types";

const LABEL_W = 156;
const LANE_H = 46;
const PAD_T = 18;
const PAD_B = 34;
const PAD_R = 28;
const MIN_W = 640;

const SEV_COLOR: Record<Severity, string> = {
  low: "var(--sev-low)",
  medium: "var(--sev-medium)",
  high: "var(--sev-high)",
  critical: "var(--sev-critical)",
};

/** Same glyph language as the severity badge: circle < diamond < triangle < square. */
function Glyph({ severity, x, y }: { severity: Severity; x: number; y: number }) {
  const fill = SEV_COLOR[severity];
  switch (severity) {
    case "low":
      return <circle cx={x} cy={y} r={5} fill="var(--surface-1)" stroke={fill} strokeWidth={2} />;
    case "medium":
      return <path d={`M${x} ${y - 7}L${x + 7} ${y}L${x} ${y + 7}L${x - 7} ${y}Z`} fill={fill} />;
    case "high":
      return <path d={`M${x} ${y - 7.5}L${x + 7.5} ${y + 6}H${x - 7.5}Z`} fill={fill} />;
    case "critical":
      return <rect x={x - 6.5} y={y - 6.5} width={13} height={13} rx={2} fill={fill} />;
  }
}

interface Node {
  step: StoryStep;
  x: number;
  y: number;
  lane: number;
}

export function Storyline({
  steps,
  tactics,
  selected,
  onSelect,
}: {
  steps: StoryStep[];
  tactics: AttackTactic[];
  selected: number | null;
  onSelect: (alertId: number) => void;
}) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(900);
  const [hover, setHover] = useState<Node | null>(null);

  useLayoutEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) => {
      if (entry) setWidth(Math.max(MIN_W, Math.floor(entry.contentRect.width)));
    });
    ro.observe(el);
    return () => {
      ro.disconnect();
    };
  }, []);

  const { lanes, nodes, ticks, height } = useMemo(() => {
    const order = new Map(tactics.map((t, i) => [t.shortname, i]));
    const names = new Map(tactics.map((t) => [t.shortname, t.name]));
    const present = [...new Set(steps.map((s) => s.tactic ?? "__none"))].sort(
      (a, b) => (order.get(a) ?? 99) - (order.get(b) ?? 99),
    );
    const laneOf = new Map(present.map((t, i) => [t, i]));
    const laneList = present.map((t) => ({
      key: t,
      name: t === "__none" ? "No tactic" : (names.get(t) ?? t),
    }));

    const times = steps.map((s) => new Date(s.time).getTime());
    const t0 = Math.min(...times);
    const t1 = Math.max(...times);
    const span = Math.max(t1 - t0, 60_000);
    const x0 = LABEL_W + 16;
    const usable = width - x0 - PAD_R;
    const xs = (t: number) => x0 + ((t - t0) / span) * usable;

    const placed: Node[] = [];
    for (const s of steps) {
      const lane = laneOf.get(s.tactic ?? "__none") ?? 0;
      let x = xs(new Date(s.time).getTime());
      // nudge nodes that would overlap on the same lane
      while (placed.some((n) => n.lane === lane && Math.abs(n.x - x) < 16)) x += 16;
      placed.push({
        step: s,
        x: Math.min(x, width - PAD_R),
        y: PAD_T + lane * LANE_H + LANE_H / 2,
        lane,
      });
    }
    const tickCount = Math.max(2, Math.min(6, Math.floor(usable / 140)));
    const tickList = Array.from({ length: tickCount }, (_, i) => {
      const t = t0 + (span * i) / (tickCount - 1);
      return { x: xs(t), label: formatTimestamp(new Date(t).toISOString()).slice(11, 16) };
    });
    return {
      lanes: laneList,
      nodes: placed,
      ticks: tickList,
      height: PAD_T + laneList.length * LANE_H + PAD_B,
    };
  }, [steps, tactics, width]);

  const path = useMemo(() => {
    if (nodes.length < 2) return "";
    const ordered = [...nodes].sort(
      (a, b) => new Date(a.step.time).getTime() - new Date(b.step.time).getTime() || a.x - b.x,
    );
    return ordered
      .map((n, i) => {
        if (i === 0) return `M${String(n.x)} ${String(n.y)}`;
        const p = ordered[i - 1];
        if (!p) return "";
        const mx = (p.x + n.x) / 2;
        return `C${String(mx)} ${String(p.y)} ${String(mx)} ${String(n.y)} ${String(n.x)} ${String(n.y)}`;
      })
      .join(" ");
  }, [nodes]);

  return (
    <div ref={wrapRef} className="relative w-full overflow-x-auto">
      <svg
        width={width}
        height={height}
        role="img"
        aria-label={`Attack storyline: ${steps.map((s) => s.title).join(", then ")}`}
        className="block"
      >
        {lanes.map((l, i) => (
          <g key={l.key}>
            <rect
              x={0}
              y={PAD_T + i * LANE_H}
              width={width}
              height={LANE_H}
              fill={i % 2 ? "transparent" : "var(--grid-dot)"}
            />
            <text
              x={12}
              y={PAD_T + i * LANE_H + LANE_H / 2}
              dominantBaseline="middle"
              className="fill-[var(--fg-muted)] text-[11px]"
            >
              {l.name}
            </text>
            <line
              x1={LABEL_W}
              x2={width - 8}
              y1={PAD_T + i * LANE_H + LANE_H / 2}
              y2={PAD_T + i * LANE_H + LANE_H / 2}
              stroke="var(--border)"
              strokeDasharray="2 4"
            />
          </g>
        ))}
        {ticks.map((t) => (
          <g key={t.x}>
            <line x1={t.x} x2={t.x} y1={PAD_T} y2={height - PAD_B + 4} stroke="var(--border)" />
            <text
              x={t.x}
              y={height - 12}
              textAnchor="middle"
              className="fill-[var(--fg-faint)] font-mono text-[10px]"
            >
              {t.label}
            </text>
          </g>
        ))}
        {path ? (
          <path
            d={path}
            fill="none"
            stroke="var(--fg-muted)"
            strokeOpacity={0.55}
            strokeWidth={1.5}
            className="story-path"
            pathLength={1}
          />
        ) : null}
        {nodes.map((n) => {
          const isSel = selected === n.step.alert_id;
          const label = `${n.step.title}, ${n.step.severity}, ${formatTimestamp(n.step.time)}`;
          return (
            <g
              key={n.step.alert_id}
              role="button"
              tabIndex={0}
              aria-label={label}
              aria-pressed={isSel}
              onClick={() => {
                onSelect(n.step.alert_id);
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  onSelect(n.step.alert_id);
                }
              }}
              onMouseEnter={() => {
                setHover(n);
              }}
              onMouseLeave={() => {
                setHover(null);
              }}
              onFocus={() => {
                setHover(n);
              }}
              onBlur={() => {
                setHover(null);
              }}
              className="cursor-pointer outline-none [&:focus-visible>circle.ring]:stroke-[var(--accent-ring)]"
            >
              <circle
                cx={n.x}
                cy={n.y}
                r={14}
                fill="transparent"
                className="ring"
                stroke={isSel ? "var(--accent)" : "transparent"}
                strokeWidth={1.5}
              />
              <Glyph severity={n.step.severity} x={n.x} y={n.y} />
            </g>
          );
        })}
      </svg>
      {hover ? (
        <div
          role="tooltip"
          className={clsx(
            "pointer-events-none absolute z-10 w-64 -translate-x-1/2 -translate-y-full rounded-sm border border-border-strong bg-surface-2 px-3 py-2 text-xs shadow-pop",
          )}
          style={{ left: hover.x, top: hover.y - 14 }}
        >
          <p className="font-medium text-fg">{hover.step.title}</p>
          <p className="mt-0.5 font-mono text-2xs text-fg-muted">
            {formatTimestamp(hover.step.time)} ·{" "}
            {hover.step.techniques.join(", ") || "no technique"}
          </p>
        </div>
      ) : null}
    </div>
  );
}
