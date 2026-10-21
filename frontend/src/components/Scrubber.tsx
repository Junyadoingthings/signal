import {
  useCallback,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type PointerEvent,
} from "react";
import { formatNumber, formatTimestamp } from "@/lib/format";
import type { Histogram } from "@/lib/types";

const H = 64;
const PAD_B = 18;

export interface Range {
  start: number;
  end: number;
}

interface Props {
  histogram: Histogram | undefined;
  /** The full domain the histogram covers. */
  domain: Range;
  /** The brushed sub-range, or null for "everything". */
  selection: Range | null;
  onSelect: (r: Range | null) => void;
}

/** Brush-selectable mini histogram: drag to pick a range, double-click to clear. Bars with
 * failures show them as a lower stacked segment in the accent colour. */
export function Scrubber({ histogram, domain, selection, onSelect }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(800);
  const [drag, setDrag] = useState<{ a: number; b: number } | null>(null);

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => {
      if (e) setWidth(Math.max(240, Math.floor(e.contentRect.width)));
    });
    ro.observe(el);
    return () => {
      ro.disconnect();
    };
  }, []);

  const span = Math.max(1, domain.end - domain.start);
  const xOf = useCallback(
    (t: number) => ((t - domain.start) / span) * width,
    [domain.start, span, width],
  );
  const tOf = useCallback(
    (x: number) => domain.start + (Math.max(0, Math.min(width, x)) / width) * span,
    [domain.start, span, width],
  );

  const max = useMemo(
    () => Math.max(1, ...(histogram?.buckets.map((b) => b.count) ?? [1])),
    [histogram],
  );
  const barW = histogram ? Math.max(1, (histogram.bucket_seconds * 1000 * width) / span - 1) : 0;

  const pos = (e: PointerEvent<SVGSVGElement>) =>
    e.clientX - e.currentTarget.getBoundingClientRect().left;
  const down = (e: PointerEvent<SVGSVGElement>) => {
    e.currentTarget.setPointerCapture(e.pointerId);
    const x = pos(e);
    setDrag({ a: x, b: x });
  };
  const move = (e: PointerEvent<SVGSVGElement>) => {
    if (drag) setDrag({ a: drag.a, b: pos(e) });
  };
  const up = () => {
    if (!drag) return;
    const [lo, hi] = [Math.min(drag.a, drag.b), Math.max(drag.a, drag.b)];
    setDrag(null);
    if (hi - lo >= 4) onSelect({ start: tOf(lo), end: tOf(hi) });
  };

  const key = (e: KeyboardEvent<SVGSVGElement>) => {
    const cur = selection ?? domain;
    const w = cur.end - cur.start;
    if (e.key === "Escape") onSelect(null);
    else if (e.key === "ArrowLeft") onSelect({ start: cur.start - w / 4, end: cur.end - w / 4 });
    else if (e.key === "ArrowRight") onSelect({ start: cur.start + w / 4, end: cur.end + w / 4 });
    else if (e.key === "+" || e.key === "=")
      onSelect({ start: cur.start + w / 4, end: cur.end - w / 4 });
    else if (e.key === "-") onSelect({ start: cur.start - w / 2, end: cur.end + w / 2 });
    else return;
    e.preventDefault();
  };

  const sel = drag
    ? { x: Math.min(drag.a, drag.b), w: Math.abs(drag.b - drag.a) }
    : selection
      ? { x: xOf(selection.start), w: xOf(selection.end) - xOf(selection.start) }
      : null;

  const tickCount = Math.max(2, Math.min(7, Math.floor(width / 130)));
  const ticks = Array.from({ length: tickCount }, (_, i) => {
    const t = domain.start + (span * i) / (tickCount - 1);
    return { x: xOf(t), label: formatTimestamp(new Date(t).toISOString()).slice(5, 16) };
  });

  return (
    <div
      ref={ref}
      className="canvas-grid relative w-full rounded-md border border-border bg-surface-1"
    >
      <svg
        width={width}
        height={H + PAD_B}
        role="slider"
        tabIndex={0}
        aria-label="Time range"
        aria-valuetext={
          selection
            ? `${formatTimestamp(new Date(selection.start).toISOString())} to ${formatTimestamp(new Date(selection.end).toISOString())}`
            : "Entire range"
        }
        aria-valuenow={0}
        onPointerDown={down}
        onPointerMove={move}
        onPointerUp={up}
        onDoubleClick={() => {
          onSelect(null);
        }}
        onKeyDown={key}
        className="block cursor-crosshair touch-none select-none"
      >
        {ticks.map((t) => (
          <g key={t.x}>
            <line x1={t.x} x2={t.x} y1={0} y2={H} stroke="var(--border)" />
            <text
              x={Math.min(Math.max(t.x, 24), width - 24)}
              y={H + 13}
              textAnchor="middle"
              className="fill-[var(--fg-faint)] font-mono text-[10px]"
            >
              {t.label}
            </text>
          </g>
        ))}
        {histogram?.buckets.map((b) => {
          const h = (b.count / max) * (H - 6);
          const f = (b.failures / max) * (H - 6);
          const x = xOf(new Date(b.start).getTime());
          if (b.count === 0) return null;
          return (
            <g key={b.start}>
              <rect
                x={x}
                y={H - h}
                width={barW}
                height={Math.max(1, h - f)}
                fill="var(--fg-faint)"
                opacity={0.7}
              />
              {f > 0 ? (
                <rect x={x} y={H - f} width={barW} height={Math.max(1, f)} fill="var(--accent)" />
              ) : null}
              <title>{`${formatTimestamp(b.start)} · ${formatNumber(b.count)} events${b.failures ? ` (${formatNumber(b.failures)} failures)` : ""}`}</title>
            </g>
          );
        })}
        <line x1={0} x2={width} y1={H} y2={H} stroke="var(--border-strong)" />
        {sel ? (
          <g pointerEvents="none">
            <rect
              x={0}
              y={0}
              width={Math.max(0, sel.x)}
              height={H}
              fill="var(--bg)"
              opacity={0.6}
            />
            <rect
              x={sel.x + sel.w}
              y={0}
              width={Math.max(0, width - sel.x - sel.w)}
              height={H}
              fill="var(--bg)"
              opacity={0.6}
            />
            <rect
              x={sel.x}
              y={0}
              width={sel.w}
              height={H}
              fill="var(--accent-soft)"
              stroke="var(--accent)"
              strokeWidth={1}
            />
          </g>
        ) : null}
      </svg>
      {histogram && histogram.total === 0 ? (
        <p className="pointer-events-none absolute inset-x-0 top-5 text-center text-xs text-fg-faint">
          No events in this range
        </p>
      ) : null}
    </div>
  );
}
