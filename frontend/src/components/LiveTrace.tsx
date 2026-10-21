import { useEffect, useMemo, useRef, useState } from "react";
import { prefersReducedMotion } from "@/lib/motion";
import { formatNumber, formatTimestamp } from "@/lib/format";
import type { OverviewData } from "@/lib/types";

const H = 150;

type Marker = OverviewData["markers"][number];

/**
 * Seismograph-style event-rate trace. Canvas, redrawn at display rate when the window is
 * short enough to scroll (≤1h); the right edge is "now" and the line drifts left between
 * data refreshes. Alerts are ticks dropped onto the trace; hover for a tooltip, click to
 * open. With reduced motion (or a long range) it is drawn once and stays still.
 */
export function LiveTrace({
  data,
  fetchedAt,
  onOpenAlert,
}: {
  data: OverviewData | undefined;
  /** Wall-clock ms when `data` was fetched, so scrolling continues from the data end. */
  fetchedAt: number;
  onOpenAlert: (id: number) => void;
}) {
  const wrap = useRef<HTMLDivElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  const [width, setWidth] = useState(900);
  const [hover, setHover] = useState<{ m: Marker; x: number } | null>(null);
  const layout = useRef<{ x: number; y: number; m: Marker }[]>([]);

  useEffect(() => {
    const el = wrap.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => {
      if (e) setWidth(Math.max(280, Math.floor(e.contentRect.width)));
    });
    ro.observe(el);
    return () => {
      ro.disconnect();
    };
  }, []);

  const span = data ? new Date(data.end).getTime() - new Date(data.start).getTime() : 0;
  const animated = Boolean(data) && span <= 3_600_000 && !prefersReducedMotion();
  const max = useMemo(() => Math.max(1, ...(data?.buckets.map((b) => b.count) ?? [1])), [data]);
  const peak = useMemo(() => Math.max(0, ...(data?.buckets.map((b) => b.count) ?? [0])), [data]);

  useEffect(() => {
    const cv = canvas.current;
    if (!cv) return;
    const dpr = window.devicePixelRatio || 1;
    cv.width = width * dpr;
    cv.height = H * dpr;
    const ctx = cv.getContext("2d");
    if (!ctx) return;
    ctx.scale(dpr, dpr);
    let raf = 0;

    const draw = () => {
      const css = getComputedStyle(cv);
      const c = (v: string) => css.getPropertyValue(v).trim();
      const line = c("--fg-muted"),
        accent = c("--accent"),
        grid = c("--border");
      ctx.clearRect(0, 0, width, H);
      const base = H - 22;
      ctx.strokeStyle = grid;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(0, base + 0.5);
      ctx.lineTo(width, base + 0.5);
      ctx.stroke();
      layout.current = [];
      if (!data || span === 0) return;

      const t0 = new Date(data.start).getTime();
      const t1 = new Date(data.end).getTime();
      const shift = animated ? Date.now() - fetchedAt : 0; // how far "now" moved since fetch
      const xOf = (t: number) => ((t - t0 - shift) / span) * width;
      const bw = data.bucket_seconds * 1000;
      const yOf = (n: number) => base - (n / max) * (base - 14);

      const pts = data.buckets.map((b) => ({
        x: xOf(new Date(b.start).getTime() + bw / 2),
        y: yOf(b.count),
        f: b,
      }));
      if (pts.length) {
        ctx.beginPath();
        ctx.moveTo(pts[0]?.x ?? 0, base);
        pts.forEach((p, i) => {
          const prev = pts[i - 1];
          if (!prev) ctx.lineTo(p.x, p.y);
          else {
            const mx = (prev.x + p.x) / 2;
            ctx.bezierCurveTo(mx, prev.y, mx, p.y, p.x, p.y);
          }
        });
        ctx.lineTo(pts.at(-1)?.x ?? width, base);
        ctx.closePath();
        const g = ctx.createLinearGradient(0, 0, 0, base);
        g.addColorStop(0, `color-mix(in srgb, ${line} 22%, transparent)`);
        g.addColorStop(1, "transparent");
        ctx.fillStyle = g;
        ctx.fill();

        ctx.beginPath();
        pts.forEach((p, i) => {
          const prev = pts[i - 1];
          if (!prev) ctx.moveTo(p.x, p.y);
          else {
            const mx = (prev.x + p.x) / 2;
            ctx.bezierCurveTo(mx, prev.y, mx, p.y, p.x, p.y);
          }
        });
        ctx.strokeStyle = line;
        ctx.lineWidth = 1.5;
        ctx.stroke();

        // failures: the same trace again, in the accent colour
        ctx.beginPath();
        pts.forEach((p, i) => {
          const y = yOf(p.f.failures);
          const prev = pts[i - 1];
          if (!prev) ctx.moveTo(p.x, y);
          else {
            const mx = (prev.x + p.x) / 2;
            ctx.bezierCurveTo(mx, yOf(prev.f.failures), mx, y, p.x, y);
          }
        });
        ctx.strokeStyle = accent;
        ctx.globalAlpha = 0.85;
        ctx.lineWidth = 1.25;
        ctx.stroke();
        ctx.globalAlpha = 1;
      }

      // alert ticks
      for (const m of data.markers) {
        const x = xOf(new Date(m.ts).getTime());
        if (x < 0 || x > width) continue;
        const near = pts.reduce<{ y: number; d: number }>(
          (best, p) => {
            const d = Math.abs(p.x - x);
            return d < best.d ? { y: p.y, d } : best;
          },
          { y: base, d: Infinity },
        );
        ctx.strokeStyle = accent;
        ctx.lineWidth = 1;
        ctx.globalAlpha = 0.5;
        ctx.beginPath();
        ctx.moveTo(x + 0.5, 4);
        ctx.lineTo(x + 0.5, near.y);
        ctx.stroke();
        ctx.globalAlpha = 1;
        ctx.fillStyle = accent;
        ctx.beginPath();
        ctx.moveTo(x, 3);
        ctx.lineTo(x + 4.5, 11);
        ctx.lineTo(x - 4.5, 11);
        ctx.closePath();
        ctx.fill();
        layout.current.push({ x, y: 8, m });
      }

      // time labels + "now" marker
      ctx.fillStyle = c("--fg-faint");
      ctx.font = `10px ${c("--font-data") || "monospace"}`;
      ctx.textAlign = "center";
      const labels = Math.max(2, Math.min(6, Math.floor(width / 140)));
      for (let i = 0; i < labels; i++) {
        const t = t0 + shift + (span * i) / (labels - 1);
        const x = Math.min(Math.max(((t - t0 - shift) / span) * width, 28), width - 28);
        ctx.fillText(
          formatTimestamp(new Date(t).toISOString()).slice(span > 86_400_000 * 2 ? 5 : 11, 16),
          x,
          H - 6,
        );
      }
      if (animated) {
        ctx.fillStyle = accent;
        ctx.fillRect(xOf(t1 + shift) - 1, 14, 1, base - 14);
      }
    };

    if (animated) {
      const tick = () => {
        draw();
        raf = requestAnimationFrame(tick);
      };
      raf = requestAnimationFrame(tick);
    } else {
      draw();
    }
    return () => {
      cancelAnimationFrame(raf);
    };
  }, [data, fetchedAt, width, animated, max, span]);

  const find = (x: number, y: number) =>
    layout.current.find((l) => Math.abs(l.x - x) <= 7 && Math.abs(l.y - y) <= 12);

  const summary = data
    ? `Event rate over the selected range: ${formatNumber(data.events_total)} events, peak ${formatNumber(peak)} per ${String(data.bucket_seconds)} seconds, ${String(data.markers.length)} alerts.`
    : "Event rate loading";

  return (
    <div ref={wrap} className="canvas-grid relative w-full">
      <canvas
        ref={canvas}
        role="img"
        aria-label={summary}
        style={{ width, height: H }}
        className="block cursor-default"
        onPointerMove={(e) => {
          const r = e.currentTarget.getBoundingClientRect();
          const hit = find(e.clientX - r.left, e.clientY - r.top);
          setHover(hit ? { m: hit.m, x: hit.x } : null);
          e.currentTarget.style.cursor = hit ? "pointer" : "default";
        }}
        onPointerLeave={() => {
          setHover(null);
        }}
        onClick={(e) => {
          const r = e.currentTarget.getBoundingClientRect();
          const hit = find(e.clientX - r.left, e.clientY - r.top);
          if (hit) onOpenAlert(hit.m.id);
        }}
      />
      {hover ? (
        <div
          role="tooltip"
          className="pointer-events-none absolute top-6 z-10 w-60 -translate-x-1/2 rounded-sm border border-border-strong bg-surface-2 px-3 py-2 text-xs shadow-pop"
          style={{ left: Math.min(Math.max(hover.x, 130), width - 130) }}
        >
          <p className="font-medium">{hover.m.title}</p>
          <p className="mt-0.5 font-mono text-2xs text-fg-muted">
            {formatTimestamp(hover.m.ts)} · {hover.m.severity}
          </p>
        </div>
      ) : null}
    </div>
  );
}
