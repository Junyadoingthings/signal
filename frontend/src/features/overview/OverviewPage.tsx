import { useQuery } from "@tanstack/react-query";
import { clsx } from "clsx";
import { useState } from "react";
import { Link, useNavigate } from "react-router";
import { LiveTrace } from "@/components/LiveTrace";
import { PageHeader, Panel, SeverityBadge } from "@/components/ui";
import { api } from "@/lib/api";
import { entityPath } from "@/lib/entity";
import { formatNumber, formatRelative } from "@/lib/format";
import { useTween } from "@/lib/motion";
import type { AttackMatrix, OverviewData, Severity } from "@/lib/types";

const RANGES = {
  "15m": "15 min",
  "1h": "1 hour",
  "24h": "24 hours",
  "7d": "7 days",
  "30d": "30 days",
} as const;
type Range = keyof typeof RANGES;
const SEVS: Severity[] = ["critical", "high", "medium", "low"];

function duration(sec: number): string {
  if (sec < 90) return `${String(Math.round(sec))}s`;
  if (sec < 5400) return `${String(Math.round(sec / 60))}m`;
  if (sec < 172_800) return `${(sec / 3600).toFixed(1)}h`;
  return `${(sec / 86_400).toFixed(1)}d`;
}

function Num({ n, className }: { n: number; className?: string }) {
  const shown = useTween(n);
  return <span className={clsx("tabular", className)}>{formatNumber(shown)}</span>;
}

export function OverviewPage() {
  const [range, setRange] = useState<Range>("24h");
  const navigate = useNavigate();
  const ov = useQuery({
    queryKey: ["overview", range],
    queryFn: async () => ({
      at: Date.now(),
      data: await api.get<OverviewData>(`/api/overview?range=${range}`),
    }),
    refetchInterval: range === "15m" || range === "1h" ? 8000 : 20_000,
  });
  const matrix = useQuery({
    queryKey: ["attack"],
    queryFn: () => api.get<AttackMatrix>("/api/attack"),
    staleTime: 300_000,
  });
  const d = ov.data?.data;
  const openAlerts = d ? SEVS.reduce((n, s) => n + d.open_alerts[s], 0) : 0;
  const openIncidents = d ? SEVS.reduce((n, s) => n + d.open_incidents[s], 0) : 0;
  const quiet = d !== undefined && openAlerts === 0;

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-6">
      <PageHeader
        title="Overview"
        description="Everything on this page is computed from ingested events and alerts."
        actions={
          <div
            role="group"
            aria-label="Time range"
            className="flex rounded-sm border border-border p-0.5"
          >
            {(Object.keys(RANGES) as Range[]).map((r) => (
              <button
                key={r}
                type="button"
                aria-pressed={range === r}
                onClick={() => {
                  setRange(r);
                }}
                className={clsx(
                  "rounded-xs px-2.5 py-1 text-xs",
                  range === r ? "bg-surface-3 text-fg" : "text-fg-muted hover:text-fg",
                )}
              >
                {RANGES[r]}
              </button>
            ))}
          </div>
        }
      />

      <Panel className="overflow-hidden">
        <div className="flex flex-wrap items-end justify-between gap-4 px-5 pt-5">
          <div>
            <p className="label-caps">Events · last {RANGES[range]}</p>
            <p className="mt-1.5 font-mono text-display leading-none tracking-[var(--tracking-tighter)]">
              {d ? (
                <Num n={d.events_total} />
              ) : (
                <span className="skeleton inline-block h-12 w-40" />
              )}
            </p>
          </div>
          <p className="max-w-xs text-right text-xs text-fg-muted">
            {quiet ? (
              <>
                <span className="text-fg">All quiet.</span> 0 open alerts in the last{" "}
                {RANGES[range]}.
              </>
            ) : d ? (
              <>
                <span className="text-accent-fg">{formatNumber(d.markers.length)} alerts</span>{" "}
                fired in this range. Ticks on the trace are alerts; click one to open it.
              </>
            ) : null}
          </p>
        </div>
        <LiveTrace
          data={d}
          fetchedAt={ov.data?.at ?? 0}
          onOpenAlert={(id) => void navigate(`/alerts?view=all&alert=${String(id)}`)}
        />
        {d && d.events_total === 0 ? (
          <p className="px-5 pb-4 text-xs text-fg-faint">
            No events in this range.{" "}
            <Link to="/ingest" className="text-fg underline-offset-4 hover:underline">
              Ingest logs
            </Link>{" "}
            or widen the range.
          </p>
        ) : null}
      </Panel>

      <div className="grid gap-px overflow-hidden rounded-md border border-border bg-border md:grid-cols-3">
        <SevBlock
          title="Open incidents"
          counts={d?.open_incidents}
          total={openIncidents}
          to="/incidents"
        />
        <SevBlock title="Open alerts" counts={d?.open_alerts} total={openAlerts} to="/alerts" />
        <div className="flex flex-col gap-2 bg-surface-1 px-5 py-4">
          <p className="label-caps">Mean time to close</p>
          {d ? (
            d.mttr_seconds === null ? (
              <p className="font-mono text-2xl text-fg-faint">—</p>
            ) : (
              <p className="font-mono text-2xl tracking-[var(--tracking-tighter)]">
                {duration(d.mttr_seconds)}
              </p>
            )
          ) : (
            <div className="skeleton h-8 w-20" />
          )}
          <p className="text-xs text-fg-muted">
            {d
              ? d.closed_count
                ? `${formatNumber(d.closed_count)} alerts closed · ${verdictLine(d.verdicts)}`
                : "No alerts closed in this range."
              : ""}
          </p>
        </div>
      </div>

      <AttackStrip matrix={matrix.data} fired={d?.fired_tactics} />

      <div className="grid gap-6 md:grid-cols-2">
        <Panel>
          <h2 className="label-caps border-b border-border px-5 py-3">Noisiest rules</h2>
          {d && d.noisy_rules.length === 0 ? (
            <p className="px-5 py-8 text-center text-xs text-fg-muted">No alerts in this range.</p>
          ) : null}
          <ul className="divide-y divide-border">
            {(d?.noisy_rules ?? []).map((r) => (
              <li key={r.rule_id}>
                <Link
                  to={`/rules/${r.rule_id}`}
                  className="flex items-center gap-3 px-5 py-2.5 hover:bg-surface-2/60"
                >
                  <SeverityBadge severity={r.severity} compact />
                  <span className="min-w-0 flex-1 truncate text-sm">{r.title}</span>
                  <span className="font-mono text-xs tabular text-fg-muted">
                    {formatNumber(r.count)}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </Panel>
        <Panel>
          <h2 className="label-caps border-b border-border px-5 py-3">Most targeted entities</h2>
          {d && d.top_entities.length === 0 ? (
            <p className="px-5 py-8 text-center text-xs text-fg-muted">
              No entities involved in alerts.
            </p>
          ) : null}
          <ul className="divide-y divide-border">
            {(d?.top_entities ?? []).map((e) => (
              <li key={`${e.type}:${e.value}`}>
                <Link
                  to={entityPath(e.type, e.value)}
                  className="flex items-center gap-3 px-5 py-2.5 hover:bg-surface-2/60"
                >
                  <SeverityBadge severity={e.top_severity} compact />
                  <span className="w-12 shrink-0 text-2xs uppercase tracking-[var(--tracking-caps)] text-fg-faint">
                    {e.type}
                  </span>
                  <span className="min-w-0 flex-1 truncate font-mono text-xs">{e.value}</span>
                  <span className="font-mono text-xs tabular text-fg-muted">
                    {formatNumber(e.count)}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </Panel>
      </div>
      <p className="font-mono text-2xs text-fg-faint">
        {ov.dataUpdatedAt
          ? `updated ${formatRelative(new Date(ov.dataUpdatedAt).toISOString())}`
          : ""}
      </p>
    </div>
  );
}

function verdictLine(v: Record<string, number>): string {
  const short: Record<string, string> = {
    true_positive: "TP",
    false_positive: "FP",
    benign_true_positive: "BTP",
  };
  return (
    Object.entries(v)
      .map(([k, n]) => `${String(n)} ${short[k] ?? k}`)
      .join(" · ") || "no verdicts"
  );
}

function SevBlock({
  title,
  counts,
  total,
  to,
}: {
  title: string;
  counts: Record<Severity, number> | undefined;
  total: number;
  to: string;
}) {
  return (
    <Link to={to} className="flex flex-col gap-3 bg-surface-1 px-5 py-4 hover:bg-surface-2/60">
      <p className="label-caps">{title}</p>
      <p className="font-mono text-2xl leading-none tracking-[var(--tracking-tighter)]">
        {counts ? (
          <Num n={total} className={total > 0 ? "text-accent-fg" : undefined} />
        ) : (
          <span className="skeleton inline-block h-8 w-12" />
        )}
      </p>
      <div className="flex flex-wrap gap-1.5">
        {SEVS.filter((s) => (counts?.[s] ?? 0) > 0).map((s) => (
          <span key={s} className="inline-flex items-center gap-1">
            <SeverityBadge severity={s} compact />
            <span className="font-mono text-xs text-fg-muted">{counts?.[s]}</span>
          </span>
        ))}
        {counts && total === 0 ? <span className="text-xs text-fg-faint">none open</span> : null}
      </div>
    </Link>
  );
}

/** Per tactic: how many enabled rules cover it, and how many alerts fired in range.
 * Covered-but-quiet vs. uncovered (a blind spot) look different on purpose. */
function AttackStrip({
  matrix,
  fired,
}: {
  matrix: AttackMatrix | undefined;
  fired: Record<string, number> | undefined;
}) {
  if (!matrix) return <div className="skeleton h-20 w-full" />;
  return (
    <section aria-labelledby="atk-h">
      <div className="mb-2 flex flex-wrap items-baseline justify-between gap-2">
        <h2 id="atk-h" className="label-caps">
          ATT&CK coverage · {matrix.version}
        </h2>
        <span className="flex items-center gap-3 text-2xs text-fg-faint">
          <span className="flex items-center gap-1">
            <span aria-hidden="true" className="size-2 rounded-xs bg-accent" /> fired in range
          </span>
          <span className="flex items-center gap-1">
            <span aria-hidden="true" className="size-2 rounded-xs border border-border-strong" />{" "}
            covered, quiet
          </span>
          <span className="flex items-center gap-1">
            <span
              aria-hidden="true"
              className="size-2 rounded-xs border border-dashed border-border"
            />{" "}
            blind spot
          </span>
        </span>
      </div>
      <ol className="grid grid-cols-5 gap-1.5 sm:grid-cols-8 lg:grid-cols-15">
        {matrix.tactics.map((t) => {
          const n = fired?.[t.shortname] ?? 0;
          const state = n > 0 ? "fired" : t.rule_count > 0 ? "quiet" : "gap";
          return (
            <li
              key={t.shortname}
              title={`${t.name}: ${String(t.rule_count)} rules, ${String(n)} alerts in range`}
              className={clsx(
                "flex min-h-16 flex-col justify-between rounded-sm border p-2",
                state === "fired" && "border-accent bg-accent-soft",
                state === "quiet" && "border-border-strong bg-surface-1",
                state === "gap" && "border-dashed border-border",
              )}
            >
              <span
                className={clsx(
                  "text-2xs leading-tight [overflow-wrap:anywhere]",
                  state === "gap" ? "text-fg-faint" : "text-fg-muted",
                )}
              >
                {t.name}
              </span>
              <span className="flex items-baseline justify-between font-mono">
                <span
                  className={clsx(
                    "text-md leading-none",
                    state === "fired"
                      ? "text-accent-fg"
                      : state === "gap"
                        ? "text-fg-faint"
                        : "text-fg",
                  )}
                >
                  {n > 0 ? n : t.rule_count > 0 ? "·" : "—"}
                </span>
                <span className="text-2xs text-fg-faint">
                  {t.rule_count > 0 ? `${String(t.rule_count)}r` : ""}
                </span>
              </span>
              <span className="sr-only">
                {state === "fired"
                  ? `${String(n)} alerts fired`
                  : state === "quiet"
                    ? "covered, no alerts"
                    : "no rule covers this tactic"}
              </span>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
