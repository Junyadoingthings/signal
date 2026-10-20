import { useQuery } from "@tanstack/react-query";
import { clsx } from "clsx";
import { PageHeader, Panel } from "@/components/ui";
import { api } from "@/lib/api";
import { formatNumber, formatRelative, formatTimestamp } from "@/lib/format";
import type { SystemStatus } from "@/lib/types";

export function OverviewPage() {
  const status = useQuery({
    queryKey: ["system", "status"],
    queryFn: () => api.get<SystemStatus>("/api/system/status"),
    refetchInterval: 15_000,
  });

  const s = status.data;
  const quiet = s !== undefined && s.alerts_open === 0;

  return (
    <div className="mx-auto max-w-6xl">
      <PageHeader title="Overview" description="Live state of everything SIGNAL has ingested." />

      <Panel className="canvas-grid relative overflow-hidden">
        <div className="flex flex-wrap items-baseline justify-between gap-3 px-5 pt-5">
          <span className="label-caps">Event rate</span>
          <span className="font-mono text-xs text-fg-faint">
            last event {s ? formatRelative(s.last_event_at) : "…"}
          </span>
        </div>
        <svg
          aria-hidden="true"
          viewBox="0 0 1000 120"
          preserveAspectRatio="none"
          className="h-32 w-full text-border-strong"
        >
          <line
            x1="0"
            y1="60"
            x2="1000"
            y2="60"
            stroke="currentColor"
            strokeWidth="1"
            vectorEffect="non-scaling-stroke"
          />
        </svg>
        <div className="px-5 pb-5">
          {status.isPending ? (
            <div className="skeleton h-4 w-64" />
          ) : status.isError ? (
            <p role="alert" className="text-danger">
              Couldn't load status.
            </p>
          ) : quiet ? (
            <p className="text-fg-muted">
              <span className="text-fg">All quiet.</span> {formatNumber(s.alerts_open)} open alerts
              {s.events_total === 0 ? " · no events ingested yet." : "."}
            </p>
          ) : (
            <p className="text-fg-muted">
              <span className="text-accent-fg">
                {formatNumber(s?.alerts_open ?? 0)} open alerts
              </span>{" "}
              need triage.
            </p>
          )}
        </div>
      </Panel>

      <dl className="mt-6 grid grid-cols-2 gap-px overflow-hidden rounded-md border border-border bg-border md:grid-cols-5">
        <Stat label="Events · 24h" value={s?.events_last_24h} />
        <Stat label="Events · total" value={s?.events_total} />
        <Stat label="Open alerts" value={s?.alerts_open} attention={(s?.alerts_open ?? 0) > 0} />
        <Stat
          label="Open incidents"
          value={s?.incidents_open}
          attention={(s?.incidents_open ?? 0) > 0}
        />
        <Stat label="Rules enabled" value={s?.rules_enabled} className="col-span-2 md:col-span-1" />
      </dl>

      <p className="mt-4 font-mono text-2xs text-fg-faint">
        last ingest {formatTimestamp(s?.last_ingest_at)} · unparsed{" "}
        {formatNumber(s?.unparsed_total ?? 0)}
      </p>
    </div>
  );
}

function Stat({
  label,
  value,
  attention = false,
  className,
}: {
  label: string;
  value: number | undefined;
  attention?: boolean;
  className?: string;
}) {
  return (
    <div className={clsx("flex flex-col gap-2 bg-surface-1 px-5 py-4", className)}>
      <dt className="label-caps">{label}</dt>
      <dd
        className={clsx(
          "font-mono text-2xl leading-none font-medium tracking-[var(--tracking-tighter)]",
          attention ? "text-accent-fg" : "text-fg",
        )}
      >
        {value === undefined ? (
          <span className="skeleton inline-block h-7 w-14 align-middle" />
        ) : (
          formatNumber(value)
        )}
      </dd>
    </div>
  );
}
