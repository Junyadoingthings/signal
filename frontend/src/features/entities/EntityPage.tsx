import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import { RawLog } from "@/components/RawLog";
import { Scrubber, type Range } from "@/components/Scrubber";
import { Button, Panel, SeverityBadge } from "@/components/ui";
import { api } from "@/lib/api";
import { ENTITY_LABEL, entityPath, huntQueryFor } from "@/lib/entity";
import { formatNumber, formatRelative, formatTimestamp } from "@/lib/format";
import type { EntityDetail, EntityType, Histogram, HuntResult } from "@/lib/types";
import { EntityGraph } from "./EntityGraph";

const PAGE = 50;
const DAY = 86_400_000;

export function EntityPage() {
  const { type } = useParams();
  const [params] = useSearchParams();
  const value = params.get("value") ?? "";
  const etype = type as EntityType;
  const navigate = useNavigate();
  const [selected, setSelected] = useState<string | null>(null);
  const [brush, setBrush] = useState<Range | null>(null);
  const [open, setOpen] = useState<number | null>(null);

  const detail = useQuery({
    queryKey: ["entity", etype, value],
    queryFn: () =>
      api.get<EntityDetail>(
        `/api/entities/detail?${new URLSearchParams({ type: etype, value }).toString()}`,
      ),
    enabled: Boolean(value),
    retry: false,
  });
  const d = detail.data;
  const q = huntQueryFor(etype, value);

  // Timeline domain: the entity's own lifetime (capped at a year back from last seen).
  const domain: Range | null = useMemo(() => {
    if (!d) return null;
    const end = new Date(d.entity.last_seen).getTime() + 60_000;
    const start = Math.max(new Date(d.entity.first_seen).getTime() - 60_000, end - 364 * DAY);
    return { start, end };
  }, [d]);
  const active = brush ?? domain;
  const iso = (t: number) => new Date(t).toISOString();

  const hist = useQuery({
    queryKey: ["entity", "hist", etype, value, domain?.start, domain?.end],
    queryFn: () =>
      api.get<Histogram>(
        `/api/hunt/histogram?${new URLSearchParams({ q, start: iso(domain?.start ?? 0), end: iso(domain?.end ?? 0) }).toString()}`,
      ),
    enabled: Boolean(domain),
  });
  const events = useInfiniteQuery({
    queryKey: ["entity", "events", etype, value, active?.start, active?.end],
    initialPageParam: 0,
    enabled: Boolean(active),
    queryFn: ({ pageParam }) =>
      api.get<HuntResult>(
        `/api/hunt?${new URLSearchParams({ q, start: iso(active?.start ?? 0), end: iso(active?.end ?? 0), offset: String(pageParam), limit: String(PAGE) }).toString()}`,
      ),
    getNextPageParam: (l) => (l.offset + l.limit < l.total ? l.offset + l.limit : undefined),
  });
  const rows = events.data?.pages.flatMap((p) => p.items) ?? [];
  const total = events.data?.pages[0]?.total ?? 0;

  if (detail.isError) {
    return (
      <div className="mx-auto max-w-3xl pt-10">
        <h1 className="text-xl">Nothing recorded for this {ENTITY_LABEL[etype].toLowerCase()}.</h1>
        <p className="mt-2 text-fg-muted">
          <span className="font-mono">{value}</span> hasn't appeared in any ingested event.{" "}
          <Link to="/hunt" className="underline">
            Go to Hunt
          </Link>
        </p>
      </div>
    );
  }
  const sel = d?.nodes.find((n) => n.id === selected) ?? null;
  const maxAction = Math.max(1, ...Object.values(d?.actions ?? { x: 1 }));

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-6">
      <div>
        <p className="label-caps">{ENTITY_LABEL[etype]}</p>
        <div className="mt-1 flex flex-wrap items-end justify-between gap-3">
          <h1 className="font-mono text-2xl tracking-[var(--tracking-tight)] [overflow-wrap:anywhere]">
            {value}
          </h1>
          <Link to={`/hunt?q=${encodeURIComponent(q)}`}>
            <Button>Hunt this {ENTITY_LABEL[etype].toLowerCase()}</Button>
          </Link>
        </div>
        <dl className="mt-4 grid grid-cols-2 gap-px overflow-hidden rounded-md border border-border bg-border sm:grid-cols-4">
          <Fact
            label="First seen"
            value={d ? formatTimestamp(d.entity.first_seen) : undefined}
            sub={d ? formatRelative(d.entity.first_seen) : undefined}
          />
          <Fact
            label="Last seen"
            value={d ? formatTimestamp(d.entity.last_seen) : undefined}
            sub={d ? formatRelative(d.entity.last_seen) : undefined}
          />
          <Fact label="Events" value={d ? formatNumber(d.entity.event_count) : undefined} mono />
          <Fact
            label="Open alerts"
            value={
              d ? formatNumber(d.alerts.filter((a) => a.status !== "closed").length) : undefined
            }
            mono
          />
        </dl>
      </div>

      <div className="grid gap-6 lg:grid-cols-[1fr_20rem]">
        <Panel className="canvas-grid overflow-hidden">
          <div className="flex items-center justify-between px-5 pt-4">
            <h2 className="label-caps">Relationships</h2>
            <span className="text-2xs text-fg-faint">click to focus · double-click to open</span>
          </div>
          {d ? (
            d.nodes.length > 1 ? (
              <EntityGraph
                nodes={d.nodes}
                edges={d.edges}
                selectedId={selected}
                onSelect={setSelected}
                onOpen={(n) => void navigate(entityPath(n.type, n.value))}
              />
            ) : (
              <p className="px-5 py-16 text-center text-sm text-fg-muted">
                No relationships recorded for this entity yet.
              </p>
            )
          ) : (
            <div className="skeleton m-5 h-80" />
          )}
        </Panel>

        <div className="flex flex-col gap-6">
          <Panel className="p-5">
            <h2 className="label-caps mb-3">{sel ? "Selected" : "Activity"}</h2>
            {sel ? (
              <div className="flex flex-col gap-2">
                <p className="font-mono text-sm [overflow-wrap:anywhere]">{sel.value}</p>
                <p className="text-xs text-fg-muted">
                  {ENTITY_LABEL[sel.type]} · {formatNumber(sel.event_count)} events
                </p>
                <div className="flex gap-2 pt-1">
                  <Button size="sm" onClick={() => void navigate(entityPath(sel.type, sel.value))}>
                    Open page
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() =>
                      void navigate(
                        `/hunt?q=${encodeURIComponent(huntQueryFor(sel.type, sel.value))}`,
                      )
                    }
                  >
                    Hunt
                  </Button>
                </div>
              </div>
            ) : (
              <ul className="flex flex-col gap-2">
                {Object.entries(d?.actions ?? {})
                  .slice(0, 8)
                  .map(([a, n]) => (
                    <li key={a} className="grid grid-cols-[1fr_auto] items-center gap-x-3 text-xs">
                      <span className="truncate font-mono">{a}</span>
                      <span className="font-mono text-fg-muted tabular">{formatNumber(n)}</span>
                      <span
                        aria-hidden="true"
                        className="col-span-2 h-0.5 overflow-hidden rounded-full bg-surface-3"
                      >
                        <span
                          className="block h-full bg-fg-muted"
                          style={{ width: `${String((n / maxAction) * 100)}%` }}
                        />
                      </span>
                    </li>
                  ))}
              </ul>
            )}
          </Panel>

          <Panel className="p-5">
            <h2 className="label-caps mb-3">Alerts</h2>
            {d && d.alerts.length === 0 ? (
              <p className="text-xs text-fg-muted">No alerts involve this entity.</p>
            ) : null}
            <ul className="flex flex-col gap-2">
              {(d?.alerts ?? []).slice(0, 8).map((a) => (
                <li key={a.id}>
                  <Link
                    to={`/alerts?view=all&alert=${String(a.id)}`}
                    className="flex items-start gap-2 hover:text-fg"
                  >
                    <SeverityBadge severity={a.severity} compact />
                    <span className="min-w-0 text-xs">
                      <span className="block truncate">{a.rule_title}</span>
                      <span className="text-2xs text-fg-faint">
                        {formatRelative(a.last_event_at)} · {a.status}
                      </span>
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
            {d?.incident_ids.length ? (
              <p className="mt-3 text-xs text-fg-muted">
                In incident{d.incident_ids.length > 1 ? "s" : ""}{" "}
                {d.incident_ids.map((i) => (
                  <Link
                    key={i}
                    to={`/incidents/${String(i)}`}
                    className="mr-1.5 font-mono text-accent-fg hover:underline"
                  >
                    #{i}
                  </Link>
                ))}
              </p>
            ) : null}
          </Panel>
        </div>
      </div>

      <section aria-labelledby="timeline-h" className="flex flex-col gap-3">
        <h2 id="timeline-h" className="text-md">
          Timeline
        </h2>
        {domain ? (
          <Scrubber histogram={hist.data} domain={domain} selection={brush} onSelect={setBrush} />
        ) : (
          <div className="skeleton h-20" />
        )}
        <Panel>
          <p className="border-b border-border px-4 py-2.5 text-xs text-fg-muted">
            <span className="font-mono text-fg">{formatNumber(total)}</span> events
            {brush ? " in the selected range" : ""}
          </p>
          <ul className="divide-y divide-border">
            {rows.map((e) => (
              <li key={e.id}>
                <button
                  type="button"
                  aria-expanded={open === e.id}
                  onClick={() => {
                    setOpen(open === e.id ? null : e.id);
                  }}
                  className="grid w-full grid-cols-[10.5rem_1fr_auto] items-center gap-3 px-4 py-2 text-left hover:bg-surface-2/60 max-md:grid-cols-[1fr_auto]"
                >
                  <span className="font-mono text-xs text-fg-muted max-md:hidden">
                    {formatTimestamp(e.timestamp)}
                  </span>
                  <span className="truncate font-mono text-xs text-fg-muted">
                    {[
                      e.host,
                      e.action,
                      e.user && `user=${e.user}`,
                      e.src_ip && `src=${e.src_ip}`,
                      e.process_name,
                    ]
                      .filter(Boolean)
                      .join("  ")}
                  </span>
                  <span className="text-2xs uppercase text-fg-faint">
                    {e.outcome === "unknown" ? "" : e.outcome}
                  </span>
                </button>
                {open === e.id ? (
                  <div className="border-t border-border bg-surface-2/40 px-4 py-3">
                    <RawLog raw={e.raw} />
                  </div>
                ) : null}
              </li>
            ))}
            {events.isPending ? (
              <li className="p-4">
                <div className="skeleton h-5" />
              </li>
            ) : null}
          </ul>
          {events.hasNextPage ? (
            <div className="flex justify-center border-t border-border p-3">
              <Button size="sm" onClick={() => void events.fetchNextPage()}>
                Load more
              </Button>
            </div>
          ) : null}
        </Panel>
      </section>
    </div>
  );
}

function Fact({
  label,
  value,
  sub,
  mono,
}: {
  label: string;
  value: string | undefined;
  sub?: string | undefined;
  mono?: boolean;
}) {
  return (
    <div className="flex flex-col gap-1.5 bg-surface-1 px-5 py-4">
      <dt className="label-caps">{label}</dt>
      <dd>
        {value === undefined ? (
          <span className="skeleton inline-block h-5 w-28" />
        ) : (
          <>
            <span className={mono ? "font-mono text-xl" : "font-mono text-xs"}>{value}</span>
            {sub ? <span className="block text-2xs text-fg-faint">{sub}</span> : null}
          </>
        )}
      </dd>
    </div>
  );
}
