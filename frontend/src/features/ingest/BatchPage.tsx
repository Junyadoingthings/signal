import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { clsx } from "clsx";
import { useState } from "react";
import { Link, useParams } from "react-router";
import { RawLog } from "@/components/RawLog";
import { Button, Panel } from "@/components/ui";
import { api } from "@/lib/api";
import { formatNumber, formatTimestamp } from "@/lib/format";
import type { Batch, EventRecord, Page, UnparsedRecord } from "@/lib/types";
import { batchName, FORMAT_LABEL, formatBytes } from "./formats";
import { BatchStatus } from "./IngestPage";

type Tab = "events" | "unparsed";

export function BatchPage() {
  const { id } = useParams();
  const batchId = Number(id);
  const [tab, setTab] = useState<Tab>("events");

  const batch = useQuery({
    queryKey: ["ingest", "batch", batchId],
    queryFn: () => api.get<Batch>(`/api/ingest/batches/${batchId}`),
    enabled: Number.isInteger(batchId) && batchId > 0,
    refetchInterval: (q) => {
      const s = q.state.data?.status;
      return s === "pending" || s === "running" ? 1500 : s === "live" ? 5000 : false;
    },
  });
  const b = batch.data;

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-6">
      <div>
        <Link to="/ingest" className="text-xs text-fg-muted hover:text-fg">
          ← Ingest
        </Link>
        <div className="mt-2 flex flex-wrap items-baseline justify-between gap-3">
          <h1 className="font-mono text-xl tracking-[var(--tracking-tight)]">
            {b ? batchName(b) : <span className="skeleton inline-block h-7 w-64" />}
          </h1>
          {b ? <BatchStatus batch={b} /> : null}
        </div>
        {b ? (
          <p className="mt-1 text-xs text-fg-muted">
            Batch #{b.id} · {FORMAT_LABEL[b.source_type]} ·{" "}
            {b.kind === "live" ? "live stream" : formatBytes(b.size_bytes)}
            {b.default_host ? ` · host ${b.default_host}` : ""} · received{" "}
            {formatTimestamp(b.created_at)}
          </p>
        ) : null}
      </div>

      {b?.error ? (
        <p
          role="alert"
          className="rounded-sm border border-danger/40 bg-surface-2 px-3 py-2 text-xs text-danger"
        >
          {b.error}
        </p>
      ) : null}

      <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-md border border-border bg-border sm:grid-cols-4">
        <Count label="Parsed" value={b?.parsed_count} />
        <Count
          label="Unparsed"
          value={b?.unparsed_count}
          attention={(b?.unparsed_count ?? 0) > 0}
        />
        <Count label="Duplicates skipped" value={b?.duplicate_count} />
        <div className="flex flex-col gap-2 bg-surface-1 px-5 py-4">
          <dt className="label-caps">Time assumption</dt>
          <dd className="font-mono text-xs text-fg-muted">
            {b?.tz_assumption
              ? `${b.tz_assumption}${b.year_assumption ? ` · ${b.year_assumption}` : ""}`
              : "timestamps carry their own zone"}
          </dd>
        </div>
      </dl>

      <div role="tablist" aria-label="Batch records" className="flex gap-1 border-b border-border">
        {(["events", "unparsed"] as Tab[]).map((t) => (
          <button
            key={t}
            role="tab"
            type="button"
            aria-selected={tab === t}
            onClick={() => {
              setTab(t);
            }}
            className={clsx(
              "-mb-px border-b px-3 py-2 text-sm capitalize transition-colors",
              tab === t ? "border-fg text-fg" : "border-transparent text-fg-muted hover:text-fg",
            )}
          >
            {t}
          </button>
        ))}
      </div>

      {tab === "events" ? <EventsList batchId={batchId} /> : <UnparsedList batchId={batchId} />}
    </div>
  );
}

function Count({
  label,
  value,
  attention = false,
}: {
  label: string;
  value: number | undefined;
  attention?: boolean;
}) {
  return (
    <div className="flex flex-col gap-2 bg-surface-1 px-5 py-4">
      <dt className="label-caps">{label}</dt>
      <dd
        className={clsx("font-mono text-xl leading-none", attention ? "text-accent-fg" : "text-fg")}
      >
        {value === undefined ? (
          <span className="skeleton inline-block h-6 w-12" />
        ) : (
          formatNumber(value)
        )}
      </dd>
    </div>
  );
}

function summary(e: EventRecord): string {
  const parts = [
    e.action ?? (e.event_code ? `event ${e.event_code}` : null),
    e.user ? `user=${e.user}` : null,
    e.src_ip ? `src=${e.src_ip}` : null,
    e.dst_ip ? `dst=${e.dst_ip}` : null,
    e.process_name,
    e.dns_query,
    e.url,
    e.http_status !== null ? String(e.http_status) : null,
  ].filter(Boolean);
  return parts.join("  ");
}

function EventsList({ batchId }: { batchId: number }) {
  const [open, setOpen] = useState<number | null>(null);
  const q = useInfiniteQuery({
    queryKey: ["events", "batch", batchId],
    initialPageParam: null as number | null,
    queryFn: ({ pageParam }) =>
      api.get<Page<EventRecord>>(
        `/api/events?batch_id=${batchId}&limit=100${pageParam ? `&before_id=${pageParam}` : ""}`,
      ),
    getNextPageParam: (p) => p.next_before_id,
  });
  const rows = q.data?.pages.flatMap((p) => p.items) ?? [];

  return (
    <Panel>
      {q.isPending ? (
        <div className="flex flex-col gap-2 p-4">
          {Array.from({ length: 6 }, (_, i) => (
            <div key={i} className="skeleton h-5 w-full" />
          ))}
        </div>
      ) : rows.length === 0 ? (
        <p className="px-4 py-10 text-center text-fg-muted">No events stored from this batch.</p>
      ) : (
        <ul className="divide-y divide-border">
          {rows.map((e) => (
            <li key={e.id}>
              <button
                type="button"
                aria-expanded={open === e.id}
                onClick={() => {
                  setOpen(open === e.id ? null : e.id);
                }}
                className="grid w-full grid-cols-[11rem_6rem_1fr_auto] items-center gap-3 px-4 py-2 text-left hover:bg-surface-2/60"
              >
                <span className="font-mono text-xs text-fg-muted">
                  {formatTimestamp(e.timestamp)}
                </span>
                <span className="truncate font-mono text-xs">{e.host ?? "—"}</span>
                <span className="truncate font-mono text-xs text-fg-muted">{summary(e)}</span>
                <OutcomeMark outcome={e.outcome} />
              </button>
              {open === e.id ? (
                <div className="grid gap-4 border-t border-border bg-surface-2/40 px-4 py-4 lg:grid-cols-2">
                  <div>
                    <p className="label-caps mb-2">Raw</p>
                    <RawLog raw={e.raw} className="rounded-sm border border-border bg-bg p-3" />
                  </div>
                  <div>
                    <p className="label-caps mb-2">Normalised</p>
                    <dl className="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-1 font-mono text-xs">
                      {Object.entries(e)
                        .filter(
                          ([k, v]) =>
                            !["raw", "extra", "tags", "id", "batch_id"].includes(k) && v !== null,
                        )
                        .map(([k, v]) => (
                          <div key={k} className="contents">
                            <dt className="text-fg-faint">{k}</dt>
                            <dd className="break-all">{String(v)}</dd>
                          </div>
                        ))}
                      {e.tags.length ? (
                        <div className="contents">
                          <dt className="text-fg-faint">tags</dt>
                          <dd>{e.tags.join(", ")}</dd>
                        </div>
                      ) : null}
                    </dl>
                    {Object.keys(e.extra).length ? (
                      <>
                        <p className="label-caps mt-4 mb-2">Source fields</p>
                        <RawLog
                          raw={JSON.stringify(e.extra, null, 2)}
                          className="rounded-sm border border-border bg-bg p-3"
                        />
                      </>
                    ) : null}
                  </div>
                </div>
              ) : null}
            </li>
          ))}
        </ul>
      )}
      {q.hasNextPage ? (
        <div className="flex justify-center border-t border-border p-3">
          <Button size="sm" onClick={() => void q.fetchNextPage()} disabled={q.isFetchingNextPage}>
            {q.isFetchingNextPage ? "Loading…" : "Load more"}
          </Button>
        </div>
      ) : null}
    </Panel>
  );
}

function OutcomeMark({ outcome }: { outcome: EventRecord["outcome"] }) {
  if (outcome === "unknown") return <span className="text-2xs text-fg-faint">—</span>;
  return (
    <span
      className={clsx(
        "text-2xs uppercase tracking-[var(--tracking-caps)]",
        outcome === "failure" ? "text-accent-fg" : "text-fg-muted",
      )}
    >
      {outcome}
    </span>
  );
}

function UnparsedList({ batchId }: { batchId: number }) {
  const q = useInfiniteQuery({
    queryKey: ["unparsed", batchId],
    initialPageParam: null as number | null,
    queryFn: ({ pageParam }) =>
      api.get<Page<UnparsedRecord>>(
        `/api/ingest/unparsed?batch_id=${batchId}&limit=100${pageParam ? `&before_id=${pageParam}` : ""}`,
      ),
    getNextPageParam: (p) => p.next_before_id,
  });
  const rows = q.data?.pages.flatMap((p) => p.items) ?? [];
  return (
    <Panel>
      {q.isPending ? (
        <div className="skeleton m-4 h-5" />
      ) : rows.length === 0 ? (
        <p className="px-4 py-10 text-center text-fg-muted">Every record in this batch parsed.</p>
      ) : (
        <ul className="divide-y divide-border">
          {rows.map((u) => (
            <li key={u.id} className="flex flex-col gap-1.5 px-4 py-3">
              <p className="text-xs">
                <span className="font-mono text-fg-faint">
                  {u.line_no !== null ? `line ${u.line_no}` : "record"}
                </span>
                <span className="ml-3 text-accent-fg">{u.reason}</span>
              </p>
              <RawLog raw={u.raw} className="text-fg-muted" />
            </li>
          ))}
        </ul>
      )}
      {q.hasNextPage ? (
        <div className="flex justify-center border-t border-border p-3">
          <Button size="sm" onClick={() => void q.fetchNextPage()}>
            Load more
          </Button>
        </div>
      ) : null}
    </Panel>
  );
}
