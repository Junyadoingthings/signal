import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { clsx } from "clsx";
import { useMemo, useRef, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router";
import { RawLog } from "@/components/RawLog";
import { Scrubber, type Range } from "@/components/Scrubber";
import { Button, Dialog, Field, Input, Kbd, PageHeader, Panel } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { entityPath } from "@/lib/entity";
import { formatNumber, formatTimestamp } from "@/lib/format";
import { useHotkey } from "@/lib/hotkeys";
import type { EntityType, EventRecord, Histogram, HuntResult, SavedSearch } from "@/lib/types";

const PRESETS = {
  "1h": 3600,
  "24h": 86400,
  "7d": 7 * 86400,
  "30d": 30 * 86400,
  "1y": 365 * 86400,
} as const;
type Preset = keyof typeof PRESETS;
const PAGE = 100;

const EXAMPLES = [
  "outcome:failure AND src_ip:203.0.113.*",
  "process:powershell.exe cmdline:*-enc*",
  "http_status:>=400 NOT ip:10.0.0.*",
  "(action:logon OR action:ssh_login) -user:root",
];

/** Field → entity type, for turning cells into links. */
const ENTITY_FIELDS: Record<string, EntityType> = {
  host: "host",
  user: "user",
  src_ip: "ip",
  dst_ip: "ip",
  process_name: "process",
};
const PIVOT_FIELDS = [
  "host",
  "user",
  "src_ip",
  "dst_ip",
  "process_name",
  "parent_process",
  "event_code",
  "action",
  "outcome",
  "dns_query",
  "url",
  "http_status",
  "user_agent",
  "source_type",
] as const;
const PIVOT_ALIAS: Record<string, string> = {
  process_name: "process",
  parent_process: "parent",
  dns_query: "dns",
  source_type: "type",
};

function quoteIfNeeded(v: string): string {
  return /[\s"():]/.test(v) || v === ""
    ? `"${v.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`
    : v;
}

interface QueryError {
  message: string;
  pos: number | null;
  fields: string[];
}

function parseError(e: unknown): QueryError | null {
  if (e instanceof ApiError && e.code === "invalid_query") {
    const d = e.details as { pos?: number; fields?: string[] } | undefined;
    return { message: e.message, pos: d?.pos ?? null, fields: d?.fields ?? [] };
  }
  return null;
}

export function HuntPage() {
  const [params, setParams] = useSearchParams();
  const urlQ = params.get("q") ?? "";
  const preset = (params.get("range") as Preset | null) ?? "30d";
  const from = Number(params.get("from")) || null;
  const to = Number(params.get("to")) || null;
  const [draft, setDraft] = useState(urlQ);
  const [syncedQ, setSyncedQ] = useState(urlQ);
  if (syncedQ !== urlQ) {
    // URL changed (back/forward, saved search, entity link): adopt it as the draft.
    setSyncedQ(urlQ);
    setDraft(urlQ);
  }
  const inputRef = useRef<HTMLInputElement>(null);
  const [anchor, setAnchor] = useState(() => Date.now());
  const [open, setOpen] = useState<number | null>(null);

  const set = (fn: (p: URLSearchParams) => void) => {
    setParams(
      (prev) => {
        const n = new URLSearchParams(prev);
        fn(n);
        return n;
      },
      { replace: false },
    );
  };

  const domain: Range = useMemo(
    () => ({ start: anchor - PRESETS[preset] * 1000, end: anchor }),
    [anchor, preset],
  );
  const selection: Range | null = from && to ? { start: from, end: to } : null;
  const active = selection ?? domain;
  const iso = (t: number) => new Date(t).toISOString();

  const hist = useQuery({
    queryKey: ["hunt", "hist", urlQ, domain.start, domain.end],
    queryFn: () =>
      api.get<Histogram>(
        `/api/hunt/histogram?${new URLSearchParams({ q: urlQ, start: iso(domain.start), end: iso(domain.end) }).toString()}`,
      ),
    retry: false,
  });

  const results = useInfiniteQuery({
    queryKey: ["hunt", "events", urlQ, active.start, active.end],
    initialPageParam: 0,
    queryFn: ({ pageParam }) =>
      api.get<HuntResult>(
        `/api/hunt?${new URLSearchParams({ q: urlQ, start: iso(active.start), end: iso(active.end), offset: String(pageParam), limit: String(PAGE) }).toString()}`,
      ),
    getNextPageParam: (l) => (l.offset + l.limit < l.total ? l.offset + l.limit : undefined),
    retry: false,
  });
  const rows = useMemo(() => results.data?.pages.flatMap((p) => p.items) ?? [], [results.data]);
  const total = results.data?.pages[0]?.total ?? 0;
  const qerr = parseError(results.error) ?? parseError(hist.error);

  const run = (q: string) => {
    set((p) => {
      if (q.trim()) p.set("q", q.trim());
      else p.delete("q");
      p.delete("alert");
    });
    setAnchor(Date.now());
  };
  const submit = (e: FormEvent) => {
    e.preventDefault();
    run(draft);
  };
  const addTerm = (field: string, value: string) => {
    const name = PIVOT_ALIAS[field] ?? field;
    const term = `${name}:${quoteIfNeeded(value)}`;
    const next = draft.trim() ? `${draft.trim()} AND ${term}` : term;
    setDraft(next);
    run(next);
  };
  const insertField = (f: string) => {
    setDraft((d) => `${d}${d && !d.endsWith(" ") ? " " : ""}${f}:`);
    inputRef.current?.focus();
  };

  useHotkey("/", () => {
    inputRef.current?.focus();
  });

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-5">
      <PageHeader
        title="Hunt"
        description="Search every normalised event. Terms combine with AND, OR, NOT and parentheses."
        actions={
          <SavedSearches
            query={urlQ}
            preset={preset}
            onLoad={(s) => {
              set((p) => {
                if (s.query) p.set("q", s.query);
                else p.delete("q");
                p.set("range", s.time_range in PRESETS ? s.time_range : "30d");
                p.delete("from");
                p.delete("to");
              });
              setAnchor(Date.now());
            }}
          />
        }
      />

      <form onSubmit={submit} className="flex flex-col gap-2" role="search">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <label htmlFor="hunt-q" className="sr-only">
              Hunt query
            </label>
            <Input
              id="hunt-q"
              ref={inputRef}
              value={draft}
              onChange={(e) => {
                setDraft(e.target.value);
              }}
              placeholder="user:admin AND outcome:failure AND src_ip:10.0.*"
              spellCheck={false}
              autoComplete="off"
              aria-invalid={qerr ? true : undefined}
              aria-describedby={qerr ? "hunt-err" : undefined}
              maxLength={1000}
              className="h-10 pr-10 font-mono text-sm"
            />
            <Kbd className="absolute top-1/2 right-3 -translate-y-1/2">/</Kbd>
          </div>
          <Button type="submit" variant="primary" className="h-10 px-5">
            Search
          </Button>
        </div>
        {qerr ? (
          <div
            id="hunt-err"
            role="alert"
            className="rounded-sm border border-danger/40 bg-surface-1 px-3 py-2 font-mono text-xs"
          >
            <p className="text-danger">{qerr.message}</p>
            {qerr.pos !== null ? (
              <p className="mt-1 whitespace-pre text-fg-faint">
                {urlQ}
                {"\n"}
                {" ".repeat(Math.min(qerr.pos, 200))}^
              </p>
            ) : null}
            {qerr.message.startsWith("unknown field") ? (
              <p className="mt-1 text-fg-muted">Fields: {qerr.fields.join(", ")}</p>
            ) : null}
          </div>
        ) : (
          <div className="flex flex-wrap items-center gap-1.5 text-2xs text-fg-faint">
            <span>Fields:</span>
            {[
              "user",
              "host",
              "ip",
              "src_ip",
              "process",
              "cmdline",
              "action",
              "outcome",
              "dns",
              "url",
              "http_status",
              "event_code",
              "tag",
            ].map((f) => (
              <button
                key={f}
                type="button"
                onClick={() => {
                  insertField(f);
                }}
                className="rounded-xs border border-border px-1.5 py-0.5 font-mono hover:border-border-strong hover:text-fg"
              >
                {f}
              </button>
            ))}
            <span className="ml-2">
              <code>*</code> wildcard · <code>&gt;=</code> numbers · <code>-</code> or NOT negates ·
              bare words search the raw log
            </span>
          </div>
        )}
      </form>

      {!urlQ && rows.length >= 0 && !qerr ? (
        <p className="text-xs text-fg-faint">
          Try:{" "}
          {EXAMPLES.map((ex, i) => (
            <button
              key={ex}
              type="button"
              onClick={() => {
                setDraft(ex);
                run(ex);
              }}
              className="mr-3 font-mono text-fg-muted underline-offset-4 hover:text-fg hover:underline"
            >
              {ex}
              {i < EXAMPLES.length - 1 ? "" : ""}
            </button>
          ))}
        </p>
      ) : null}

      <div className="flex flex-wrap items-center gap-3">
        <div
          role="group"
          aria-label="Time range"
          className="flex rounded-sm border border-border p-0.5"
        >
          {(Object.keys(PRESETS) as Preset[]).map((p) => (
            <button
              key={p}
              type="button"
              aria-pressed={preset === p}
              onClick={() => {
                set((n) => {
                  n.set("range", p);
                  n.delete("from");
                  n.delete("to");
                });
                setAnchor(Date.now());
              }}
              className={clsx(
                "rounded-xs px-2.5 py-1 text-xs",
                preset === p ? "bg-surface-3 text-fg" : "text-fg-muted hover:text-fg",
              )}
            >
              {p === "1y" ? "1 year" : `Last ${p}`}
            </button>
          ))}
        </div>
        <span className="font-mono text-2xs text-fg-faint">
          {formatTimestamp(iso(active.start))} → {formatTimestamp(iso(active.end))}
        </span>
        {selection ? (
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              set((n) => {
                n.delete("from");
                n.delete("to");
              });
            }}
          >
            Clear selection
          </Button>
        ) : (
          <span className="text-2xs text-fg-faint">drag on the chart to narrow the range</span>
        )}
      </div>

      <Scrubber
        histogram={hist.data}
        domain={domain}
        selection={selection}
        onSelect={(r) => {
          set((n) => {
            if (r) {
              n.set("from", String(Math.round(Math.max(domain.start, r.start))));
              n.set("to", String(Math.round(Math.min(domain.end, r.end))));
            } else {
              n.delete("from");
              n.delete("to");
            }
          });
        }}
      />

      <Panel>
        <div className="flex items-center justify-between border-b border-border px-4 py-2.5">
          <p className="text-xs text-fg-muted" aria-live="polite">
            <span className="font-mono text-fg">
              {results.isPending ? "…" : formatNumber(total)}
            </span>{" "}
            events
            {rows.length < total ? ` · showing ${formatNumber(rows.length)}` : ""}
          </p>
        </div>
        {results.isPending ? (
          <div className="flex flex-col gap-2 p-4">
            {Array.from({ length: 8 }, (_, i) => (
              <div key={i} className="skeleton h-5 w-full" />
            ))}
          </div>
        ) : qerr ? null : rows.length === 0 ? (
          <p className="px-4 py-12 text-center text-fg-muted">
            No events match. Widen the time range or loosen the query.
          </p>
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
                  className="grid w-full grid-cols-[10.5rem_5.5rem_8rem_1fr_auto] items-center gap-3 px-4 py-2 text-left hover:bg-surface-2/60 max-md:grid-cols-[1fr_auto]"
                >
                  <span className="font-mono text-xs text-fg-muted max-md:hidden">
                    {formatTimestamp(e.timestamp)}
                  </span>
                  <span className="truncate font-mono text-2xs text-fg-faint max-md:hidden">
                    {e.source_type}
                  </span>
                  <span className="truncate font-mono text-xs max-md:hidden">{e.host ?? "—"}</span>
                  <span className="truncate font-mono text-xs text-fg-muted">
                    {[
                      e.action ?? (e.event_code ? `event ${e.event_code}` : null),
                      e.user && `user=${e.user}`,
                      e.src_ip && `src=${e.src_ip}`,
                      e.process_name,
                      e.dns_query,
                      e.url,
                    ]
                      .filter(Boolean)
                      .join("  ")}
                  </span>
                  <span
                    className={clsx(
                      "text-2xs uppercase tracking-[var(--tracking-caps)]",
                      e.outcome === "failure" ? "text-accent-fg" : "text-fg-faint",
                    )}
                  >
                    {e.outcome === "unknown" ? "" : e.outcome}
                  </span>
                </button>
                {open === e.id ? <EventDetail event={e} onPivot={addTerm} /> : null}
              </li>
            ))}
          </ul>
        )}
        {results.hasNextPage ? (
          <div className="flex justify-center border-t border-border p-3">
            <Button
              size="sm"
              onClick={() => void results.fetchNextPage()}
              disabled={results.isFetchingNextPage}
            >
              {results.isFetchingNextPage ? "Loading…" : `Load ${String(PAGE)} more`}
            </Button>
          </div>
        ) : null}
      </Panel>
    </div>
  );
}

function EventDetail({
  event: e,
  onPivot,
}: {
  event: EventRecord;
  onPivot: (field: string, value: string) => void;
}) {
  const shown = PIVOT_FIELDS.filter((f) => e[f] !== null && e[f] !== "");
  return (
    <div className="grid gap-4 border-t border-border bg-surface-2/40 px-4 py-4 lg:grid-cols-2">
      <div>
        <p className="label-caps mb-2">Raw</p>
        <RawLog raw={e.raw} className="rounded-sm border border-border bg-bg p-3" />
      </div>
      <div>
        <p className="label-caps mb-2">Fields · click a value to filter on it</p>
        <dl className="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-1 font-mono text-xs">
          {shown.map((f) => {
            const v = String(e[f]);
            const et = ENTITY_FIELDS[f];
            return (
              <div key={f} className="contents">
                <dt className="text-fg-faint">{f}</dt>
                <dd className="flex items-start gap-2 [overflow-wrap:anywhere]">
                  <button
                    type="button"
                    title={`Add ${f}:${v} to the query`}
                    onClick={() => {
                      onPivot(f, v);
                    }}
                    className="text-left underline-offset-4 hover:text-accent-fg hover:underline"
                  >
                    {v}
                  </button>
                  {et ? (
                    <Link
                      to={entityPath(et, v)}
                      className="shrink-0 text-2xs text-fg-faint hover:text-fg"
                      aria-label={`Open ${f} ${v}`}
                    >
                      page →
                    </Link>
                  ) : null}
                </dd>
              </div>
            );
          })}
        </dl>
      </div>
    </div>
  );
}

function SavedSearches({
  query,
  preset,
  onLoad,
}: {
  query: string;
  preset: Preset;
  onLoad: (s: SavedSearch) => void;
}) {
  const qc = useQueryClient();
  const [menu, setMenu] = useState(false);
  const [saving, setSaving] = useState(false);
  const [name, setName] = useState("");
  const list = useQuery({
    queryKey: ["searches"],
    queryFn: () => api.get<SavedSearch[]>("/api/searches"),
  });
  const save = useMutation({
    mutationFn: () => api.post<SavedSearch>("/api/searches", { name, query, time_range: preset }),
    onSuccess: () => {
      setSaving(false);
      setName("");
      void qc.invalidateQueries({ queryKey: ["searches"] });
    },
  });
  const del = useMutation({
    mutationFn: (id: number) => api.delete(`/api/searches/${String(id)}`),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["searches"] }),
  });
  const items = list.data ?? [];
  return (
    <div className="relative flex gap-2">
      <Button
        onClick={() => {
          setMenu((m) => !m);
        }}
        aria-expanded={menu}
        aria-haspopup="menu"
      >
        Saved searches{items.length ? ` (${String(items.length)})` : ""}
      </Button>
      <Button
        disabled={!query.trim()}
        onClick={() => {
          setSaving(true);
        }}
      >
        Save
      </Button>
      {menu ? (
        <div
          role="menu"
          className="absolute top-full right-0 z-20 mt-1 w-80 rounded-md border border-border-strong bg-surface-1 p-1 shadow-pop"
        >
          {items.length === 0 ? (
            <p className="px-3 py-3 text-xs text-fg-muted">
              Nothing saved yet. Run a query, then Save.
            </p>
          ) : null}
          {items.map((s) => (
            <div
              key={s.id}
              role="none"
              className="group flex items-center gap-1 rounded-sm hover:bg-surface-2"
            >
              <button
                type="button"
                role="menuitem"
                onClick={() => {
                  setMenu(false);
                  onLoad(s);
                }}
                className="min-w-0 flex-1 px-3 py-2 text-left"
              >
                <span className="block truncate text-sm">{s.name}</span>
                <span className="block truncate font-mono text-2xs text-fg-faint">
                  {s.query || "(all events)"}
                </span>
              </button>
              <button
                type="button"
                aria-label={`Delete ${s.name}`}
                onClick={() => {
                  del.mutate(s.id);
                }}
                className="px-2 text-fg-faint hover:text-danger"
              >
                ×
              </button>
            </div>
          ))}
        </div>
      ) : null}
      <Dialog
        open={saving}
        onClose={() => {
          setSaving(false);
        }}
        title="Save search"
      >
        <form
          className="flex flex-col gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate();
          }}
        >
          <Field label="Name" htmlFor="ss-name">
            <Input
              id="ss-name"
              required
              maxLength={120}
              value={name}
              onChange={(e) => {
                setName(e.target.value);
              }}
            />
          </Field>
          <p className="rounded-sm border border-border bg-surface-2 px-3 py-2 font-mono text-xs text-fg-muted">
            {query}
          </p>
          <p className="text-xs text-fg-faint">
            Saved with the “{preset}” range. Only you can see it.
          </p>
          <div className="flex justify-end gap-2">
            <Button
              onClick={() => {
                setSaving(false);
              }}
            >
              Cancel
            </Button>
            <Button type="submit" variant="primary" disabled={!name.trim() || save.isPending}>
              Save
            </Button>
          </div>
        </form>
      </Dialog>
    </div>
  );
}
