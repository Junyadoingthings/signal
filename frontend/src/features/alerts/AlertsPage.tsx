import { useInfiniteQuery } from "@tanstack/react-query";
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  useReactTable,
  type SortingState,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { clsx } from "clsx";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type PointerEvent as RPointerEvent,
} from "react";
import { Link, useSearchParams } from "react-router";
import { SearchIcon } from "@/components/icons";
import { Button, Dialog, Input, Kbd, SeverityBadge } from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { formatNumber, formatRelative, formatTimestamp } from "@/lib/format";
import { useHotkey } from "@/lib/hotkeys";
import { isFresh, useLive } from "@/lib/live";
import type { AlertList, AlertRow, Severity, TriagePatch, Verdict } from "@/lib/types";
import { Inspector } from "./Inspector";
import { STATUS_LABEL, useBulkTriage, VERDICT_LABEL } from "./triage";

const PAGE = 100;
const ROW_H = 46;
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const STATUS_VIEWS = {
  open: { label: "Open", statuses: ["new", "investigating"] },
  new: { label: "New", statuses: ["new"] },
  investigating: { label: "Investigating", statuses: ["investigating"] },
  closed: { label: "Closed", statuses: ["closed"] },
  all: { label: "All", statuses: [] },
} as const;
type View = keyof typeof STATUS_VIEWS;

const SORTABLE = new Set(["severity", "created_at", "last_event_at", "event_count"]);

function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = window.setTimeout(() => {
      setV(value);
    }, ms);
    return () => {
      window.clearTimeout(t);
    };
  }, [value, ms]);
  return v;
}

const col = createColumnHelper<AlertRow>();

export function AlertsPage() {
  const [params, setParams] = useSearchParams();
  const view = (params.get("view") as View | null) ?? "open";
  const sevs = params.getAll("sev") as Severity[];
  const sortKey = params.get("sort") ?? "created_at";
  const order = (params.get("order") as "asc" | "desc" | null) ?? "desc";
  const openId = Number(params.get("alert")) || null;
  const [qInput, setQInput] = useState(params.get("q") ?? "");
  const q = useDebounced(qInput.trim(), 250);
  const { fresh } = useLive();

  const update = useCallback(
    (fn: (p: URLSearchParams) => void) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          fn(next);
          return next;
        },
        { replace: true },
      );
    },
    [setParams],
  );

  useEffect(() => {
    update((p) => {
      if (q) p.set("q", q);
      else p.delete("q");
    });
  }, [q, update]);

  const filterKey = { view, sevs, q, sortKey, order };
  const query = useInfiniteQuery({
    queryKey: ["alerts", "queue", filterKey],
    initialPageParam: 0,
    queryFn: ({ pageParam }) => {
      const sp = new URLSearchParams({
        sort: sortKey,
        order,
        offset: String(pageParam),
        limit: String(PAGE),
      });
      for (const s of STATUS_VIEWS[view].statuses) sp.append("status", s);
      for (const s of sevs) sp.append("severity", s);
      if (q) sp.set("q", q);
      return api.get<AlertList>(`/api/alerts?${sp.toString()}`);
    },
    getNextPageParam: (last) =>
      last.offset + last.limit < last.total ? last.offset + last.limit : undefined,
  });
  const rows = useMemo(() => query.data?.pages.flatMap((p) => p.items) ?? [], [query.data]);
  const total = query.data?.pages[0]?.total ?? 0;

  // ---------------------------------------------------------------- selection & focus
  const [active, setActive] = useState(0);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const sevKey = sevs.join(",");
  useEffect(() => {
    setSelected(new Set());
    setActive(0);
  }, [view, q, sortKey, order, sevKey]);

  const open = (id: number | null) => {
    update((p) => {
      if (id) p.set("alert", String(id));
      else p.delete("alert");
    });
  };

  // ---------------------------------------------------------------- table
  const sorting: SortingState = [{ id: sortKey, desc: order === "desc" }];
  const columns = useMemo(
    () => [
      col.display({
        id: "select",
        header: () => <span className="sr-only">Select</span>,
        size: 36,
      }),
      col.accessor("severity", { header: "Severity", size: 110 }),
      col.accessor("rule_title", { header: "Alert", size: 340, enableSorting: false }),
      col.display({ id: "entity", header: "Entity", size: 220 }),
      col.accessor("event_count", { header: "Events", size: 80 }),
      col.accessor("last_event_at", { header: "Last event", size: 120 }),
      col.accessor("status", { header: "Status", size: 120, enableSorting: false }),
      col.accessor("created_at", { header: "Raised", size: 110 }),
    ],
    [],
  );
  // eslint-disable-next-line react-hooks/incompatible-library -- TanStack Table returns unstable functions; this component is not compiled by React Compiler.
  const table = useReactTable({
    data: rows,
    columns,
    getCoreRowModel: getCoreRowModel(),
    manualSorting: true,
    state: { sorting },
    onSortingChange: (updater) => {
      const next = typeof updater === "function" ? updater(sorting) : updater;
      const s = next[0];
      update((p) => {
        p.set("sort", s && SORTABLE.has(s.id) ? s.id : "created_at");
        p.set("order", s?.desc === false ? "asc" : "desc");
      });
    },
    getRowId: (r) => String(r.id),
  });
  const tableRows = table.getRowModel().rows;

  // ---------------------------------------------------------------- virtualisation
  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: tableRows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_H,
    overscan: 12,
    // Used until the scroll container is measured (and in jsdom, which has no layout).
    initialRect: { width: 1024, height: 720 },
  });
  const items = virtualizer.getVirtualItems();
  const lastIndex = items.at(-1)?.index ?? 0;
  useEffect(() => {
    if (lastIndex >= rows.length - 20 && query.hasNextPage && !query.isFetchingNextPage) {
      void query.fetchNextPage();
    }
  }, [lastIndex, rows.length, query]);

  const move = (delta: number) => {
    if (!rows.length) return;
    const next = Math.max(0, Math.min(rows.length - 1, active + delta));
    setActive(next);
    virtualizer.scrollToIndex(next, { align: "auto" });
    if (openId) open(rows[next]?.id ?? null);
  };

  // ---------------------------------------------------------------- keyboard
  const searchRef = useRef<HTMLInputElement>(null);
  const [triageOpen, setTriageOpen] = useState(false);
  const nav = { ignoreInteractive: true, enabled: !triageOpen };
  useHotkey(
    "j",
    () => {
      move(1);
    },
    nav,
  );
  useHotkey(
    "k",
    () => {
      move(-1);
    },
    nav,
  );
  useHotkey(
    "ArrowDown",
    () => {
      move(1);
    },
    nav,
  );
  useHotkey(
    "ArrowUp",
    () => {
      move(-1);
    },
    nav,
  );
  useHotkey(
    "Enter",
    () => {
      const r = rows[active];
      if (r) open(r.id);
    },
    nav,
  );
  useHotkey(
    "x",
    () => {
      const r = rows[active];
      if (!r) return;
      setSelected((s) => {
        const n = new Set(s);
        if (n.has(r.id)) n.delete(r.id);
        else n.add(r.id);
        return n;
      });
    },
    nav,
  );
  useHotkey(
    "e",
    () => {
      if (rows[active] || selected.size) setTriageOpen(true);
    },
    nav,
  );
  useHotkey("/", () => {
    searchRef.current?.focus();
  });
  useHotkey(
    "Escape",
    () => {
      if (openId) open(null);
      else if (selected.size) setSelected(new Set());
    },
    { enabled: !triageOpen },
  );

  const targetIds = selected.size ? [...selected] : rows[active] ? [rows[active].id] : [];

  // ---------------------------------------------------------------- inspector width
  const [width, setWidth] = useState(() => {
    try {
      return Number(localStorage.getItem("signal.inspector.width")) || 520;
    } catch {
      return 520;
    }
  });
  const setPersistedWidth = (w: number) => {
    const clamped = Math.max(380, Math.min(960, w));
    setWidth(clamped);
    try {
      localStorage.setItem("signal.inspector.width", String(clamped));
    } catch {
      /* per-tab only */
    }
  };
  const startDrag = (e: RPointerEvent<HTMLDivElement>) => {
    const startX = e.clientX;
    const startW = width;
    const onMove = (ev: PointerEvent) => {
      setPersistedWidth(startW + (startX - ev.clientX));
    };
    const onUp = () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
  };

  return (
    <div className="flex h-full min-h-0">
      <div className="flex min-w-0 flex-1 flex-col">
        {/* filter bar */}
        <div className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-3 sm:px-6">
          <h1 className="mr-2 text-lg tracking-[var(--tracking-tighter)]">Alerts</h1>
          <div
            role="tablist"
            aria-label="Status"
            className="flex rounded-sm border border-border p-0.5"
          >
            {(Object.keys(STATUS_VIEWS) as View[]).map((v) => (
              <button
                key={v}
                type="button"
                role="tab"
                aria-selected={view === v}
                onClick={() => {
                  update((p) => {
                    p.set("view", v);
                  });
                }}
                className={clsx(
                  "rounded-xs px-2.5 py-1 text-xs transition-colors",
                  view === v ? "bg-surface-3 text-fg" : "text-fg-muted hover:text-fg",
                )}
              >
                {STATUS_VIEWS[v].label}
              </button>
            ))}
          </div>
          <div role="group" aria-label="Severity filter" className="flex gap-1">
            {SEVERITIES.map((s) => {
              const on = sevs.includes(s);
              return (
                <button
                  key={s}
                  type="button"
                  aria-pressed={on}
                  onClick={() => {
                    update((p) => {
                      const cur = p.getAll("sev").filter((x) => x !== s);
                      p.delete("sev");
                      for (const x of on ? cur : [...cur, s]) p.append("sev", x);
                    });
                  }}
                  className={clsx(
                    "rounded-xs border",
                    on ? "border-fg" : "border-transparent opacity-70 hover:opacity-100",
                  )}
                >
                  <SeverityBadge severity={s} />
                </button>
              );
            })}
          </div>
          <label className="relative ml-auto w-full max-w-64 sm:w-64">
            <span className="sr-only">Search alerts</span>
            <SearchIcon className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-fg-faint" />
            <Input
              ref={searchRef}
              value={qInput}
              onChange={(e) => {
                setQInput(e.target.value);
              }}
              onKeyDown={(e) => {
                if (e.key === "Escape" || e.key === "Enter") e.currentTarget.blur();
              }}
              placeholder="Rule, host, user, IP"
              className="pl-8"
            />
            <Kbd className="absolute top-1/2 right-2 -translate-y-1/2">/</Kbd>
          </label>
        </div>

        {/* bulk bar */}
        {selected.size ? (
          <BulkBar
            ids={[...selected]}
            onDone={() => {
              setSelected(new Set());
            }}
            onTriage={() => {
              setTriageOpen(true);
            }}
          />
        ) : null}

        {/* table */}
        <div
          role="grid"
          aria-label="Alert queue"
          aria-rowcount={total}
          className="flex min-h-0 flex-1 flex-col"
        >
          <div role="row" className="flex shrink-0 border-b border-border px-2 sm:px-4">
            {table.getHeaderGroups()[0]?.headers.map((h) => {
              const sortable = h.column.getCanSort() && SORTABLE.has(h.column.id);
              const dir = sortKey === h.column.id ? order : null;
              return (
                <div
                  key={h.id}
                  role="columnheader"
                  aria-sort={
                    dir === "asc" ? "ascending" : dir === "desc" ? "descending" : undefined
                  }
                  style={{ width: h.getSize(), flexGrow: h.column.id === "rule_title" ? 1 : 0 }}
                  className="label-caps shrink-0 px-2 py-2.5 font-medium"
                >
                  {sortable ? (
                    <button
                      type="button"
                      onClick={h.column.getToggleSortingHandler()}
                      className="inline-flex items-center gap-1 uppercase hover:text-fg"
                    >
                      {flexRender(h.column.columnDef.header, h.getContext())}
                      <span aria-hidden="true">
                        {dir === "asc" ? "↑" : dir === "desc" ? "↓" : ""}
                      </span>
                    </button>
                  ) : (
                    flexRender(h.column.columnDef.header, h.getContext())
                  )}
                </div>
              );
            })}
          </div>

          <div ref={scrollRef} className="min-h-0 flex-1 overflow-auto">
            {query.isPending ? (
              <div className="flex flex-col">
                {Array.from({ length: 10 }, (_, i) => (
                  <div
                    key={i}
                    className="flex h-[46px] items-center gap-4 border-b border-border px-6"
                  >
                    <div className="skeleton h-4 w-20" />
                    <div className="skeleton h-4 flex-1" />
                    <div className="skeleton h-4 w-40" />
                  </div>
                ))}
              </div>
            ) : rows.length === 0 ? (
              <EmptyQueue view={view} filtered={Boolean(q) || sevs.length > 0} />
            ) : (
              <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
                {items.map((vi) => {
                  const row = tableRows[vi.index];
                  if (!row) return null;
                  const a = row.original;
                  const isActive = vi.index === active;
                  const isSel = selected.has(a.id);
                  return (
                    <div
                      key={row.id}
                      role="row"
                      aria-selected={isSel}
                      aria-rowindex={vi.index + 1}
                      data-active={isActive || undefined}
                      onClick={() => {
                        setActive(vi.index);
                        open(a.id);
                      }}
                      className={clsx(
                        "absolute inset-x-0 flex cursor-default items-center border-b border-border px-2 sm:px-4",
                        isActive ? "bg-surface-2" : "hover:bg-surface-2/50",
                        openId === a.id && "shadow-[inset_2px_0_0_var(--fg)]",
                        isFresh(fresh, a.id) && "row-fresh",
                        a.status === "closed" && "text-fg-muted",
                      )}
                      style={{ height: ROW_H, transform: `translateY(${String(vi.start)}px)` }}
                    >
                      {row.getVisibleCells().map((cell) => (
                        <div
                          key={cell.id}
                          role="gridcell"
                          style={{
                            width: cell.column.getSize(),
                            flexGrow: cell.column.id === "rule_title" ? 1 : 0,
                          }}
                          className="min-w-0 shrink-0 truncate px-2"
                        >
                          <Cell
                            id={cell.column.id}
                            a={a}
                            selected={isSel}
                            onSelect={(v) => {
                              setSelected((s) => {
                                const n = new Set(s);
                                if (v) n.add(a.id);
                                else n.delete(a.id);
                                return n;
                              });
                            }}
                          />
                        </div>
                      ))}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
          <footer className="flex shrink-0 items-center justify-between border-t border-border px-4 py-2 text-2xs text-fg-faint sm:px-6">
            <span className="tabular">
              {formatNumber(rows.length)} of {formatNumber(total)}
              {query.isFetchingNextPage ? " · loading…" : ""}
            </span>
            <span className="hidden gap-3 md:flex">
              <span>
                <Kbd>j</Kbd>/<Kbd>k</Kbd> move
              </span>
              <span>
                <Kbd>↵</Kbd> open
              </span>
              <span>
                <Kbd>x</Kbd> select
              </span>
              <span>
                <Kbd>e</Kbd> triage
              </span>
              <span>
                <Kbd>/</Kbd> search
              </span>
            </span>
          </footer>
        </div>
      </div>

      {openId ? (
        <>
          <div
            role="separator"
            aria-orientation="vertical"
            aria-label="Resize inspector"
            aria-valuenow={width}
            aria-valuemin={380}
            aria-valuemax={960}
            tabIndex={0}
            onPointerDown={startDrag}
            onKeyDown={(e) => {
              if (e.key === "ArrowLeft") setPersistedWidth(width + 24);
              if (e.key === "ArrowRight") setPersistedWidth(width - 24);
            }}
            className="hidden w-1.5 shrink-0 cursor-col-resize border-l border-border bg-bg transition-colors hover:bg-border-strong focus-visible:bg-accent lg:block"
          />
          <div
            className="inspector-in fixed inset-0 z-30 lg:static lg:z-auto lg:w-[var(--inspector-w)] lg:shrink-0"
            style={{ ["--inspector-w" as string]: `${String(width)}px` }}
          >
            <Inspector
              key={openId}
              alertId={openId}
              onClose={() => {
                open(null);
              }}
            />
          </div>
        </>
      ) : null}

      <TriageMenu
        open={triageOpen}
        ids={targetIds}
        onClose={() => {
          setTriageOpen(false);
        }}
        onDone={() => {
          setTriageOpen(false);
          setSelected(new Set());
        }}
      />
    </div>
  );
}

function Cell({
  id,
  a,
  selected,
  onSelect,
}: {
  id: string;
  a: AlertRow;
  selected: boolean;
  onSelect: (v: boolean) => void;
}) {
  switch (id) {
    case "select":
      return (
        <input
          type="checkbox"
          aria-label={`Select alert ${String(a.id)}`}
          checked={selected}
          onClick={(e) => {
            e.stopPropagation();
          }}
          onChange={(e) => {
            onSelect(e.target.checked);
          }}
          className="size-3.5 accent-[var(--accent)]"
        />
      );
    case "severity":
      return <SeverityBadge severity={a.severity} breathing={a.status === "new"} />;
    case "rule_title":
      return (
        <span className="flex min-w-0 flex-col leading-tight">
          <span className="truncate text-sm">{a.rule_title}</span>
          <span className="truncate text-2xs text-fg-faint">
            {a.tactic ?? "hunting"}
            {a.incident_id ? (
              <>
                {" · "}
                <Link
                  to={`/incidents/${String(a.incident_id)}`}
                  onClick={(e) => {
                    e.stopPropagation();
                  }}
                  className="text-accent-fg hover:underline"
                >
                  incident #{a.incident_id}
                </Link>
              </>
            ) : null}
          </span>
        </span>
      );
    case "entity":
      return (
        <span
          className="truncate font-mono text-xs"
          title={[a.host, a.user, a.src_ip].filter(Boolean).join(" · ")}
        >
          {[a.host, a.user, a.src_ip].filter(Boolean).join(" · ") || "—"}
        </span>
      );
    case "event_count":
      return <span className="font-mono text-xs tabular">{formatNumber(a.event_count)}</span>;
    case "last_event_at":
      return (
        <time
          dateTime={a.last_event_at}
          title={formatTimestamp(a.last_event_at)}
          className="text-xs text-fg-muted"
        >
          {formatRelative(a.last_event_at)}
        </time>
      );
    case "status":
      return (
        <span className="flex flex-col text-xs leading-tight">
          <span>{STATUS_LABEL[a.status]}</span>
          <span className="truncate text-2xs text-fg-faint">
            {a.assignee_name ?? (a.verdict ? a.verdict.replaceAll("_", " ") : "")}
          </span>
        </span>
      );
    case "created_at":
      return (
        <time
          dateTime={a.created_at}
          title={formatTimestamp(a.created_at)}
          className="text-xs text-fg-muted"
        >
          {formatRelative(a.created_at)}
        </time>
      );
    default:
      return null;
  }
}

function EmptyQueue({ view, filtered }: { view: View; filtered: boolean }) {
  return (
    <div className="canvas-grid relative flex h-full min-h-72 flex-col items-center justify-center gap-3 px-6 text-center">
      <svg
        aria-hidden="true"
        viewBox="0 0 600 40"
        preserveAspectRatio="none"
        className="absolute inset-x-0 top-1/2 h-10 w-full -translate-y-1/2 text-border-strong"
      >
        <line
          x1="0"
          y1="20"
          x2="600"
          y2="20"
          stroke="currentColor"
          strokeWidth="1"
          vectorEffect="non-scaling-stroke"
        />
      </svg>
      <p className="relative bg-bg px-3 text-md">
        {filtered
          ? "Nothing matches these filters."
          : view === "open"
            ? "All quiet."
            : `No ${STATUS_VIEWS[view].label.toLowerCase()} alerts.`}
      </p>
      {!filtered && view === "open" ? (
        <p className="relative bg-bg px-3 text-xs text-fg-muted">
          0 open alerts. New detections appear here as they fire.
        </p>
      ) : null}
    </div>
  );
}

function BulkBar({
  ids,
  onDone,
  onTriage,
}: {
  ids: number[];
  onDone: () => void;
  onTriage: () => void;
}) {
  const bulk = useBulkTriage();
  const { user } = useAuth();
  const run = (patch: TriagePatch) => {
    bulk.mutate({ ids, patch }, { onSuccess: onDone });
  };
  return (
    <div
      className="flex flex-wrap items-center gap-2 border-b border-border bg-surface-2 px-4 py-2 sm:px-6"
      role="toolbar"
      aria-label="Bulk actions"
    >
      <span className="text-xs">
        <span className="font-mono">{ids.length}</span> selected
      </span>
      <Button
        size="sm"
        onClick={() => {
          run({ status: "investigating" });
        }}
      >
        Investigate
      </Button>
      <Button size="sm" onClick={onTriage}>
        Close as…
      </Button>
      {user ? (
        <Button
          size="sm"
          onClick={() => {
            run({ assignee_id: user.id });
          }}
        >
          Assign to me
        </Button>
      ) : null}
      <Button size="sm" variant="ghost" onClick={onDone}>
        Clear
      </Button>
    </div>
  );
}

function TriageMenu({
  open,
  ids,
  onClose,
  onDone,
}: {
  open: boolean;
  ids: number[];
  onClose: () => void;
  onDone: () => void;
}) {
  const bulk = useBulkTriage();
  const { user } = useAuth();
  const actions: { key: string; label: string; patch: TriagePatch }[] = [
    { key: "1", label: "Start investigating", patch: { status: "investigating" } },
    ...(Object.keys(VERDICT_LABEL) as Verdict[]).map((v, i) => ({
      key: String(i + 2),
      label: `Close as ${VERDICT_LABEL[v].toLowerCase()}`,
      patch: { status: "closed" as const, verdict: v },
    })),
    ...(user ? [{ key: "5", label: "Assign to me", patch: { assignee_id: user.id } }] : []),
  ];
  const run = (patch: TriagePatch) => {
    bulk.mutate({ ids, patch }, { onSuccess: onDone });
  };
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={`Triage ${String(ids.length)} alert${ids.length === 1 ? "" : "s"}`}
    >
      <ul
        className="flex flex-col gap-1"
        onKeyDown={(e) => {
          const a = actions.find((x) => x.key === e.key);
          if (a) {
            e.preventDefault();
            run(a.patch);
          }
        }}
      >
        {actions.map((a, i) => (
          <li key={a.key}>
            <button
              type="button"
              autoFocus={i === 0}
              onClick={() => {
                run(a.patch);
              }}
              className="flex w-full items-center justify-between rounded-sm px-3 py-2 text-left text-sm hover:bg-surface-2 focus-visible:bg-surface-2"
            >
              {a.label}
              <Kbd>{a.key}</Kbd>
            </button>
          </li>
        ))}
      </ul>
    </Dialog>
  );
}
