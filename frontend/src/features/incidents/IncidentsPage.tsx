import { useQuery } from "@tanstack/react-query";
import { clsx } from "clsx";
import { useState } from "react";
import { Link } from "react-router";
import { PageHeader, Panel, SeverityBadge } from "@/components/ui";
import { api } from "@/lib/api";
import { formatNumber, formatRelative } from "@/lib/format";
import type { Incident } from "@/lib/types";
import { ScoreBar, TacticChain } from "./bits";
import { useTacticNames } from "./useTacticNames";

type View = "open" | "closed" | "all";
const VIEWS: Record<View, string[]> = {
  open: ["new", "investigating"],
  closed: ["closed"],
  all: [],
};

export function IncidentsPage() {
  const [view, setView] = useState<View>("open");
  const names = useTacticNames();
  const list = useQuery({
    queryKey: ["incidents", "list", view],
    queryFn: () => {
      const sp = new URLSearchParams({ limit: "200" });
      for (const s of VIEWS[view]) sp.append("status", s);
      return api.get<{ items: Incident[]; total: number }>(`/api/incidents?${sp.toString()}`);
    },
  });
  const rows = list.data?.items ?? [];

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-6">
      <PageHeader
        title="Incidents"
        description="Alerts that share a host, user or IP in a short window, scored by severity, ATT&CK breadth and kill-chain order."
        actions={
          <div
            role="tablist"
            aria-label="Status"
            className="flex rounded-sm border border-border p-0.5"
          >
            {(Object.keys(VIEWS) as View[]).map((v) => (
              <button
                key={v}
                type="button"
                role="tab"
                aria-selected={view === v}
                onClick={() => {
                  setView(v);
                }}
                className={clsx(
                  "rounded-xs px-2.5 py-1 text-xs capitalize",
                  view === v ? "bg-surface-3 text-fg" : "text-fg-muted hover:text-fg",
                )}
              >
                {v}
              </button>
            ))}
          </div>
        }
      />
      <Panel>
        {list.isPending ? (
          <div className="flex flex-col gap-3 p-5">
            {Array.from({ length: 3 }, (_, i) => (
              <div key={i} className="skeleton h-14 w-full" />
            ))}
          </div>
        ) : rows.length === 0 ? (
          <p className="px-5 py-12 text-center text-fg-muted">
            {view === "open"
              ? "No open incidents. Related alerts will be grouped here."
              : "No incidents."}
          </p>
        ) : (
          <ul className="divide-y divide-border">
            {rows.map((inc) => (
              <li key={inc.id}>
                <Link
                  to={`/incidents/${String(inc.id)}`}
                  className="grid grid-cols-1 gap-3 px-5 py-4 hover:bg-surface-2/60 md:grid-cols-[7rem_1fr_9rem_8rem] md:items-center"
                >
                  <span className="flex items-center gap-3 md:flex-col md:items-start md:gap-1.5">
                    <SeverityBadge severity={inc.severity} breathing={inc.status === "new"} />
                    <ScoreBar score={inc.score} />
                  </span>
                  <span className="flex min-w-0 flex-col gap-1.5">
                    <span className="truncate">{inc.title}</span>
                    <TacticChain tactics={inc.tactics} names={names} />
                  </span>
                  <span className="font-mono text-xs text-fg-muted">
                    {formatNumber(inc.alert_count)} alerts
                    <br />
                    {[...(inc.entities.host ?? []), ...(inc.entities.user ?? [])]
                      .slice(0, 3)
                      .join(", ")}
                  </span>
                  <span className="text-xs text-fg-muted md:text-right">
                    <span className="capitalize text-fg">{inc.status}</span>
                    <br />
                    {formatRelative(inc.last_event_at)}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}
