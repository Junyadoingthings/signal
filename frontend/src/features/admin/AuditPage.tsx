import { useInfiniteQuery } from "@tanstack/react-query";
import { Button, PageHeader, Panel } from "@/components/ui";
import { api } from "@/lib/api";
import { formatTimestamp } from "@/lib/format";
import type { AuditEntry, AuditPage as AuditPageData } from "@/lib/types";

function fmt(v: unknown): string {
  if (v === undefined || v === null) return "—";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return JSON.stringify(v);
}

function describeChange(e: AuditEntry): string {
  if (!e.before || !e.after) return "";
  const changed = Object.keys(e.after).filter(
    (k) => JSON.stringify(e.before?.[k]) !== JSON.stringify(e.after?.[k]),
  );
  return changed.map((k) => `${k}: ${fmt(e.before?.[k])} → ${fmt(e.after?.[k])}`).join(", ");
}

export function AuditPage() {
  const audit = useInfiniteQuery({
    queryKey: ["audit"],
    initialPageParam: null as number | null,
    queryFn: ({ pageParam }) =>
      api.get<AuditPageData>(`/api/audit?limit=50${pageParam ? `&before_id=${pageParam}` : ""}`),
    getNextPageParam: (last) => last.next_before_id,
  });

  const rows = audit.data?.pages.flatMap((p) => p.items) ?? [];

  return (
    <div className="mx-auto max-w-6xl">
      <PageHeader
        title="Audit log"
        description="Every login, admin change and triage action, newest first."
      />
      <Panel className="overflow-x-auto">
        <table className="w-full min-w-[48rem] text-left">
          <thead>
            <tr className="border-b border-border">
              {["Time (UTC)", "Actor", "Action", "Target", "Change", "IP"].map((h) => (
                <th key={h} scope="col" className="label-caps px-4 py-2.5 font-medium">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="font-mono text-xs">
            {audit.isPending
              ? Array.from({ length: 6 }, (_, i) => (
                  <tr key={i} className="border-b border-border">
                    <td colSpan={6} className="px-4 py-3">
                      <div className="skeleton h-4 w-full" />
                    </td>
                  </tr>
                ))
              : rows.map((e) => (
                  <tr
                    key={e.id}
                    className="border-b border-border last:border-0 hover:bg-surface-2/60"
                  >
                    <td className="px-4 py-2 whitespace-nowrap text-fg-muted">
                      {formatTimestamp(e.ts)}
                    </td>
                    <td className="px-4 py-2">{e.actor_email ?? "—"}</td>
                    <td
                      className={
                        e.action.endsWith("_failed") ? "px-4 py-2 text-accent-fg" : "px-4 py-2"
                      }
                    >
                      {e.action}
                    </td>
                    <td className="px-4 py-2 text-fg-muted">
                      {e.target_type ? `${e.target_type}#${e.target_id ?? ""}` : "—"}
                    </td>
                    <td
                      className="max-w-80 truncate px-4 py-2 text-fg-muted"
                      title={describeChange(e)}
                    >
                      {describeChange(e) || "—"}
                    </td>
                    <td className="px-4 py-2 text-fg-faint">{e.ip ?? "—"}</td>
                  </tr>
                ))}
          </tbody>
        </table>
      </Panel>
      {audit.hasNextPage ? (
        <div className="mt-4 flex justify-center">
          <Button onClick={() => void audit.fetchNextPage()} disabled={audit.isFetchingNextPage}>
            {audit.isFetchingNextPage ? "Loading…" : "Load older entries"}
          </Button>
        </div>
      ) : null}
    </div>
  );
}
