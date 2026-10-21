import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { clsx } from "clsx";
import { useState } from "react";
import { Link, useParams } from "react-router";
import { Activity } from "@/components/Activity";
import { Button, Panel, Select, SeverityBadge } from "@/components/ui";
import { Inspector } from "@/features/alerts/Inspector";
import { STATUS_LABEL, useDirectory, VERDICT_LABEL } from "@/features/alerts/triage";
import { api, ApiError } from "@/lib/api";
import { entityPath } from "@/lib/entity";
import { formatNumber, formatRelative, formatTimestamp } from "@/lib/format";
import { useHotkey } from "@/lib/hotkeys";
import type { AlertStatus, AttackMatrix, IncidentDetail, TriagePatch, Verdict } from "@/lib/types";
import { TacticChain } from "./bits";
import { useTacticNames } from "./useTacticNames";
import { Storyline } from "./Storyline";

export function IncidentPage() {
  const { id } = useParams();
  const incidentId = Number(id);
  const qc = useQueryClient();
  const names = useTacticNames();
  const [inspect, setInspect] = useState<number | null>(null);
  const detail = useQuery({
    queryKey: ["incidents", "detail", incidentId],
    queryFn: () => api.get<IncidentDetail>(`/api/incidents/${String(incidentId)}`),
  });
  const matrix = useQuery({
    queryKey: ["attack"],
    queryFn: () => api.get<AttackMatrix>("/api/attack"),
    staleTime: 300_000,
  });
  useHotkey(
    "Escape",
    () => {
      setInspect(null);
    },
    { enabled: inspect !== null },
  );

  if (detail.isError) {
    return (
      <p className="mx-auto max-w-5xl text-fg-muted">
        Incident not found. It may have been merged into another one.{" "}
        <Link to="/incidents" className="underline">
          All incidents
        </Link>
      </p>
    );
  }
  const d = detail.data;
  const inc = d?.incident;

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-6">
      <div>
        <Link to="/incidents" className="text-xs text-fg-muted hover:text-fg">
          ← Incidents
        </Link>
        <div className="mt-3 flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-3">
              {inc ? (
                <SeverityBadge severity={inc.severity} breathing={inc.status === "new"} />
              ) : null}
              <span className="font-mono text-2xs text-fg-faint">incident #{incidentId}</span>
            </div>
            <h1 className="mt-2 text-xl leading-snug tracking-[var(--tracking-tighter)]">
              {inc?.title ?? <span className="skeleton inline-block h-7 w-96" />}
            </h1>
            {inc ? (
              <p className="mt-1.5 font-mono text-xs text-fg-muted">
                {formatTimestamp(inc.first_event_at)} →{" "}
                {formatTimestamp(inc.last_event_at).slice(11)} · {formatNumber(inc.alert_count)}{" "}
                alerts · updated {formatRelative(inc.updated_at)}
              </p>
            ) : null}
          </div>
          {inc ? (
            <div className="text-right">
              <p className="label-caps">Score</p>
              <p
                className={clsx(
                  "font-mono text-display leading-none tracking-[var(--tracking-tighter)]",
                  inc.score >= 80 ? "text-accent-fg" : "text-fg",
                )}
              >
                {inc.score}
              </p>
            </div>
          ) : null}
        </div>
      </div>

      {d && inc ? (
        <>
          <IncidentTriage
            incidentId={incidentId}
            status={inc.status}
            verdict={inc.verdict}
            assigneeId={inc.assignee_id}
            openAlerts={d.alerts.filter((a) => a.status !== "closed").length}
            onChanged={() => {
              void qc.invalidateQueries({ queryKey: ["incidents"] });
              void qc.invalidateQueries({ queryKey: ["alerts"] });
            }}
          />

          <Panel className="canvas-grid overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-3 px-5 pt-4">
              <h2 className="label-caps">Storyline</h2>
              <TacticChain tactics={inc.tactics} names={names} />
            </div>
            <div className="px-2 pt-2 pb-3">
              <Storyline
                steps={d.storyline}
                tactics={matrix.data?.tactics ?? []}
                selected={inspect}
                onSelect={setInspect}
              />
            </div>
          </Panel>

          <div className="grid gap-6 lg:grid-cols-[1fr_22rem]">
            <Panel className="overflow-x-auto">
              <h2 className="label-caps border-b border-border px-5 py-3">Alerts in time order</h2>
              <ul className="divide-y divide-border">
                {d.alerts.map((a) => (
                  <li key={a.id}>
                    <button
                      type="button"
                      onClick={() => {
                        setInspect(a.id);
                      }}
                      className={clsx(
                        "grid w-full grid-cols-[6.5rem_1fr_auto] items-center gap-3 px-5 py-2.5 text-left hover:bg-surface-2/60",
                        inspect === a.id && "bg-surface-2",
                      )}
                    >
                      <SeverityBadge severity={a.severity} />
                      <span className="min-w-0">
                        <span className="block truncate text-sm">{a.rule_title}</span>
                        <span className="block truncate font-mono text-2xs text-fg-faint">
                          {formatTimestamp(a.first_event_at).slice(11)} ·{" "}
                          {[a.host, a.user, a.src_ip].filter(Boolean).join(" · ")}
                        </span>
                      </span>
                      <span className="text-xs text-fg-muted">{STATUS_LABEL[a.status]}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </Panel>
            <Panel className="flex flex-col gap-4 p-5">
              <h2 className="label-caps">Entities</h2>
              <dl className="grid grid-cols-[5rem_1fr] gap-x-3 gap-y-1.5 text-xs">
                {(["host", "user", "src_ip"] as const).map((k) => {
                  const vals = inc.entities[k] ?? [];
                  return vals.length ? (
                    <div key={k} className="contents">
                      <dt className="text-fg-faint">{k === "src_ip" ? "source ip" : k}</dt>
                      <dd className="font-mono [overflow-wrap:anywhere]">
                        {vals.map((v, i) => (
                          <span key={v}>
                            {i > 0 ? ", " : ""}
                            <Link
                              to={entityPath(k === "src_ip" ? "ip" : k, v)}
                              className="hover:text-accent-fg hover:underline"
                            >
                              {v}
                            </Link>
                          </span>
                        ))}
                      </dd>
                    </div>
                  ) : null;
                })}
              </dl>
            </Panel>
          </div>

          <Panel className="p-5">
            <h2 className="label-caps mb-3">Investigation notes & history</h2>
            <Activity target="incidents" id={incidentId} />
          </Panel>
        </>
      ) : (
        <div className="skeleton h-96 w-full" />
      )}

      {inspect ? (
        <div className="fixed inset-y-0 right-0 z-30 w-full border-l border-border-strong shadow-pop sm:w-[34rem] inspector-in">
          <Inspector
            key={inspect}
            alertId={inspect}
            onClose={() => {
              setInspect(null);
            }}
          />
        </div>
      ) : null}
    </div>
  );
}

function IncidentTriage({
  incidentId,
  status,
  verdict,
  assigneeId,
  openAlerts,
  onChanged,
}: {
  incidentId: number;
  status: AlertStatus;
  verdict: Verdict | null;
  assigneeId: number | null;
  openAlerts: number;
  onChanged: () => void;
}) {
  const users = useDirectory();
  const [closing, setClosing] = useState(false);
  const [closeAlerts, setCloseAlerts] = useState(true);
  const mutate = useMutation({
    mutationFn: (patch: TriagePatch & { close_alerts?: boolean }) =>
      api.patch(`/api/incidents/${String(incidentId)}`, patch),
    onSuccess: () => {
      setClosing(false);
      onChanged();
    },
  });
  const error = mutate.error instanceof ApiError ? mutate.error.message : null;

  return (
    <Panel className="flex flex-col gap-3 px-5 py-3">
      <div className="flex flex-wrap items-center gap-3">
        <div
          role="radiogroup"
          aria-label="Incident status"
          className="flex rounded-sm border border-border p-0.5"
        >
          {(["new", "investigating", "closed"] as AlertStatus[]).map((s) => (
            <button
              key={s}
              type="button"
              role="radio"
              aria-checked={status === s}
              disabled={mutate.isPending}
              onClick={() => {
                if (s === "closed") setClosing(true);
                else {
                  setClosing(false);
                  mutate.mutate({ status: s });
                }
              }}
              className={clsx(
                "rounded-xs px-2.5 py-1 text-xs",
                status === s ? "bg-fg text-fg-inverse" : "text-fg-muted hover:text-fg",
              )}
            >
              {STATUS_LABEL[s]}
            </button>
          ))}
        </div>
        {verdict ? (
          <span className="text-xs text-fg-muted">
            Verdict <span className="text-fg">{VERDICT_LABEL[verdict]}</span>
          </span>
        ) : null}
        <Select
          aria-label="Incident owner"
          className="ml-auto h-7 w-44 text-xs"
          value={assigneeId ?? ""}
          onChange={(e) => {
            const v = e.target.value;
            mutate.mutate(v ? { assignee_id: Number(v) } : { unassign: true });
          }}
        >
          <option value="">No owner</option>
          {(users.data ?? []).map((u) => (
            <option key={u.id} value={u.id}>
              {u.display_name}
            </option>
          ))}
        </Select>
      </div>
      {closing ? (
        <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Close incident">
          <span className="text-xs text-fg-muted">Close as</span>
          {(Object.keys(VERDICT_LABEL) as Verdict[]).map((v) => (
            <Button
              key={v}
              size="sm"
              variant={v === "true_positive" ? "primary" : "secondary"}
              onClick={() => {
                mutate.mutate({ status: "closed", verdict: v, close_alerts: closeAlerts });
              }}
            >
              {VERDICT_LABEL[v]}
            </Button>
          ))}
          <label className="ml-2 flex items-center gap-1.5 text-xs text-fg-muted">
            <input
              type="checkbox"
              checked={closeAlerts}
              onChange={(e) => {
                setCloseAlerts(e.target.checked);
              }}
              className="accent-[var(--accent)]"
            />
            also close its {openAlerts} open alert{openAlerts === 1 ? "" : "s"}
          </label>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              setClosing(false);
            }}
          >
            Cancel
          </Button>
        </div>
      ) : null}
      {error ? (
        <p role="alert" className="text-xs text-danger">
          {error}
        </p>
      ) : null}
    </Panel>
  );
}
