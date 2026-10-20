import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Link, useParams } from "react-router";
import { ExternalIcon } from "@/components/icons";
import { RawLog } from "@/components/RawLog";
import { Button, Field, Input, Panel, SeverityBadge } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { formatNumber, formatRelative, formatTimestamp } from "@/lib/format";
import type { Alert, Page, RuleDetail } from "@/lib/types";
import { Toggle } from "@/components/Toggle";
import { LOGIC_LABEL, RULES_KEY, useToggleRule } from "./shared";

/** Only http(s) links from rule files are rendered as links. */
function safeHref(url: string): string | undefined {
  try {
    const u = new URL(url);
    return u.protocol === "https:" || u.protocol === "http:" ? u.href : undefined;
  } catch {
    return undefined;
  }
}

export function RulePage() {
  const { id = "" } = useParams();
  const { user } = useAuth();
  const rule = useQuery({
    queryKey: [...RULES_KEY, id],
    queryFn: () => api.get<RuleDetail>(`/api/rules/${encodeURIComponent(id)}`),
  });
  const alerts = useQuery({
    queryKey: ["alerts", "rule", id],
    queryFn: () => api.get<Page<Alert>>(`/api/alerts?rule_id=${encodeURIComponent(id)}&limit=20`),
  });
  const toggle = useToggleRule();
  const r = rule.data;

  if (rule.isError) {
    return <p className="mx-auto max-w-5xl text-fg-muted">Rule not found.</p>;
  }

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-6">
      <div>
        <Link to="/rules" className="text-xs text-fg-muted hover:text-fg">
          ← Rules
        </Link>
        <div className="mt-2 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            {r ? <SeverityBadge severity={r.severity} /> : null}
            <h1 className="text-xl tracking-[var(--tracking-tighter)]">
              {r?.title ?? <span className="skeleton inline-block h-7 w-80" />}
            </h1>
          </div>
          {r ? (
            <label className="flex items-center gap-2 text-xs text-fg-muted">
              {r.enabled ? "Enabled" : "Disabled"}
              <Toggle
                checked={r.enabled}
                label={`${r.enabled ? "Disable" : "Enable"} rule`}
                disabled={user?.role !== "admin" || toggle.isPending}
                onChange={(v) => {
                  toggle.mutate({ id: r.id, enabled: v });
                }}
              />
            </label>
          ) : null}
        </div>
        {r ? (
          <p className="mt-1 font-mono text-xs text-fg-faint">
            {r.id} · {LOGIC_LABEL[r.logic_type]} · {formatNumber(r.hit_count)} alerts · last fired{" "}
            {r.last_fired_at ? formatRelative(r.last_fired_at) : "never"}
          </p>
        ) : null}
      </div>

      {r ? (
        <div className="grid gap-6 lg:grid-cols-[1fr_22rem]">
          <div className="flex flex-col gap-6">
            <Panel className="p-5">
              <p className="leading-relaxed">{r.description}</p>
              <h2 className="label-caps mt-5 mb-2">MITRE ATT&CK</h2>
              {r.techniques.length ? (
                <ul className="flex flex-col gap-1.5">
                  {r.techniques.map((t) => {
                    const href = t.url ? safeHref(t.url) : undefined;
                    return (
                      <li key={t.id} className="flex items-baseline gap-3">
                        <span className="w-20 font-mono text-xs">{t.id}</span>
                        {href ? (
                          <a
                            href={href}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 underline-offset-4 hover:underline"
                          >
                            {t.name ?? "unknown technique"}
                            <ExternalIcon className="size-3 text-fg-faint" />
                          </a>
                        ) : (
                          <span>{t.name ?? "unknown technique"}</span>
                        )}
                      </li>
                    );
                  })}
                  <li className="mt-1 text-xs text-fg-muted">
                    Primary tactic: <span className="font-mono text-fg">{r.primary_tactic}</span>
                  </li>
                </ul>
              ) : (
                <p className="text-xs text-fg-muted">
                  No hard technique mapping (hunting aid or pass-through).
                </p>
              )}
            </Panel>

            <Panel>
              <h2 className="label-caps border-b border-border px-5 py-3">
                Rule definition (read-only)
              </h2>
              <RawLog raw={r.yaml} wrap={false} className="max-h-[28rem] overflow-auto p-5" />
            </Panel>
          </div>

          <div className="flex flex-col gap-6">
            <Panel className="p-5">
              <h2 className="label-caps mb-2">Known false positives</h2>
              <ul className="flex list-disc flex-col gap-2 pl-4 text-fg-muted">
                {r.false_positives.map((f) => (
                  <li key={f}>{f}</li>
                ))}
              </ul>
              {r.references.length ? (
                <>
                  <h2 className="label-caps mt-5 mb-2">References</h2>
                  <ul className="flex flex-col gap-1 text-xs">
                    {r.references.map((ref) => {
                      const href = safeHref(ref);
                      return (
                        <li key={ref} className="truncate">
                          {href ? (
                            <a
                              href={href}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-fg-muted hover:text-fg"
                            >
                              {ref}
                            </a>
                          ) : (
                            <span className="text-fg-faint">{ref}</span>
                          )}
                        </li>
                      );
                    })}
                  </ul>
                </>
              ) : null}
            </Panel>
            <RetroHunt ruleId={r.id} />
          </div>
        </div>
      ) : (
        <div className="skeleton h-80 w-full" />
      )}

      <section aria-labelledby="recent-h">
        <h2 id="recent-h" className="mb-3 text-md">
          Recent alerts
        </h2>
        <Panel className="overflow-x-auto">
          {alerts.data?.items.length ? (
            <table className="w-full min-w-[44rem] text-left">
              <thead>
                <tr className="border-b border-border">
                  {["#", "Severity", "Entity", "Events", "First event", "Last event", "Status"].map(
                    (h) => (
                      <th key={h} scope="col" className="label-caps px-4 py-2.5 font-medium">
                        {h}
                      </th>
                    ),
                  )}
                </tr>
              </thead>
              <tbody className="font-mono text-xs">
                {alerts.data.items.map((a) => (
                  <tr key={a.id} className="border-b border-border last:border-0">
                    <td className="px-4 py-2 text-fg-faint">{a.id}</td>
                    <td className="px-4 py-2">
                      <SeverityBadge severity={a.severity} compact />
                    </td>
                    <td className="max-w-72 truncate px-4 py-2" title={a.group_key}>
                      {[a.host, a.user, a.src_ip].filter(Boolean).join(" · ") || a.group_key}
                    </td>
                    <td className="px-4 py-2">{formatNumber(a.event_count)}</td>
                    <td className="px-4 py-2 text-fg-muted">{formatTimestamp(a.first_event_at)}</td>
                    <td className="px-4 py-2 text-fg-muted">{formatTimestamp(a.last_event_at)}</td>
                    <td className="px-4 py-2 font-sans capitalize text-fg-muted">{a.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="px-4 py-10 text-center text-fg-muted">
              {alerts.isPending ? "Loading…" : "This rule hasn't fired."}
            </p>
          )}
        </Panel>
      </section>
    </div>
  );
}

function toLocalInput(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${String(d.getFullYear())}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function RetroHunt({ ruleId }: { ruleId: string }) {
  const qc = useQueryClient();
  const now = new Date();
  const [start, setStart] = useState(toLocalInput(new Date(now.getTime() - 7 * 86400_000)));
  const [end, setEnd] = useState(toLocalInput(now));
  const [message, setMessage] = useState<string | null>(null);
  const hunt = useMutation({
    mutationFn: () =>
      api.post<{ events_scanned: number; alerts: number }>(
        `/api/rules/${encodeURIComponent(ruleId)}/retro-hunt`,
        {
          start: new Date(start).toISOString(),
          end: new Date(end).toISOString(),
        },
      ),
    onSuccess: (r) => {
      setMessage(
        `Scanned ${formatNumber(r.events_scanned)} events · ${formatNumber(r.alerts)} alerts created or extended.`,
      );
      void qc.invalidateQueries({ queryKey: ["alerts", "rule", ruleId] });
      void qc.invalidateQueries({ queryKey: RULES_KEY });
    },
    onError: (e) => {
      setMessage(e instanceof ApiError ? e.message : "Retro-hunt failed.");
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    setMessage(null);
    hunt.mutate();
  };
  return (
    <Panel className="p-5">
      <h2 className="label-caps mb-1">Retro-hunt</h2>
      <p className="mb-4 text-xs text-fg-muted">
        Re-run this rule over stored events. Safe to repeat: existing alerts are extended, not
        duplicated.
      </p>
      <form onSubmit={submit} className="flex flex-col gap-3">
        <Field label="From (local time)" htmlFor="rh-start">
          <Input
            id="rh-start"
            type="datetime-local"
            value={start}
            onChange={(e) => {
              setStart(e.target.value);
            }}
          />
        </Field>
        <Field label="To" htmlFor="rh-end">
          <Input
            id="rh-end"
            type="datetime-local"
            value={end}
            onChange={(e) => {
              setEnd(e.target.value);
            }}
          />
        </Field>
        <Button type="submit" disabled={hunt.isPending}>
          {hunt.isPending ? "Hunting…" : "Run retro-hunt"}
        </Button>
        {message ? (
          <p role="status" className="text-xs text-fg-muted">
            {message}
          </p>
        ) : null}
      </form>
    </Panel>
  );
}
