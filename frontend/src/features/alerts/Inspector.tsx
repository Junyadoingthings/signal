import { useQuery } from "@tanstack/react-query";
import { clsx } from "clsx";
import { lazy, Suspense, useState } from "react";
import { Link } from "react-router";
import { ExternalIcon } from "@/components/icons";
import { RawLog } from "@/components/RawLog";
import { Button, Kbd, Select, SeverityBadge } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { entityPath } from "@/lib/entity";
import { formatNumber, formatTimestamp } from "@/lib/format";
import type { AlertDetail, AlertStatus, EventRecord, MatchHit, Verdict } from "@/lib/types";
import { STATUS_LABEL, useDirectory, useTriage, VERDICT_LABEL } from "./triage";

// Markdown rendering is heavy and only needed once the notes panel is on screen.
const Activity = lazy(() => import("@/components/Activity").then((m) => ({ default: m.Activity })));

function safeHref(url: string | null): string | undefined {
  if (!url) return undefined;
  try {
    const u = new URL(url);
    return u.protocol === "https:" ? u.href : undefined;
  } catch {
    return undefined;
  }
}

function show(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return JSON.stringify(v);
}

const OP_LABEL: Record<string, string> = {
  equals: "is",
  re: "matches",
  contains: "contains",
  startswith: "starts with",
  endswith: "ends with",
  gte: "≥",
  gt: ">",
  lte: "≤",
  lt: "<",
  cidr: "in",
  exists: "exists",
  off_hours: "outside business hours",
  len_gte: "length ≥",
  entropy_gte: "entropy ≥",
  first_seen: "first seen",
};

export function Inspector({ alertId, onClose }: { alertId: number; onClose: () => void }) {
  const detail = useQuery({
    queryKey: ["alert", alertId],
    queryFn: () => api.get<AlertDetail>(`/api/alerts/${String(alertId)}?events_limit=50`),
  });
  const d = detail.data;

  return (
    <aside
      aria-label={`Alert ${String(alertId)}`}
      className="flex h-full min-w-0 flex-col bg-surface-1"
    >
      <header className="flex items-start justify-between gap-3 border-b border-border px-5 py-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            {d ? (
              <SeverityBadge severity={d.alert.severity} breathing={d.alert.status === "new"} />
            ) : null}
            <span className="font-mono text-2xs text-fg-faint">#{alertId}</span>
            {d?.alert.incident_id ? (
              <Link
                to={`/incidents/${String(d.alert.incident_id)}`}
                className="font-mono text-2xs text-accent-fg hover:underline"
              >
                incident #{d.alert.incident_id}
              </Link>
            ) : null}
          </div>
          <h2 className="mt-1.5 text-lg leading-snug tracking-[var(--tracking-tight)]">
            {d?.rule.title ?? <span className="skeleton inline-block h-6 w-64" />}
          </h2>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="flex items-center gap-1.5 rounded-xs p-1 text-fg-muted hover:text-fg"
          aria-label="Close inspector"
          title="Close (Esc)"
        >
          <Kbd>esc</Kbd>
        </button>
      </header>

      {detail.isError ? (
        <p className="p-5 text-fg-muted">This alert couldn't be loaded.</p>
      ) : !d ? (
        <div className="flex flex-col gap-3 p-5">
          {Array.from({ length: 6 }, (_, i) => (
            <div key={i} className="skeleton h-5 w-full" />
          ))}
        </div>
      ) : (
        <div className="min-h-0 flex-1 overflow-y-auto">
          <TriageBar detail={d} />
          <div className="flex flex-col gap-6 px-5 py-5">
            <Entities detail={d} />
            <WhyFired detail={d} />
            <Section title="MITRE ATT&CK">
              {d.rule.techniques.length ? (
                <ul className="flex flex-col gap-1">
                  {d.rule.techniques.map((t) => {
                    const href = safeHref(t.url);
                    return (
                      <li key={t.id} className="flex items-baseline gap-3 text-sm">
                        <span className="w-20 shrink-0 font-mono text-xs">{t.id}</span>
                        {href ? (
                          <a
                            href={href}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 hover:underline"
                          >
                            {t.name}
                            <ExternalIcon className="size-3 text-fg-faint" />
                          </a>
                        ) : (
                          <span>{t.name ?? "unknown"}</span>
                        )}
                      </li>
                    );
                  })}
                  <li className="text-xs text-fg-muted">
                    Tactic <span className="font-mono text-fg">{d.rule.primary_tactic}</span>
                  </li>
                </ul>
              ) : (
                <p className="text-xs text-fg-muted">No hard mapping for this rule.</p>
              )}
            </Section>
            <Section title="Rule">
              <p className="text-sm leading-relaxed text-fg-muted">{d.rule.description}</p>
              <p className="mt-3 text-xs font-medium text-fg">
                Before calling it a true positive, rule out:
              </p>
              <ul className="mt-1.5 flex list-disc flex-col gap-1 pl-4 text-xs text-fg-muted">
                {d.rule.false_positives.map((f) => (
                  <li key={f}>{f}</li>
                ))}
              </ul>
              <Link
                to={`/rules/${d.rule.id}`}
                className="mt-2 inline-block font-mono text-2xs text-fg-faint hover:text-fg"
              >
                {d.rule.id} →
              </Link>
            </Section>
            <Events detail={d} />
            <Section title="Notes & history">
              <Suspense fallback={<div className="skeleton h-16 w-full" />}>
                <Activity target="alerts" id={alertId} />
              </Suspense>
            </Section>
          </div>
        </div>
      )}
    </aside>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h3 className="label-caps mb-2">{title}</h3>
      {children}
    </section>
  );
}

function TriageBar({ detail }: { detail: AlertDetail }) {
  const { user } = useAuth();
  const triage = useTriage();
  const users = useDirectory();
  const a = detail.alert;
  const [closing, setClosing] = useState(false);
  const error = triage.error instanceof ApiError ? triage.error.message : null;

  const setStatus = (s: AlertStatus) => {
    if (s === "closed") {
      setClosing(true);
      return;
    }
    setClosing(false);
    triage.mutate({ id: a.id, patch: { status: s } });
  };
  const close = (v: Verdict) => {
    setClosing(false);
    triage.mutate({ id: a.id, patch: { status: "closed", verdict: v } });
  };

  return (
    <div className="flex flex-col gap-3 border-b border-border bg-surface-2/50 px-5 py-3">
      <div className="flex flex-wrap items-center gap-3">
        <div
          role="radiogroup"
          aria-label="Status"
          className="flex rounded-sm border border-border p-0.5"
        >
          {(["new", "investigating", "closed"] as AlertStatus[]).map((s) => (
            <button
              key={s}
              type="button"
              role="radio"
              aria-checked={a.status === s}
              disabled={triage.isPending}
              onClick={() => {
                setStatus(s);
              }}
              className={clsx(
                "rounded-xs px-2.5 py-1 text-xs transition-colors",
                a.status === s ? "bg-fg text-fg-inverse" : "text-fg-muted hover:text-fg",
              )}
            >
              {STATUS_LABEL[s]}
            </button>
          ))}
        </div>
        {a.verdict ? (
          <span className="text-xs text-fg-muted">
            Verdict <span className="text-fg">{VERDICT_LABEL[a.verdict as Verdict]}</span>
          </span>
        ) : null}
        <div className="ml-auto flex items-center gap-2">
          <Select
            aria-label="Assignee"
            className="h-7 w-40 text-xs"
            value={a.assignee_id ?? ""}
            onChange={(e) => {
              const v = e.target.value;
              triage.mutate({
                id: a.id,
                patch: v ? { assignee_id: Number(v) } : { unassign: true },
              });
            }}
          >
            <option value="">Unassigned</option>
            {(users.data ?? []).map((u) => (
              <option key={u.id} value={u.id}>
                {u.display_name}
                {u.id === user?.id ? " (me)" : ""}
              </option>
            ))}
          </Select>
        </div>
      </div>
      {closing ? (
        <div
          className="flex flex-wrap items-center gap-2"
          role="group"
          aria-label="Choose a verdict to close"
        >
          <span className="text-xs text-fg-muted">Close as</span>
          {(Object.keys(VERDICT_LABEL) as Verdict[]).map((v) => (
            <Button
              key={v}
              size="sm"
              variant={v === "true_positive" ? "primary" : "secondary"}
              onClick={() => {
                close(v);
              }}
            >
              {VERDICT_LABEL[v]}
            </Button>
          ))}
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
    </div>
  );
}

function Entities({ detail }: { detail: AlertDetail }) {
  const a = detail.alert;
  const items: [string, string | null, "host" | "user" | "ip"][] = [
    ["host", a.host, "host"],
    ["user", a.user, "user"],
    ["source ip", a.src_ip, "ip"],
  ];
  return (
    <dl className="grid grid-cols-[6rem_1fr] gap-x-3 gap-y-1.5 text-sm">
      {items
        .filter(([, v]) => v)
        .map(([k, v, t]) => (
          <div key={k} className="contents">
            <dt className="text-xs text-fg-faint">{k}</dt>
            <dd className="font-mono text-xs">
              <Link to={entityPath(t, v ?? "")} className="hover:text-accent-fg hover:underline">
                {v}
              </Link>
            </dd>
          </div>
        ))}
      <dt className="text-xs text-fg-faint">window</dt>
      <dd className="font-mono text-xs text-fg-muted">
        {formatTimestamp(a.first_event_at)}
        {a.last_event_at !== a.first_event_at
          ? ` → ${formatTimestamp(a.last_event_at).slice(11)}`
          : ""}
      </dd>
      <dt className="text-xs text-fg-faint">events</dt>
      <dd className="font-mono text-xs">{formatNumber(a.event_count)}</dd>
    </dl>
  );
}

function hitValues(hits: MatchHit[]): string[] {
  return hits
    .map((h) => h.actual)
    .filter((v): v is string => typeof v === "string" && v.length >= 2);
}

function WhyFired({ detail }: { detail: AlertDetail }) {
  const ctx = detail.alert.match_context;
  const hits = ctx.matched ?? [];
  const extras: string[] = [];
  if (ctx.type === "threshold") {
    const n = ctx.distinct_field
      ? `${show(ctx.distinct)} distinct ${show(ctx.distinct_field)}`
      : `${show(ctx.count)} events`;
    extras.push(
      `${n} (threshold ${show(ctx.threshold)}) within ${show(ctx.window)} for ${show(ctx.group && Object.values(ctx.group as Record<string, unknown>).join(" · "))}`,
    );
  } else if (ctx.type === "sequence") {
    const steps = (ctx.steps as { name: string; count: number }[] | undefined) ?? [];
    extras.push(
      `${steps.map((s) => `${s.name} ×${String(s.count)}`).join(" → ")} within ${show(ctx.within)}`,
    );
  } else if (ctx.type === "first_seen") {
    extras.push(
      `history for this ${Object.keys(ctx.entity as object).join("")} since ${formatTimestamp(show(ctx.history_since))}`,
    );
  }
  return (
    <section>
      <h3 className="label-caps mb-2">Why it fired</h3>
      {extras.map((x) => (
        <p key={x} className="mb-2 text-sm">
          {x}
        </p>
      ))}
      <ul className="flex flex-col gap-1.5">
        {hits.map((h, i) => (
          <li key={i} className="grid grid-cols-[minmax(6rem,auto)_1fr] gap-x-3 font-mono text-xs">
            <span className="text-fg-muted">{h.field}</span>
            <span className="[overflow-wrap:anywhere]">
              <span className="text-fg-faint">{OP_LABEL[h.op] ?? h.op} </span>
              {h.op === "re" ? (
                <>
                  <span className="text-fg-faint">/…/ → </span>
                  <mark className="rounded-xs bg-accent-soft px-0.5 text-accent-fg">
                    {show(h.actual)}
                  </mark>
                </>
              ) : (
                <>
                  <span className="text-fg-faint">{show(h.expected)}</span>
                  {h.op !== "equals" ? (
                    <>
                      <span className="text-fg-faint"> → </span>
                      <mark className="rounded-xs bg-accent-soft px-0.5 text-accent-fg">
                        {show(h.actual)}
                      </mark>
                    </>
                  ) : null}
                </>
              )}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

const FIELD_ORDER: (keyof EventRecord)[] = [
  "timestamp",
  "source_type",
  "host",
  "user",
  "src_ip",
  "src_port",
  "dst_ip",
  "dst_port",
  "process_name",
  "process_cmdline",
  "parent_process",
  "event_code",
  "action",
  "outcome",
  "dns_query",
  "url",
  "http_status",
  "user_agent",
];

function Events({ detail }: { detail: AlertDetail }) {
  const hits = detail.alert.match_context.matched ?? [];
  const highlight = hitValues(hits);
  const matchedFields = new Set(hits.map((h) => h.field));
  const [openId, setOpenId] = useState<number | null>(detail.events[0]?.id ?? null);
  return (
    <section>
      <h3 className="label-caps mb-2">
        Events{" "}
        <span className="normal-case tracking-normal text-fg-faint">
          {detail.events.length < detail.events_total
            ? `first ${String(detail.events.length)} of ${formatNumber(detail.events_total)}`
            : formatNumber(detail.events_total)}
        </span>
      </h3>
      <ul className="flex flex-col divide-y divide-border rounded-sm border border-border">
        {detail.events.map((e) => (
          <li key={e.id}>
            <button
              type="button"
              aria-expanded={openId === e.id}
              onClick={() => {
                setOpenId(openId === e.id ? null : e.id);
              }}
              className="w-full px-3 py-2 text-left hover:bg-surface-2/60"
            >
              <RawLog
                raw={e.raw}
                highlight={highlight}
                className={clsx(openId !== e.id && "line-clamp-2")}
              />
            </button>
            {openId === e.id ? (
              <dl className="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-1 border-t border-border bg-bg/40 px-3 py-3 font-mono text-xs">
                {FIELD_ORDER.filter((k) => e[k] !== null).map((k) => (
                  <div key={k} className="contents">
                    <dt
                      className={clsx(
                        "flex items-center gap-1.5",
                        matchedFields.has(k) ? "text-accent-fg" : "text-fg-faint",
                      )}
                    >
                      {matchedFields.has(k) ? (
                        <span aria-hidden="true" className="size-1 rounded-full bg-accent" />
                      ) : null}
                      {k}
                      {matchedFields.has(k) ? <span className="sr-only"> (matched)</span> : null}
                    </dt>
                    <dd className="[overflow-wrap:anywhere]">{show(e[k])}</dd>
                  </div>
                ))}
              </dl>
            ) : null}
          </li>
        ))}
      </ul>
    </section>
  );
}
