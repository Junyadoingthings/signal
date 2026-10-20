import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Toggle } from "@/components/Toggle";
import { clsx } from "clsx";
import { useState } from "react";
import { Link } from "react-router";
import { Button, Dialog, Field, Input, PageHeader, Panel, SeverityBadge } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { formatNumber, formatRelative } from "@/lib/format";
import type { AttackMatrix, DetectionSettings, RuleSummary } from "@/lib/types";
import { LOGIC_LABEL, RULES_KEY, useToggleRule } from "./shared";

export function RulesPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [settingsOpen, setSettingsOpen] = useState(false);
  const rules = useQuery({
    queryKey: RULES_KEY,
    queryFn: () => api.get<RuleSummary[]>("/api/rules"),
  });
  const matrix = useQuery({
    queryKey: ["attack"],
    queryFn: () => api.get<AttackMatrix>("/api/attack"),
  });
  const toggle = useToggleRule();
  const rows = rules.data ?? [];
  const enabled = rows.filter((r) => r.enabled).length;

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-8">
      <PageHeader
        title="Rules"
        description={
          rules.data
            ? `${String(enabled)} of ${String(rows.length)} enabled · mapped to MITRE ATT&CK ${matrix.data?.version ?? ""}`
            : "Detections, their ATT&CK mapping and how often they fire."
        }
        actions={
          isAdmin ? (
            <Button
              onClick={() => {
                setSettingsOpen(true);
              }}
            >
              Business hours
            </Button>
          ) : undefined
        }
      />

      <Coverage matrix={matrix.data} />

      <Panel className="overflow-x-auto">
        <table className="w-full min-w-[56rem] text-left">
          <thead>
            <tr className="border-b border-border">
              {[
                "Severity",
                "Rule",
                "Logic",
                "Tactic",
                "Techniques",
                "Hits",
                "Last fired",
                "Enabled",
              ].map((h) => (
                <th key={h} scope="col" className="label-caps px-4 py-2.5 font-medium">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rules.isPending
              ? Array.from({ length: 8 }, (_, i) => (
                  <tr key={i} className="border-b border-border">
                    <td colSpan={8} className="px-4 py-3">
                      <div className="skeleton h-4 w-full" />
                    </td>
                  </tr>
                ))
              : rows.map((r) => (
                  <tr
                    key={r.id}
                    className={clsx(
                      "border-b border-border last:border-0 hover:bg-surface-2/60",
                      !r.enabled && "text-fg-faint",
                    )}
                  >
                    <td className="px-4 py-2.5">
                      <SeverityBadge severity={r.severity} />
                    </td>
                    <td className="px-4 py-2.5">
                      <Link to={`/rules/${r.id}`} className="underline-offset-4 hover:underline">
                        {r.title}
                      </Link>
                      <div className="font-mono text-2xs text-fg-faint">{r.id}</div>
                    </td>
                    <td className="px-4 py-2.5 text-xs text-fg-muted">
                      {LOGIC_LABEL[r.logic_type]}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-fg-muted">{r.primary_tactic ?? "—"}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-fg-muted">
                      {r.techniques.length ? r.techniques.map((t) => t.id).join(", ") : "—"}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs tabular">
                      <span className={r.hit_count > 0 ? "text-fg" : "text-fg-faint"}>
                        {formatNumber(r.hit_count)}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-xs text-fg-muted">
                      {r.last_fired_at ? formatRelative(r.last_fired_at) : "never"}
                    </td>
                    <td className="px-4 py-2.5">
                      <Toggle
                        checked={r.enabled}
                        label={`${r.enabled ? "Disable" : "Enable"} ${r.title}`}
                        disabled={!isAdmin || toggle.isPending}
                        onChange={(v) => {
                          toggle.mutate({ id: r.id, enabled: v });
                        }}
                      />
                    </td>
                  </tr>
                ))}
          </tbody>
        </table>
      </Panel>
      {isAdmin ? (
        <BusinessHoursDialog
          open={settingsOpen}
          onClose={() => {
            setSettingsOpen(false);
          }}
        />
      ) : null}
    </div>
  );
}

/** One cell per ATT&CK tactic in kill-chain order. Gaps stay visible on purpose. */
export function Coverage({ matrix }: { matrix: AttackMatrix | undefined }) {
  if (!matrix) return <div className="skeleton h-16 w-full" />;
  return (
    <section aria-labelledby="coverage-h">
      <div className="mb-2 flex items-baseline justify-between">
        <h2 id="coverage-h" className="label-caps">
          Rule coverage by tactic
        </h2>
        <span className="text-2xs text-fg-faint">
          enabled rules per tactic · empty = blind spot
        </span>
      </div>
      <ol className="grid grid-cols-5 gap-px overflow-hidden rounded-md border border-border bg-border sm:grid-cols-8 lg:grid-cols-15">
        {matrix.tactics.map((t) => (
          <li
            key={t.shortname}
            className={clsx(
              "flex min-h-16 flex-col justify-between gap-1 p-2",
              t.rule_count ? "bg-surface-1" : "bg-surface-2/40",
            )}
            title={`${t.name} (${t.id}): ${String(t.rule_count)} rules`}
          >
            <span
              className={clsx(
                "text-2xs leading-tight [overflow-wrap:anywhere]",
                t.rule_count ? "text-fg-muted" : "text-fg-faint",
              )}
            >
              {t.name}
            </span>
            <span
              className={clsx(
                "font-mono text-md leading-none",
                t.rule_count ? "text-fg" : "text-fg-faint",
              )}
            >
              {t.rule_count || "·"}
            </span>
          </li>
        ))}
      </ol>
    </section>
  );
}

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

function BusinessHoursDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const current = useQuery({
    queryKey: ["settings", "detection"],
    queryFn: () => api.get<DetectionSettings>("/api/settings/detection"),
    enabled: open,
  });
  const [draft, setDraft] = useState<DetectionSettings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const value = draft ?? current.data;
  const save = useMutation({
    mutationFn: (v: DetectionSettings) => api.put<DetectionSettings>("/api/settings/detection", v),
    onSuccess: (v) => {
      qc.setQueryData(["settings", "detection"], v);
      setDraft(null);
      setError(null);
      onClose();
    },
    onError: (e) => {
      setError(
        e instanceof ApiError && e.code === "validation_error"
          ? "Check the timezone and times."
          : "Save failed.",
      );
    },
  });

  return (
    <Dialog open={open} onClose={onClose} title="Business hours">
      {value ? (
        <form
          className="flex flex-col gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate(value);
          }}
        >
          <p className="text-xs text-fg-muted">
            Used by off-hours rules. Changes apply to new detections and retro-hunts.
          </p>
          <Field label="Timezone" htmlFor="bh-tz">
            <Input
              id="bh-tz"
              value={value.business_timezone}
              onChange={(e) => {
                setDraft({ ...value, business_timezone: e.target.value });
              }}
            />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Start" htmlFor="bh-start">
              <Input
                id="bh-start"
                type="time"
                value={value.business_start}
                onChange={(e) => {
                  setDraft({ ...value, business_start: e.target.value });
                }}
              />
            </Field>
            <Field label="End" htmlFor="bh-end">
              <Input
                id="bh-end"
                type="time"
                value={value.business_end}
                onChange={(e) => {
                  setDraft({ ...value, business_end: e.target.value });
                }}
              />
            </Field>
          </div>
          <fieldset>
            <legend className="mb-1.5 text-xs font-medium text-fg-muted">Working days</legend>
            <div className="flex flex-wrap gap-1.5">
              {DAYS.map((d, i) => {
                const on = value.business_days.includes(i);
                return (
                  <button
                    key={d}
                    type="button"
                    aria-pressed={on}
                    onClick={() => {
                      setDraft({
                        ...value,
                        business_days: on
                          ? value.business_days.filter((x) => x !== i)
                          : [...value.business_days, i],
                      });
                    }}
                    className={clsx(
                      "h-7 rounded-sm border px-2.5 text-xs",
                      on
                        ? "border-fg bg-fg text-fg-inverse"
                        : "border-border text-fg-muted hover:border-border-strong",
                    )}
                  >
                    {d}
                  </button>
                );
              })}
            </div>
          </fieldset>
          {error ? (
            <p role="alert" className="text-xs text-danger">
              {error}
            </p>
          ) : null}
          <div className="flex justify-end gap-2">
            <Button onClick={onClose}>Cancel</Button>
            <Button type="submit" variant="primary" disabled={save.isPending}>
              Save
            </Button>
          </div>
        </form>
      ) : (
        <div className="skeleton h-40" />
      )}
    </Dialog>
  );
}
