import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { clsx } from "clsx";
import { useId, useRef, useState, type DragEvent, type FormEvent } from "react";
import { Link } from "react-router";
import { PlusIcon, UploadIcon } from "@/components/icons";
import { Button, Dialog, Field, Input, PageHeader, Panel, Select } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { formatNumber, formatRelative } from "@/lib/format";
import type {
  Batch,
  IngestFormat,
  IngestSettings,
  IngestToken,
  IngestTokenCreated,
  Page,
} from "@/lib/types";
import { uploadFile } from "@/lib/upload";
import { batchName, FORMAT_LABEL, FORMAT_OPTIONS, formatBytes, MAPPABLE_FIELDS } from "./formats";

const BATCHES_KEY = ["ingest", "batches"] as const;
const SETTINGS_KEY = ["ingest", "settings"] as const;

export function IngestPage() {
  const { user } = useAuth();
  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-8">
      <PageHeader
        title="Ingest"
        description="Upload log files or stream them live. Every raw record is kept, parsed or not."
      />
      <UploadPanel />
      <BatchesTable />
      {user?.role === "admin" ? <TokensPanel /> : <LiveHint />}
    </div>
  );
}

/* ------------------------------------------------------------------ upload */

type FormatChoice = "auto" | IngestFormat;
interface MappingRow {
  field: string;
  path: string;
}

function UploadPanel() {
  const qc = useQueryClient();
  const inputRef = useRef<HTMLInputElement>(null);
  const ids = { format: useId(), host: useId() };
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [format, setFormat] = useState<FormatChoice>("auto");
  const [host, setHost] = useState("");
  const [mapping, setMapping] = useState<MappingRow[]>([{ field: "timestamp", path: "" }]);
  const [progress, setProgress] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastBatch, setLastBatch] = useState<Batch | null>(null);

  const settings = useQuery({
    queryKey: SETTINGS_KEY,
    queryFn: () => api.get<IngestSettings>("/api/ingest/settings"),
  });
  const maxBytes = settings.data?.max_upload_bytes ?? 50 * 1024 * 1024;

  const pick = (f: File | undefined) => {
    setError(null);
    setLastBatch(null);
    if (!f) return;
    if (f.size > maxBytes) {
      setError(`${f.name} is ${formatBytes(f.size)}; the limit is ${formatBytes(maxBytes)}.`);
      return;
    }
    setFile(f);
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    pick(e.dataTransfer.files[0]);
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!file) return;
    setError(null);
    setProgress(0);
    try {
      const fieldMapping =
        format === "generic_jsonl"
          ? Object.fromEntries(
              mapping.filter((m) => m.path.trim()).map((m) => [m.field, m.path.trim()]),
            )
          : undefined;
      const batch = await uploadFile({
        file,
        format,
        host: host.trim() || undefined,
        fieldMapping,
        onProgress: setProgress,
      });
      setLastBatch(batch);
      setFile(null);
      if (inputRef.current) inputRef.current.value = "";
      void qc.invalidateQueries({ queryKey: BATCHES_KEY });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Upload failed.");
    } finally {
      setProgress(null);
    }
  };

  const showHost = format === "auto" || format === "web_access";
  const hint = FORMAT_OPTIONS.find((o) => o.value === format)?.hint;

  return (
    <Panel>
      <form onSubmit={(e) => void submit(e)} className="grid gap-6 p-5 lg:grid-cols-[1.2fr_1fr]">
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => {
            setDragging(false);
          }}
          onDrop={onDrop}
          className={clsx(
            "canvas-grid relative flex min-h-48 flex-col items-center justify-center gap-3 rounded-md border border-dashed px-6 py-8 text-center",
            "transition-colors duration-[var(--dur-fast)]",
            dragging ? "border-accent bg-accent-soft" : "border-border-strong",
          )}
        >
          <UploadIcon className={clsx("size-6", dragging ? "text-accent-fg" : "text-fg-faint")} />
          {file ? (
            <div>
              <p className="font-mono text-sm">{file.name}</p>
              <p className="text-xs text-fg-muted">{formatBytes(file.size)}</p>
            </div>
          ) : (
            <div>
              <p className="text-md">Drop a log file here</p>
              <p className="text-xs text-fg-muted">
                auth.log, access.log, .evtx, Wazuh alerts.json, JSON Lines · up to{" "}
                {formatBytes(maxBytes)}
              </p>
            </div>
          )}
          <Button
            size="sm"
            onClick={() => {
              inputRef.current?.click();
            }}
          >
            {file ? "Choose another" : "Browse files"}
          </Button>
          <input
            ref={inputRef}
            type="file"
            className="sr-only"
            tabIndex={-1}
            aria-label="Log file"
            onChange={(e) => {
              pick(e.target.files?.[0]);
            }}
          />
          {progress !== null ? (
            <div
              className="absolute inset-x-0 bottom-0 h-0.5 overflow-hidden rounded-b-md bg-border"
              role="progressbar"
              aria-label="Upload progress"
              aria-valuenow={Math.round(progress * 100)}
              aria-valuemin={0}
              aria-valuemax={100}
            >
              <div
                className="h-full bg-accent transition-[width] duration-[var(--dur-fast)]"
                style={{ width: `${progress * 100}%` }}
              />
            </div>
          ) : null}
        </div>

        <div className="flex flex-col gap-4">
          <Field label="Format" htmlFor={ids.format} hint={hint}>
            <Select
              id={ids.format}
              value={format}
              onChange={(e) => {
                setFormat(e.target.value as FormatChoice);
              }}
            >
              {FORMAT_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </Select>
          </Field>

          {showHost ? (
            <Field
              label="Host (web access logs)"
              htmlFor={ids.host}
              hint="Access logs don't name the server they came from."
            >
              <Input
                id={ids.host}
                placeholder="web01"
                value={host}
                pattern="[A-Za-z0-9._-]*"
                onChange={(e) => {
                  setHost(e.target.value);
                }}
              />
            </Field>
          ) : null}

          {format === "generic_jsonl" ? (
            <MappingEditor rows={mapping} onChange={setMapping} />
          ) : null}

          <SyslogAssumption settings={settings.data} />

          {error ? (
            <p role="alert" className="text-xs text-danger">
              {error}
            </p>
          ) : null}
          {lastBatch ? (
            <p role="status" className="text-xs text-fg-muted">
              Queued as{" "}
              <Link
                className="text-fg underline-offset-4 hover:underline"
                to={`/ingest/batches/${lastBatch.id}`}
              >
                batch #{lastBatch.id}
              </Link>{" "}
              · detected {FORMAT_LABEL[lastBatch.source_type]}
            </p>
          ) : null}

          <div className="mt-auto flex justify-end">
            <Button type="submit" variant="primary" disabled={!file || progress !== null}>
              {progress !== null ? `Uploading ${Math.round(progress * 100)}%` : "Upload and parse"}
            </Button>
          </div>
        </div>
      </form>
    </Panel>
  );
}

function MappingEditor({
  rows,
  onChange,
}: {
  rows: MappingRow[];
  onChange: (rows: MappingRow[]) => void;
}) {
  const used = new Set(rows.map((r) => r.field));
  const next = MAPPABLE_FIELDS.find((f) => !used.has(f));
  return (
    <fieldset className="flex flex-col gap-2">
      <legend className="mb-1.5 text-xs font-medium text-fg-muted">
        Field mapping <span className="text-fg-faint">(dotted path in each record)</span>
      </legend>
      {rows.map((row, i) => (
        <div key={i} className="flex gap-2">
          <Select
            aria-label="Schema field"
            className="w-40 font-mono text-xs"
            value={row.field}
            disabled={row.field === "timestamp"}
            onChange={(e) => {
              onChange(rows.map((r, j) => (j === i ? { ...r, field: e.target.value } : r)));
            }}
          >
            {MAPPABLE_FIELDS.filter((f) => f === row.field || !used.has(f)).map((f) => (
              <option key={f} value={f}>
                {f}
              </option>
            ))}
          </Select>
          <Input
            aria-label={`Path for ${row.field}`}
            className="font-mono text-xs"
            placeholder={
              row.field === "timestamp" ? "e.g. @timestamp or event.created" : "e.g. source.ip"
            }
            value={row.path}
            onChange={(e) => {
              onChange(rows.map((r, j) => (j === i ? { ...r, path: e.target.value } : r)));
            }}
          />
          {row.field !== "timestamp" ? (
            <Button
              size="sm"
              variant="ghost"
              aria-label={`Remove ${row.field}`}
              onClick={() => {
                onChange(rows.filter((_, j) => j !== i));
              }}
            >
              ×
            </Button>
          ) : null}
        </div>
      ))}
      {next ? (
        <Button
          size="sm"
          variant="ghost"
          className="self-start"
          onClick={() => {
            onChange([...rows, { field: next, path: "" }]);
          }}
        >
          <PlusIcon className="size-3" /> Add field
        </Button>
      ) : null}
    </fieldset>
  );
}

function SyslogAssumption({ settings }: { settings: IngestSettings | undefined }) {
  const { user } = useAuth();
  const [editing, setEditing] = useState(false);
  if (!settings) return <div className="skeleton h-4 w-56" />;
  return (
    <div className="rounded-sm border border-border bg-surface-2 px-3 py-2.5 text-xs text-fg-muted">
      <p>
        Classic syslog has no year or timezone. Assuming{" "}
        <span className="font-mono text-fg">{settings.syslog_timezone}</span>, year{" "}
        <span className="font-mono text-fg">
          {settings.syslog_year ?? "inferred (current, rolled back if in the future)"}
        </span>
        .
        {user?.role === "admin" ? (
          <button
            type="button"
            className="ml-1.5 text-fg underline-offset-4 hover:underline"
            onClick={() => {
              setEditing(true);
            }}
          >
            Change
          </button>
        ) : null}
      </p>
      <AssumptionDialog
        open={editing}
        settings={settings}
        onClose={() => {
          setEditing(false);
        }}
      />
    </div>
  );
}

function AssumptionDialog({
  open,
  settings,
  onClose,
}: {
  open: boolean;
  settings: IngestSettings;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [tz, setTz] = useState(settings.syslog_timezone);
  const [year, setYear] = useState(settings.syslog_year?.toString() ?? "");
  const [error, setError] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: () =>
      api.put<IngestSettings>("/api/ingest/settings", {
        syslog_timezone: tz.trim(),
        syslog_year: year.trim() ? Number(year) : null,
      }),
    onSuccess: (data) => {
      qc.setQueryData(SETTINGS_KEY, data);
      setError(null);
      onClose();
    },
    onError: (e) => {
      setError(
        e instanceof ApiError && e.code === "validation_error"
          ? "Unknown timezone or invalid year."
          : "Save failed.",
      );
    },
  });
  const zones = Intl.supportedValuesOf("timeZone");
  return (
    <Dialog open={open} onClose={onClose} title="Syslog assumptions">
      <form
        className="flex flex-col gap-4"
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate();
        }}
      >
        <Field
          label="Timezone of the log source"
          htmlFor="tz"
          hint="IANA name, e.g. Africa/Johannesburg."
        >
          <Input
            id="tz"
            list="tz-list"
            value={tz}
            onChange={(e) => {
              setTz(e.target.value);
            }}
          />
          <datalist id="tz-list">
            {["UTC", ...zones].map((z) => (
              <option key={z} value={z} />
            ))}
          </datalist>
        </Field>
        <Field label="Year" htmlFor="year" hint="Leave empty to infer it.">
          <Input
            id="year"
            inputMode="numeric"
            placeholder="inferred"
            value={year}
            onChange={(e) => {
              setYear(e.target.value.replace(/\D/g, "").slice(0, 4));
            }}
          />
        </Field>
        <p className="text-xs text-fg-faint">
          Applies to files ingested from now on. Recorded in the audit log.
        </p>
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
    </Dialog>
  );
}

/* ------------------------------------------------------------------ batches */

export function BatchStatus({ batch }: { batch: Batch }) {
  const meta: Record<Batch["status"], { label: string; dot: string }> = {
    pending: { label: "Queued", dot: "bg-fg-faint" },
    running: { label: "Parsing", dot: "bg-accent animate-pulse" },
    done: { label: "Done", dot: "bg-ok" },
    failed: { label: "Failed", dot: "bg-danger" },
    live: { label: "Live", dot: "bg-accent" },
  };
  const m = meta[batch.status];
  return (
    <span className="inline-flex items-center gap-1.5 text-xs">
      <span aria-hidden="true" className={clsx("size-1.5 rounded-full", m.dot)} />
      {m.label}
    </span>
  );
}

function BatchesTable() {
  const batches = useQuery({
    queryKey: BATCHES_KEY,
    queryFn: () => api.get<Page<Batch>>("/api/ingest/batches?limit=50"),
    refetchInterval: (q) =>
      q.state.data?.items.some((b) => b.status === "pending" || b.status === "running")
        ? 1500
        : 10_000,
  });
  const rows = batches.data?.items ?? [];

  return (
    <section aria-labelledby="batches-h">
      <h2 id="batches-h" className="mb-3 text-md">
        Batches
      </h2>
      <Panel className="overflow-x-auto">
        <table className="w-full min-w-[52rem] text-left">
          <thead>
            <tr className="border-b border-border">
              {[
                "#",
                "Source",
                "Format",
                "Status",
                "Parsed",
                "Unparsed",
                "Duplicates",
                "Size",
                "Received",
              ].map((h) => (
                <th key={h} scope="col" className="label-caps px-4 py-2.5 font-medium">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="tabular">
            {batches.isPending ? (
              Array.from({ length: 3 }, (_, i) => (
                <tr key={i} className="border-b border-border">
                  <td colSpan={9} className="px-4 py-3">
                    <div className="skeleton h-4 w-full" />
                  </td>
                </tr>
              ))
            ) : rows.length === 0 ? (
              <tr>
                <td colSpan={9} className="px-4 py-10 text-center text-fg-muted">
                  Nothing ingested yet. Drop a file above, or point signal-tail at a log.
                </td>
              </tr>
            ) : (
              rows.map((b) => (
                <tr
                  key={b.id}
                  className="border-b border-border last:border-0 hover:bg-surface-2/60"
                >
                  <td className="px-4 py-2.5 font-mono text-xs text-fg-faint">{b.id}</td>
                  <td className="max-w-64 truncate px-4 py-2.5">
                    <Link
                      to={`/ingest/batches/${b.id}`}
                      className="font-mono text-xs text-fg underline-offset-4 hover:underline"
                      title={batchName(b)}
                    >
                      {batchName(b)}
                    </Link>
                  </td>
                  <td className="px-4 py-2.5 text-xs text-fg-muted">
                    {FORMAT_LABEL[b.source_type]}
                  </td>
                  <td className="px-4 py-2.5" title={b.error ?? undefined}>
                    <BatchStatus batch={b} />
                  </td>
                  <td className="px-4 py-2.5 font-mono text-xs">{formatNumber(b.parsed_count)}</td>
                  <td
                    className={clsx(
                      "px-4 py-2.5 font-mono text-xs",
                      b.unparsed_count > 0 ? "text-accent-fg" : "text-fg-faint",
                    )}
                  >
                    {formatNumber(b.unparsed_count)}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-xs text-fg-muted">
                    {formatNumber(b.duplicate_count)}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-xs text-fg-muted">
                    {b.kind === "live" ? "—" : formatBytes(b.size_bytes)}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-fg-muted">
                    {formatRelative(b.created_at)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </Panel>
    </section>
  );
}

/* ------------------------------------------------------------------ live */

const TAIL_CMD =
  "SIGNAL_INGEST_TOKEN=<token> python3 tools/signal_tail.py /var/log/auth.log --format linux_auth --url https://signal.example";

function LiveHint() {
  return (
    <Panel className="p-5">
      <h2 className="text-md">Live ingest</h2>
      <p className="mt-1 text-fg-muted">
        Ship a log as it's written with <span className="font-mono text-fg">signal-tail</span>. An
        admin issues the ingest token.
      </p>
    </Panel>
  );
}

function TokensPanel() {
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [created, setCreated] = useState<IngestTokenCreated | null>(null);
  const tokens = useQuery({
    queryKey: ["ingest", "tokens"],
    queryFn: () => api.get<IngestToken[]>("/api/ingest/tokens"),
  });
  const create = useMutation({
    mutationFn: () => api.post<IngestTokenCreated>("/api/ingest/tokens", { name: name.trim() }),
    onSuccess: (t) => {
      setCreated(t);
      setName("");
      void qc.invalidateQueries({ queryKey: ["ingest", "tokens"] });
    },
  });
  const revoke = useMutation({
    mutationFn: (id: number) => api.delete(`/api/ingest/tokens/${id}`),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["ingest", "tokens"] }),
  });

  return (
    <section aria-labelledby="tokens-h">
      <div className="mb-3 flex items-end justify-between gap-4">
        <div>
          <h2 id="tokens-h" className="text-md">
            Live ingest tokens
          </h2>
          <p className="mt-1 text-xs text-fg-muted">
            Bearer tokens for <span className="font-mono">signal-tail</span> and lab forwarders.
            They can only post events. Stored hashed; shown once.
          </p>
        </div>
        <Button
          onClick={() => {
            setCreated(null);
            setCreating(true);
          }}
        >
          <PlusIcon className="size-3.5" /> New token
        </Button>
      </div>
      <Panel className="overflow-x-auto">
        <table className="w-full min-w-[36rem] text-left">
          <thead>
            <tr className="border-b border-border">
              {["Name", "Prefix", "Created", "Last used", "Actions"].map((h) => (
                <th key={h} scope="col" className="label-caps px-4 py-2.5 font-medium">
                  {h === "Actions" ? <span className="sr-only">{h}</span> : h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {(tokens.data ?? []).length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-6 text-center text-fg-muted">
                  No tokens yet.
                </td>
              </tr>
            ) : (
              (tokens.data ?? []).map((t) => (
                <tr
                  key={t.id}
                  className={clsx(
                    "border-b border-border last:border-0",
                    t.revoked_at && "opacity-50",
                  )}
                >
                  <td className="px-4 py-2.5">{t.name}</td>
                  <td className="px-4 py-2.5 font-mono text-xs text-fg-muted">{t.prefix}…</td>
                  <td className="px-4 py-2.5 text-xs text-fg-muted">
                    {formatRelative(t.created_at)}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-fg-muted">
                    {formatRelative(t.last_used_at)}
                  </td>
                  <td className="px-4 py-2.5 text-right">
                    {t.revoked_at ? (
                      <span className="text-xs text-fg-faint">Revoked</span>
                    ) : (
                      <Button
                        size="sm"
                        variant="danger"
                        onClick={() => {
                          revoke.mutate(t.id);
                        }}
                      >
                        Revoke
                      </Button>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </Panel>

      <Dialog
        open={creating}
        onClose={() => {
          setCreating(false);
          setCreated(null);
        }}
        title={created ? "Token created" : "New ingest token"}
      >
        {created ? (
          <div className="flex flex-col gap-4">
            <p className="text-fg-muted">Copy it now. It won't be shown again.</p>
            <code className="rounded-sm border border-border bg-surface-2 px-3 py-2 font-mono text-xs break-all select-all">
              {created.token}
            </code>
            <p className="text-xs text-fg-muted">Then, on the machine with the log:</p>
            <code className="rounded-sm border border-border bg-surface-2 px-3 py-2 font-mono text-2xs break-all text-fg-muted">
              {TAIL_CMD}
            </code>
            <div className="flex justify-end gap-2">
              <Button
                onClick={() => {
                  void navigator.clipboard.writeText(created.token);
                }}
              >
                Copy token
              </Button>
              <Button
                variant="primary"
                onClick={() => {
                  setCreating(false);
                  setCreated(null);
                }}
              >
                Done
              </Button>
            </div>
          </div>
        ) : (
          <form
            className="flex flex-col gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              create.mutate();
            }}
          >
            <Field
              label="Name"
              htmlFor="token-name"
              hint="Where it will run, e.g. lab-wazuh or web01 tail."
            >
              <Input
                id="token-name"
                required
                maxLength={80}
                value={name}
                onChange={(e) => {
                  setName(e.target.value);
                }}
              />
            </Field>
            <div className="flex justify-end gap-2">
              <Button
                onClick={() => {
                  setCreating(false);
                }}
              >
                Cancel
              </Button>
              <Button type="submit" variant="primary" disabled={!name.trim() || create.isPending}>
                Create token
              </Button>
            </div>
          </form>
        )}
      </Dialog>
    </section>
  );
}
