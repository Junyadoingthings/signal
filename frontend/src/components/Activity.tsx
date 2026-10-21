import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type KeyboardEvent } from "react";
import ReactMarkdown, { type Components } from "react-markdown";
import { Button } from "@/components/ui";
import { useDirectory } from "@/features/alerts/triage";
import { api, ApiError } from "@/lib/api";
import { formatRelative, formatTimestamp } from "@/lib/format";
import { modKeyLabel } from "@/lib/hotkeys";
import type { HistoryEntry, Note } from "@/lib/types";

/**
 * Notes are markdown written by analysts, rendered without raw HTML (react-markdown
 * never parses it), without images (no tracking pixels / IP leaks to attacker URLs) and
 * with links forced to open safely in a new tab. Unsafe URL schemes are stripped by
 * react-markdown's default urlTransform.
 */
const MD_COMPONENTS: Components = {
  a: ({ href, children }) => (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer nofollow"
      className="text-accent-fg underline underline-offset-2"
    >
      {children}
    </a>
  ),
  code: ({ children }) => (
    <code className="rounded-xs bg-surface-3 px-1 font-mono text-xs">{children}</code>
  ),
  pre: ({ children }) => (
    <pre className="overflow-x-auto rounded-sm bg-surface-3 p-2 text-xs">{children}</pre>
  ),
  ul: ({ children }) => <ul className="list-disc pl-5">{children}</ul>,
  ol: ({ children }) => <ol className="list-decimal pl-5">{children}</ol>,
};

export function Markdown({ text }: { text: string }) {
  return (
    <div className="flex flex-col gap-2 leading-relaxed [overflow-wrap:anywhere]">
      <ReactMarkdown
        components={MD_COMPONENTS}
        disallowedElements={["img"]}
        unwrapDisallowed
        skipHtml
      >
        {text}
      </ReactMarkdown>
    </div>
  );
}

const ACTION_LABEL: Record<string, string> = {
  "alert.update": "updated",
  "incident.update": "updated",
  "incident.create": "created the incident",
  "incident.merge": "merged another incident into this one",
};

function describe(e: HistoryEntry, names: Map<number, string>): string {
  const label = ACTION_LABEL[e.action ?? ""] ?? e.action ?? "";
  if (!e.before || !e.after) return label;
  const parts: string[] = [];
  for (const k of Object.keys(e.after)) {
    const b = e.before[k];
    const a = e.after[k];
    if (JSON.stringify(a) === JSON.stringify(b)) continue;
    const fmt = (v: unknown): string => {
      if (v === null || v === undefined) return "none";
      if (k === "assignee_id" && typeof v === "number") return names.get(v) ?? `user ${String(v)}`;
      return (typeof v === "string" ? v : JSON.stringify(v)).replaceAll("_", " ");
    };
    parts.push(`${k.replace("_id", "")} ${fmt(b)} → ${fmt(a)}`);
  }
  return parts.join(", ") || label;
}

export function Activity({ target, id }: { target: "alerts" | "incidents"; id: number }) {
  const qc = useQueryClient();
  const key = [target === "alerts" ? "alert" : "incident", id, "history"];
  const history = useQuery({
    queryKey: key,
    queryFn: () => api.get<HistoryEntry[]>(`/api/${target}/${String(id)}/history`),
  });
  const directory = useDirectory();
  const names = new Map((directory.data ?? []).map((u) => [u.id, u.display_name]));
  const [text, setText] = useState("");
  const [preview, setPreview] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: () => api.post<Note>(`/api/${target}/${String(id)}/notes`, { markdown: text }),
    onSuccess: () => {
      setText("");
      setPreview(false);
      setError(null);
      void qc.invalidateQueries({ queryKey: key });
    },
    onError: (e) => {
      setError(e instanceof ApiError ? e.message : "Couldn't save the note.");
    },
  });

  const onKey = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter" && text.trim()) {
      e.preventDefault();
      save.mutate();
    }
  };

  return (
    <section aria-label="Notes and history" className="flex flex-col gap-3">
      <ol className="flex flex-col gap-3">
        {(history.data ?? []).map((e, i) => (
          <li key={i} className="flex gap-3 text-xs">
            <span
              aria-hidden="true"
              className="mt-1.5 size-1.5 shrink-0 rounded-full bg-border-strong"
            />
            <div className="min-w-0 flex-1">
              <p className="text-fg-muted">
                <span className="text-fg">{e.actor ?? "system"}</span>{" "}
                {e.kind === "note" ? "added a note" : describe(e, names)}{" "}
                <time dateTime={e.ts} title={formatTimestamp(e.ts)} className="text-fg-faint">
                  {formatRelative(e.ts)}
                </time>
              </p>
              {e.note ? (
                <div className="mt-1.5 rounded-sm border border-border bg-surface-2 px-3 py-2 text-sm">
                  <Markdown text={e.note.markdown} />
                </div>
              ) : null}
            </div>
          </li>
        ))}
        {history.data?.length === 0 ? (
          <li className="text-xs text-fg-faint">No activity yet.</li>
        ) : null}
      </ol>

      <div className="rounded-sm border border-border bg-surface-1 focus-within:border-accent">
        {preview ? (
          <div className="min-h-20 px-3 py-2 text-sm">
            {text.trim() ? (
              <Markdown text={text} />
            ) : (
              <p className="text-fg-faint">Nothing to preview.</p>
            )}
          </div>
        ) : (
          <textarea
            aria-label="Add a note"
            value={text}
            maxLength={20000}
            onChange={(e) => {
              setText(e.target.value);
            }}
            onKeyDown={onKey}
            placeholder="Add a note (markdown). What did you check? Why this verdict?"
            className="block min-h-20 w-full resize-y bg-transparent px-3 py-2 text-sm outline-none placeholder:text-fg-faint"
          />
        )}
        <div className="flex items-center justify-between border-t border-border px-2 py-1.5">
          <button
            type="button"
            className="text-2xs text-fg-muted hover:text-fg"
            onClick={() => {
              setPreview((p) => !p);
            }}
          >
            {preview ? "Edit" : "Preview"}
          </button>
          <div className="flex items-center gap-2">
            <span className="text-2xs text-fg-faint">{modKeyLabel}+Enter</span>
            <Button
              size="sm"
              disabled={!text.trim() || save.isPending}
              onClick={() => {
                save.mutate();
              }}
            >
              Add note
            </Button>
          </div>
        </div>
      </div>
      {error ? (
        <p role="alert" className="text-xs text-danger">
          {error}
        </p>
      ) : null}
    </section>
  );
}
