import { clsx } from "clsx";
import { Fragment, useMemo, type ReactNode } from "react";
import { tokenize, type Kind } from "./tokenize";

/**
 * Syntax highlighting for raw, attacker-controlled log records.
 *
 * Security: this only ever produces React text nodes inside <span>s. There is no HTML
 * parsing and no dangerouslySetInnerHTML, so a log line like `<img onerror=…>` renders
 * as the literal characters. Tokenising is a single regex pass with bounded input.
 */

const KIND_CLASS: Record<Kind, string> = {
  ts: "text-fg-muted",
  ip: "text-accent-fg",
  str: "text-[color:var(--sev-medium)]",
  key: "text-fg-muted",
  num: "text-fg",
  punct: "text-fg-faint",
  text: "text-fg",
};

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Splits text on highlight terms (case-insensitive) and wraps them in <mark>. */
function marked(text: string, rx: RegExp | null, keyPrefix: string): ReactNode {
  if (!rx) return text;
  const parts = text.split(rx);
  if (parts.length === 1) return text;
  return parts.map((p, i) =>
    i % 2 === 1 ? (
      <mark
        key={`${keyPrefix}-${String(i)}`}
        className="rounded-xs bg-accent-soft text-accent-fg ring-1 ring-accent/40"
      >
        {p}
      </mark>
    ) : (
      p
    ),
  );
}

export function RawLog({
  raw,
  className,
  wrap = true,
  highlight = [],
}: {
  raw: string;
  className?: string;
  wrap?: boolean;
  /** Literal substrings to mark (e.g. the values that made a rule fire). */
  highlight?: string[];
}) {
  const tokens = useMemo(() => tokenize(raw), [raw]);
  const rx = useMemo(() => {
    const terms = [...new Set(highlight.filter((h) => h.length >= 2))].sort(
      (a, b) => b.length - a.length,
    );
    return terms.length ? new RegExp(`(${terms.map(escapeRegex).join("|")})`, "gi") : null;
  }, [highlight]);
  return (
    <pre
      className={clsx(
        "font-mono text-xs leading-relaxed",
        wrap ? "break-all whitespace-pre-wrap" : "overflow-x-auto whitespace-pre",
        className,
      )}
    >
      <code>
        {tokens.map((t, i) =>
          t.kind === "text" ? (
            <Fragment key={i}>{marked(t.text, rx, String(i))}</Fragment>
          ) : (
            <span key={i} className={KIND_CLASS[t.kind]}>
              {marked(t.text, rx, String(i))}
            </span>
          ),
        )}
      </code>
    </pre>
  );
}
