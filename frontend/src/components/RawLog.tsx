import { clsx } from "clsx";
import { useMemo } from "react";
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

export function RawLog({
  raw,
  className,
  wrap = true,
}: {
  raw: string;
  className?: string;
  wrap?: boolean;
}) {
  const tokens = useMemo(() => tokenize(raw), [raw]);
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
            t.text
          ) : (
            <span key={i} className={KIND_CLASS[t.kind]}>
              {t.text}
            </span>
          ),
        )}
      </code>
    </pre>
  );
}
