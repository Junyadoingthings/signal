/** Single-pass, bounded log tokenizer used by <RawLog>. Produces plain strings only. */

export type Kind = "ts" | "ip" | "str" | "key" | "num" | "punct" | "text";

const MAX_CHARS = 20_000;

const TOKEN = new RegExp(
  [
    // ISO-ish timestamps and syslog "Oct 20 03:14:07"
    String.raw`(?<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\b[A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2}\b|\[\d{2}\/[A-Z][a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\])`,
    // IPv4, and IPv6 with at least two colons
    String.raw`(?<ip>\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}\b)`,
    // "quoted strings" with escapes
    String.raw`(?<str>"(?:[^"\\]|\\.)*")`,
    // key= / "key": / Name="…" style keys
    String.raw`(?<key>\b[A-Za-z_][\w.-]*(?==)|(?<=[{,]\s*)"[\w.$#@-]+"(?=\s*:))`,
    String.raw`(?<num>\b\d+\b)`,
    String.raw`(?<punct>[{}[\]<>])`,
  ].join("|"),
  "g",
);

export interface Token {
  kind: Kind;
  text: string;
}

export function tokenize(input: string): Token[] {
  const s = input.length > MAX_CHARS ? input.slice(0, MAX_CHARS) : input;
  const out: Token[] = [];
  let last = 0;
  for (const m of s.matchAll(TOKEN)) {
    const idx = m.index;
    if (idx > last) out.push({ kind: "text", text: s.slice(last, idx) });
    const groups = m.groups ?? {};
    const kind = (Object.keys(groups).find((k) => groups[k] !== undefined) ?? "text") as Kind;
    out.push({ kind, text: m[0] });
    last = idx + m[0].length;
  }
  if (last < s.length) out.push({ kind: "text", text: s.slice(last) });
  if (input.length > MAX_CHARS) {
    out.push({ kind: "punct", text: ` … (${input.length - MAX_CHARS} more characters)` });
  }
  return out;
}
