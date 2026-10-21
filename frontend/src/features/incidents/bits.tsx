import { clsx } from "clsx";

export function ScoreBar({ score }: { score: number }) {
  return (
    <span className="inline-flex items-center gap-2" title={`Score ${String(score)} / 100`}>
      <span className="font-mono text-sm tabular">{score}</span>
      <span aria-hidden="true" className="h-1 w-12 overflow-hidden rounded-full bg-surface-3">
        <span
          className={clsx("block h-full rounded-full", score >= 80 ? "bg-accent" : "bg-fg-muted")}
          style={{ width: `${String(score)}%` }}
        />
      </span>
    </span>
  );
}

export function TacticChain({ tactics, names }: { tactics: string[]; names: Map<string, string> }) {
  return (
    <span className="flex flex-wrap items-center gap-1 text-2xs text-fg-muted">
      {tactics.map((t, i) => (
        <span key={t} className="inline-flex items-center gap-1">
          {i > 0 ? (
            <span aria-hidden="true" className="text-fg-faint">
              →
            </span>
          ) : null}
          <span className="rounded-xs border border-border px-1.5 py-0.5">{names.get(t) ?? t}</span>
        </span>
      ))}
    </span>
  );
}
