import { Link } from "react-router";

export function NotFound() {
  return (
    <div className="mx-auto flex max-w-md flex-col items-start gap-3 pt-16">
      <p className="font-mono text-xs text-fg-faint">404</p>
      <h1 className="text-xl tracking-[var(--tracking-tighter)]">Nothing on this frequency.</h1>
      <p className="text-fg-muted">The page doesn't exist, or your role can't see it.</p>
      <Link to="/" className="text-accent-fg underline-offset-4 hover:underline">
        Back to overview
      </Link>
    </div>
  );
}
