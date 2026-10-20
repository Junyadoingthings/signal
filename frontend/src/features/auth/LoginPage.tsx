import { useState, type FormEvent } from "react";
import { Navigate, useLocation } from "react-router";
import { Button, Field, Input, LogoMark } from "@/components/ui";
import { ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";

export function LoginPage() {
  const { user, login } = useAuth();
  const location = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const from = (location.state as { from?: string } | null)?.from ?? "/";
  if (user) return <Navigate to={from} replace />;

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(email, password);
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.status === 429
            ? "Too many attempts. Wait a minute and try again."
            : err.status === 401
              ? "Invalid email or password."
              : err.message
          : "Couldn't reach the server.",
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="canvas-grid relative flex min-h-full flex-col items-center justify-center px-4 py-12">
      <FlatTrace />
      <main className="relative w-full max-w-[22rem]">
        <div className="mb-8 flex items-center gap-2.5">
          <LogoMark className="size-7" />
          <span className="text-lg font-semibold tracking-[var(--tracking-tighter)]">signal</span>
        </div>
        <h1 className="text-2xl tracking-[var(--tracking-tighter)]">Sign in</h1>
        <p className="mt-1.5 mb-7 text-fg-muted">Detection console. Authorised analysts only.</p>

        <form onSubmit={(e) => void onSubmit(e)} className="flex flex-col gap-4" noValidate>
          <Field label="Email" htmlFor="email">
            <Input
              id="email"
              type="email"
              autoComplete="username"
              required
              value={email}
              onChange={(e) => {
                setEmail(e.target.value);
              }}
              aria-invalid={error ? true : undefined}
            />
          </Field>
          <Field label="Password" htmlFor="password">
            <Input
              id="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
              }}
              aria-invalid={error ? true : undefined}
            />
          </Field>
          {error ? (
            <p role="alert" className="text-xs text-danger">
              {error}
            </p>
          ) : null}
          <Button
            type="submit"
            variant="primary"
            className="mt-2 h-9"
            disabled={busy || !email || !password}
          >
            {busy ? "Signing in…" : "Sign in"}
          </Button>
        </form>
      </main>
    </div>
  );
}

/** Decorative baseline across the page: the instrument at rest. */
function FlatTrace() {
  return (
    <svg
      aria-hidden="true"
      className="pointer-events-none absolute inset-x-0 bottom-[12%] h-24 w-full text-border-strong"
      preserveAspectRatio="none"
      viewBox="0 0 1000 100"
    >
      <path
        d="M0 50 H430 l8 -3 6 6 5 -10 6 16 5 -9 6 2 4 -2 H1000"
        fill="none"
        stroke="currentColor"
        strokeWidth="1"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}
