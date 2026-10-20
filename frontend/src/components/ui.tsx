import { clsx } from "clsx";
import {
  forwardRef,
  useEffect,
  useRef,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
} from "react";
import type { Severity } from "@/lib/types";

/* ------------------------------------------------------------------ logo */

/** A flat trace with one deflection: the product in one glyph. */
export function LogoMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true" className={className}>
      <path
        d="M2 13h6l2-6 3.2 11L15.4 9 17 13h5"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="13.2" cy="18" r="1.6" fill="var(--accent)" />
    </svg>
  );
}

/* ------------------------------------------------------------------ button */

type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";
type ButtonSize = "sm" | "md";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
}

const buttonBase =
  "inline-flex items-center justify-center gap-2 rounded-sm font-medium whitespace-nowrap " +
  "transition-[background-color,border-color,color,opacity] duration-[var(--dur-fast)] ease-out " +
  "disabled:opacity-50 disabled:pointer-events-none select-none";

const buttonVariants: Record<ButtonVariant, string> = {
  // Primary is high-contrast neutral, not accent: amber stays reserved for attention.
  primary: "bg-fg text-fg-inverse hover:opacity-90",
  secondary:
    "bg-surface-2 text-fg border border-border hover:border-border-strong hover:bg-surface-3",
  ghost: "text-fg-muted hover:text-fg hover:bg-surface-2",
  danger: "bg-surface-2 text-danger border border-border hover:border-danger",
};

const buttonSizes: Record<ButtonSize, string> = {
  sm: "h-7 px-2.5 text-xs",
  md: "h-8 px-3 text-sm",
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "secondary", size = "md", className, type = "button", ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      className={clsx(buttonBase, buttonVariants[variant], buttonSizes[size], className)}
      {...rest}
    />
  );
});

/* ------------------------------------------------------------------ inputs */

const fieldBase =
  "w-full h-8 rounded-sm bg-surface-1 border border-border px-2.5 text-sm text-fg " +
  "placeholder:text-fg-faint transition-colors duration-[var(--dur-fast)] " +
  "hover:border-border-strong focus:border-accent focus-visible:outline-none aria-invalid:border-danger";

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  function Input({ className, ...rest }, ref) {
    return <input ref={ref} className={clsx(fieldBase, className)} {...rest} />;
  },
);

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(
  function Select({ className, ...rest }, ref) {
    return <select ref={ref} className={clsx(fieldBase, "pr-7", className)} {...rest} />;
  },
);

export function Field({
  label,
  htmlFor,
  hint,
  error,
  children,
}: {
  label: string;
  htmlFor: string;
  hint?: string;
  error?: string | null;
  children: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={htmlFor} className="text-xs font-medium text-fg-muted">
        {label}
      </label>
      {children}
      {error ? (
        <p role="alert" className="text-xs text-danger">
          {error}
        </p>
      ) : hint ? (
        <p className="text-xs text-fg-faint">{hint}</p>
      ) : null}
    </div>
  );
}

/* ------------------------------------------------------------------ kbd */

export function Kbd({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <kbd
      className={clsx(
        "inline-flex h-5 min-w-5 items-center justify-center rounded-xs border border-border",
        "bg-surface-2 px-1 text-2xs leading-none text-fg-muted",
        className,
      )}
    >
      {children}
    </kbd>
  );
}

/* ------------------------------------------------------------------ severity */

const SEV_META: Record<Severity, { label: string; glyph: ReactNode; cls: string }> = {
  // Glyph shape climbs with severity so meaning never depends on colour alone.
  low: {
    label: "Low",
    cls: "text-sev-low bg-[var(--sev-low-soft)]",
    glyph: <circle cx="5" cy="5" r="3.25" fill="none" stroke="currentColor" strokeWidth="1.5" />,
  },
  medium: {
    label: "Medium",
    cls: "text-sev-medium bg-[var(--sev-medium-soft)]",
    glyph: <path d="M5 1.5 8.5 5 5 8.5 1.5 5Z" fill="currentColor" />,
  },
  high: {
    label: "High",
    cls: "text-sev-high bg-[var(--sev-high-soft)]",
    glyph: <path d="M5 1.25 9 8.5H1Z" fill="currentColor" />,
  },
  critical: {
    label: "Critical",
    cls: "text-sev-critical bg-[var(--sev-critical-soft)]",
    glyph: <rect x="1.25" y="1.25" width="7.5" height="7.5" rx="1" fill="currentColor" />,
  },
};

export function SeverityBadge({
  severity,
  breathing = false,
  compact = false,
}: {
  severity: Severity;
  /** Only for unacknowledged critical items. */
  breathing?: boolean;
  compact?: boolean;
}) {
  const m = SEV_META[severity];
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1.5 rounded-xs px-1.5 py-0.5 text-2xs font-medium",
        "tracking-[var(--tracking-caps)] uppercase",
        m.cls,
        breathing && severity === "critical" && "sev-breathing",
      )}
    >
      <svg viewBox="0 0 10 10" className="size-2.5 shrink-0" aria-hidden="true">
        {m.glyph}
      </svg>
      {compact ? <span className="sr-only">{m.label}</span> : m.label}
    </span>
  );
}

/* ------------------------------------------------------------------ dialog */

/** Native <dialog>: focus trapping, Esc to close and inert background for free. */
export function Dialog({
  open,
  onClose,
  title,
  children,
  className,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  className?: string;
}) {
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (open && !el.open) el.showModal();
    if (!open && el.open) el.close();
  }, [open]);

  return (
    <dialog
      ref={ref}
      onClose={onClose}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
      aria-label={title}
      className={clsx(
        "dialog-pop m-auto w-[min(92vw,30rem)] rounded-md border border-border bg-surface-1 p-0 text-fg",
        "shadow-pop backdrop:bg-overlay",
        className,
      )}
    >
      {open ? (
        <div className="flex flex-col">
          <header className="flex items-center justify-between border-b border-border px-5 py-3.5">
            <h2 className="text-md">{title}</h2>
            <button
              type="button"
              onClick={onClose}
              className="rounded-xs p-1 text-fg-muted hover:text-fg"
              aria-label="Close"
            >
              <svg viewBox="0 0 16 16" className="size-4" aria-hidden="true">
                <path
                  d="M4 4l8 8M12 4l-8 8"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                />
              </svg>
            </button>
          </header>
          <div className="p-5">{children}</div>
        </div>
      ) : null}
    </dialog>
  );
}

/* ------------------------------------------------------------------ misc */

export function Panel({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <section className={clsx("rounded-md border border-border bg-surface-1", className)}>
      {children}
    </section>
  );
}

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4 pb-6">
      <div>
        <h1 className="text-xl tracking-[var(--tracking-tighter)]">{title}</h1>
        {description ? <p className="mt-1 text-fg-muted">{description}</p> : null}
      </div>
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </div>
  );
}
