import { clsx } from "clsx";

export function Toggle({
  checked,
  onChange,
  label,
  disabled,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={(e) => {
        e.stopPropagation();
        onChange(!checked);
      }}
      className={clsx(
        "relative inline-flex h-4.5 w-8 shrink-0 items-center rounded-full border transition-colors duration-[var(--dur-fast)]",
        checked ? "border-fg bg-fg" : "border-border-strong bg-surface-2",
        disabled && "opacity-50",
      )}
    >
      <span
        aria-hidden="true"
        className={clsx(
          "absolute size-3 rounded-full transition-transform duration-[var(--dur-fast)] ease-out",
          checked ? "translate-x-[0.9rem] bg-fg-inverse" : "translate-x-0.5 bg-fg-faint",
        )}
      />
    </button>
  );
}
