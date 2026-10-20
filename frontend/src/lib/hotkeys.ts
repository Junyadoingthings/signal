import { useEffect, useLayoutEffect, useRef } from "react";

/** True when the user is typing, so single-letter shortcuts must not fire. */
export function isTypingTarget(el: EventTarget | null): boolean {
  if (!(el instanceof HTMLElement)) return false;
  const tag = el.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || el.isContentEditable;
}

export const isMac =
  typeof navigator !== "undefined" &&
  /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);

export const modKeyLabel = isMac ? "⌘" : "Ctrl";

interface HotkeyOptions {
  /** Require ⌘ on macOS / Ctrl elsewhere. */
  mod?: boolean;
  shift?: boolean;
  /** Fire even while focus is in a text field (only sensible with `mod`). */
  allowInInputs?: boolean;
  enabled?: boolean;
}

/**
 * Registers a global keyboard shortcut. `key` is compared case-insensitively against
 * KeyboardEvent.key (e.g. "k", "?", "Escape").
 */
export function useHotkey(
  key: string,
  handler: (e: KeyboardEvent) => void,
  opts: HotkeyOptions = {},
) {
  const ref = useRef(handler);
  useLayoutEffect(() => {
    ref.current = handler;
  });
  const { mod = false, shift, allowInInputs = false, enabled = true } = opts;

  useEffect(() => {
    if (!enabled) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key.toLowerCase() !== key.toLowerCase()) return;
      const modDown = isMac ? e.metaKey : e.ctrlKey;
      if (mod !== modDown) return;
      if (!mod && (e.metaKey || e.ctrlKey || e.altKey)) return;
      if (shift !== undefined && shift !== e.shiftKey) return;
      if (!allowInInputs && isTypingTarget(e.target)) return;
      e.preventDefault();
      ref.current(e);
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
    };
  }, [key, mod, shift, allowInInputs, enabled]);
}
