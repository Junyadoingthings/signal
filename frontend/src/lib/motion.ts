import { useEffect, useRef, useState } from "react";

export function prefersReducedMotion(): boolean {
  return (
    typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches
  );
}

/** Eases a displayed number towards its target (200–300ms, ease-out). Instant when the
 * user prefers reduced motion. */
export function useTween(target: number, ms = 280): number {
  const [shown, setShown] = useState(target);
  const from = useRef(target);
  useEffect(() => {
    if (prefersReducedMotion() || from.current === target) {
      from.current = target;
      setShown(target);
      return;
    }
    const start = performance.now();
    const a = from.current;
    let raf = 0;
    const step = (now: number) => {
      const t = Math.min(1, (now - start) / ms);
      const eased = 1 - (1 - t) ** 3;
      from.current = a + (target - a) * eased;
      setShown(from.current);
      if (t < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => {
      cancelAnimationFrame(raf);
    };
  }, [target, ms]);
  return Math.round(shown);
}
