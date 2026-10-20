import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

export type ThemePref = "system" | "dark" | "light";
type Resolved = "dark" | "light";

const STORAGE_KEY = "signal.theme";

function readPref(): ThemePref {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    return v === "dark" || v === "light" || v === "system" ? v : "system";
  } catch {
    return "system";
  }
}

function systemTheme(): Resolved {
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

interface ThemeState {
  pref: ThemePref;
  resolved: Resolved;
  setPref: (p: ThemePref) => void;
  toggle: () => void;
}

const ThemeContext = createContext<ThemeState | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [pref, setPrefState] = useState<ThemePref>(readPref);
  const [system, setSystem] = useState<Resolved>(systemTheme);

  useEffect(() => {
    const mq = window.matchMedia("(prefers-color-scheme: light)");
    const onChange = () => {
      setSystem(mq.matches ? "light" : "dark");
    };
    mq.addEventListener("change", onChange);
    return () => {
      mq.removeEventListener("change", onChange);
    };
  }, []);

  const resolved: Resolved = pref === "system" ? system : pref;

  useEffect(() => {
    const root = document.documentElement;
    if (pref === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", pref);
  }, [pref]);

  const setPref = useCallback((p: ThemePref) => {
    setPrefState(p);
    try {
      localStorage.setItem(STORAGE_KEY, p);
    } catch {
      /* storage unavailable: preference lasts for this tab only */
    }
  }, []);

  const toggle = useCallback(() => {
    setPref(resolved === "dark" ? "light" : "dark");
  }, [resolved, setPref]);

  const value = useMemo(
    () => ({ pref, resolved, setPref, toggle }),
    [pref, resolved, setPref, toggle],
  );
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeState {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme must be used inside <ThemeProvider>");
  return ctx;
}
