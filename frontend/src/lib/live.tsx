import { useQueryClient } from "@tanstack/react-query";
import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

/**
 * One WebSocket per tab to /ws. Server pushes small "something changed" messages; we
 * invalidate the matching queries and remember which alerts are brand new so the queue
 * can pulse them. Reconnects with capped exponential backoff.
 */

interface LiveState {
  connected: boolean;
  /** Alert ids that arrived in this session, newest last, with arrival time. */
  fresh: ReadonlyMap<number, number>;
}

const LiveContext = createContext<LiveState>({ connected: false, fresh: new Map() });

const FRESH_MS = 8000;

type Message =
  | { type: "hello" | "ping" }
  | { type: "alerts"; ids: number[]; incidents: number[] }
  | { type: "alerts_updated"; ids: number[] }
  | { type: "incidents_updated"; ids: number[] }
  | { type: "events"; count: number; at: string };

export function LiveProvider({ children, enabled }: { children: ReactNode; enabled: boolean }) {
  const qc = useQueryClient();
  const [connected, setConnected] = useState(false);
  const [fresh, setFresh] = useState<Map<number, number>>(new Map());
  const statusTimer = useRef<number | null>(null);

  useEffect(() => {
    if (!enabled || typeof WebSocket === "undefined") return;
    let ws: WebSocket | null = null;
    let retry = 0;
    let stopped = false;
    let reconnect: number | null = null;

    const refreshStatusSoon = () => {
      if (statusTimer.current !== null) return;
      statusTimer.current = window.setTimeout(() => {
        statusTimer.current = null;
        void qc.invalidateQueries({ queryKey: ["system"] });
        void qc.invalidateQueries({ queryKey: ["overview"] });
      }, 1000);
    };

    const onMessage = (raw: MessageEvent<string>) => {
      let msg: Message;
      try {
        msg = JSON.parse(raw.data) as Message;
      } catch {
        return;
      }
      switch (msg.type) {
        case "alerts": {
          const now = Date.now();
          setFresh((prev) => {
            const next = new Map([...prev].filter(([, t]) => now - t < FRESH_MS));
            for (const id of msg.ids) if (!next.has(id)) next.set(id, now);
            return next;
          });
          void qc.invalidateQueries({ queryKey: ["alerts"] });
          void qc.invalidateQueries({ queryKey: ["incidents"] });
          void qc.invalidateQueries({ queryKey: ["rules"] });
          refreshStatusSoon();
          break;
        }
        case "alerts_updated":
          void qc.invalidateQueries({ queryKey: ["alerts"] });
          void qc.invalidateQueries({ queryKey: ["incidents"] });
          refreshStatusSoon();
          break;
        case "incidents_updated":
          void qc.invalidateQueries({ queryKey: ["incidents"] });
          break;
        case "events":
          refreshStatusSoon();
          break;
        default:
          break;
      }
    };

    const connect = () => {
      const proto = window.location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${window.location.host}/ws`);
      ws.onopen = () => {
        retry = 0;
        setConnected(true);
      };
      ws.onmessage = onMessage;
      ws.onclose = () => {
        setConnected(false);
        if (stopped) return;
        const delay = Math.min(30_000, 1000 * 2 ** retry++);
        reconnect = window.setTimeout(connect, delay);
      };
    };
    connect();
    return () => {
      stopped = true;
      if (reconnect !== null) window.clearTimeout(reconnect);
      ws?.close();
    };
  }, [enabled, qc]);

  const value = useMemo(() => ({ connected, fresh }), [connected, fresh]);
  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>;
}

export function useLive(): LiveState {
  return useContext(LiveContext);
}

export function isFresh(fresh: ReadonlyMap<number, number>, id: number): boolean {
  const t = fresh.get(id);
  return t !== undefined && Date.now() - t < FRESH_MS;
}
