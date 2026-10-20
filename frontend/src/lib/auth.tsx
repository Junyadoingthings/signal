import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useMemo, type ReactNode } from "react";
import { api, setCsrfToken, setUnauthenticatedHandler } from "./api";
import type { Me, User } from "./types";

interface AuthState {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);
const ME_KEY = ["auth", "me"] as const;

function fetchMe(): Promise<Me | null> {
  return api.get<Me | null>("/api/auth/session");
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const me = useQuery({ queryKey: ME_KEY, queryFn: fetchMe, staleTime: 60_000, retry: false });

  useEffect(() => {
    setCsrfToken(me.data?.csrf_token ?? null);
  }, [me.data]);

  useEffect(() => {
    setUnauthenticatedHandler(() => {
      setCsrfToken(null);
      qc.setQueryData(ME_KEY, null);
    });
    return () => {
      setUnauthenticatedHandler(null);
    };
  }, [qc]);

  const login = useCallback(
    async (email: string, password: string) => {
      const data = await api.post<Me>("/api/auth/login", { email, password });
      setCsrfToken(data.csrf_token);
      qc.setQueryData(ME_KEY, data);
    },
    [qc],
  );

  const logout = useCallback(async () => {
    try {
      await api.post("/api/auth/logout");
    } finally {
      setCsrfToken(null);
      qc.clear();
      qc.setQueryData(ME_KEY, null);
    }
  }, [qc]);

  const value = useMemo<AuthState>(
    () => ({ user: me.data?.user ?? null, loading: me.isPending, login, logout }),
    [me.data, me.isPending, login, logout],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}
