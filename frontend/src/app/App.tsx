import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import { createBrowserRouter, Navigate, Outlet, RouterProvider, useLocation } from "react-router";
import { AuditPage } from "@/features/admin/AuditPage";
import { UsersPage } from "@/features/admin/UsersPage";
import { LoginPage } from "@/features/auth/LoginPage";
import { OverviewPage } from "@/features/overview/OverviewPage";
import { ApiError } from "@/lib/api";
import { AuthProvider, useAuth } from "@/lib/auth";
import { ThemeProvider } from "@/lib/theme";
import type { Role } from "@/lib/types";
import { NotFound } from "./NotFound";
import { Shell } from "./Shell";

function RequireAuth() {
  const { user, loading } = useAuth();
  const location = useLocation();
  if (loading) return <BootScreen />;
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return <Outlet />;
}

function RequireRole({ role, children }: { role: Role; children: ReactNode }) {
  const { user } = useAuth();
  // Cosmetic only: the API enforces roles. This just avoids showing a page of 403s.
  if (user?.role !== role) return <NotFound />;
  return <>{children}</>;
}

function BootScreen() {
  return (
    <div className="grid h-full place-items-center" aria-busy="true" aria-label="Loading">
      <div className="skeleton h-px w-40" />
    </div>
  );
}

export const routes = [
  { path: "/login", element: <LoginPage /> },
  {
    element: <RequireAuth />,
    children: [
      {
        element: <Shell />,
        children: [
          { index: true, element: <OverviewPage /> },
          {
            path: "admin/users",
            element: (
              <RequireRole role="admin">
                <UsersPage />
              </RequireRole>
            ),
          },
          {
            path: "admin/audit",
            element: (
              <RequireRole role="admin">
                <AuditPage />
              </RequireRole>
            ),
          },
          { path: "*", element: <NotFound /> },
        ],
      },
    ],
  },
];

export function makeQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: (count, err) => !(err instanceof ApiError && err.status < 500) && count < 2,
        refetchOnWindowFocus: false,
      },
    },
  });
}

export function Providers({ client, children }: { client: QueryClient; children: ReactNode }) {
  return (
    <QueryClientProvider client={client}>
      <ThemeProvider>
        <AuthProvider>{children}</AuthProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export function App() {
  const [client] = useState(makeQueryClient);
  const [router] = useState(() => createBrowserRouter(routes));
  return (
    <Providers client={client}>
      <RouterProvider router={router} />
    </Providers>
  );
}
