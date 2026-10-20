import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Me, SystemStatus } from "@/lib/types";
import { makeQueryClient, Providers, routes } from "./App";

const status: SystemStatus = {
  events_total: 0,
  events_last_24h: 0,
  unparsed_total: 0,
  alerts_open: 0,
  incidents_open: 0,
  rules_enabled: 0,
  last_event_at: null,
  last_ingest_at: null,
};

function me(role: "admin" | "analyst"): Me {
  return {
    csrf_token: "csrf-123",
    session_expires_at: new Date(Date.now() + 3600_000).toISOString(),
    user: {
      id: 1,
      email: `${role}@signal.test`,
      display_name: role === "admin" ? "Ada Admin" : "Ana Lyst",
      role,
      is_active: true,
      created_at: new Date().toISOString(),
      last_login_at: null,
    },
  };
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function mockApi(session: Me | null) {
  const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url === "/api/auth/session") return Promise.resolve(json(session));
    if (url === "/api/auth/login") {
      const body = JSON.parse(typeof init?.body === "string" ? init.body : "{}") as {
        password: string;
      };
      return Promise.resolve(
        body.password === "right password!"
          ? json(me("admin"))
          : json(
              { error: { code: "invalid_credentials", message: "Invalid email or password" } },
              401,
            ),
      );
    }
    if (url === "/api/system/status") return Promise.resolve(json(status));
    return Promise.resolve(json({ error: { code: "not_found", message: "nope" } }, 404));
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function renderAt(path: string) {
  const router = createMemoryRouter(routes, { initialEntries: [path] });
  render(
    <Providers client={makeQueryClient()}>
      <RouterProvider router={router} />
    </Providers>,
  );
  return router;
}

beforeEach(() => {
  document.documentElement.removeAttribute("data-theme");
  localStorage.clear();
});

describe("auth gate", () => {
  it("redirects anonymous users to login and shows a generic error on bad credentials", async () => {
    mockApi(null);
    const router = renderAt("/");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/login");

    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Email"), "admin@signal.test");
    await user.type(screen.getByLabelText("Password"), "wrong");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid email or password.");
  });

  it("logs in and lands on the overview with real (zero) counts", async () => {
    mockApi(null);
    renderAt("/login");
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Email"), "admin@signal.test");
    await user.type(screen.getByLabelText("Password"), "right password!");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("heading", { name: "Overview" })).toBeInTheDocument();
    expect(await screen.findByText("All quiet.")).toBeInTheDocument();
  });
});

describe("shell", () => {
  it("opens the command palette with mod+K and navigates", async () => {
    mockApi(me("admin"));
    const router = renderAt("/");
    await screen.findByRole("heading", { name: "Overview" });

    const user = userEvent.setup();
    await user.keyboard("{Control>}k{/Control}");
    const input = await screen.findByPlaceholderText("Jump to a page or run a command…");
    await user.type(input, "audit");
    await user.keyboard("{Enter}");
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/admin/audit");
    });
  });

  it("hides admin pages from analysts in nav and palette", async () => {
    mockApi(me("analyst"));
    renderAt("/");
    await screen.findByRole("heading", { name: "Overview" });
    expect(screen.queryByRole("link", { name: "Users" })).not.toBeInTheDocument();

    const user = userEvent.setup();
    await user.keyboard("{Control>}k{/Control}");
    await screen.findByPlaceholderText("Jump to a page or run a command…");
    expect(screen.queryByRole("option", { name: /Users/ })).not.toBeInTheDocument();
    expect(screen.getByRole("option", { name: /Overview/ })).toBeInTheDocument();
  });

  it("toggles the theme and remembers it", async () => {
    mockApi(me("admin"));
    renderAt("/");
    await screen.findByRole("heading", { name: "Overview" });
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Switch to light theme" }));
    expect(document.documentElement).toHaveAttribute("data-theme", "light");
    expect(localStorage.getItem("signal.theme")).toBe("light");
  });

  it("opens the shortcut sheet with ?", async () => {
    mockApi(me("admin"));
    renderAt("/");
    await screen.findByRole("heading", { name: "Overview" });
    const user = userEvent.setup();
    await user.keyboard("?");
    expect(await screen.findByText("Open command palette")).toBeInTheDocument();
  });
});
