import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { makeQueryClient, Providers, routes } from "@/app/App";
import type { AlertDetail, AlertRow, Me } from "@/lib/types";

// jsdom has no layout, so a real virtualizer renders nothing. These tests cover keyboard
// and triage behaviour; windowing itself is exercised in the browser.
vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: ({ count, estimateSize }: { count: number; estimateSize: () => number }) => ({
    getVirtualItems: () =>
      Array.from({ length: count }, (_, i) => ({
        index: i,
        start: i * estimateSize(),
        key: i,
        size: estimateSize(),
      })),
    getTotalSize: () => count * estimateSize(),
    scrollToIndex: () => undefined,
  }),
}));

const me: Me = {
  csrf_token: "csrf-q",
  session_expires_at: new Date(Date.now() + 3600_000).toISOString(),
  user: {
    id: 7,
    email: "ana@signal.test",
    display_name: "Ana",
    role: "analyst",
    is_active: true,
    created_at: new Date().toISOString(),
    last_login_at: null,
  },
};

function row(id: number, over: Partial<AlertRow> = {}): AlertRow {
  const now = new Date().toISOString();
  return {
    id,
    rule_id: "sig-auth-brute-force",
    rule_title: `Alert number ${String(id)}`,
    tactic: "credential-access",
    severity: "high",
    status: "new",
    verdict: null,
    host: "web01",
    user: "root",
    src_ip: "203.0.113.50",
    group_key: "src_ip=203.0.113.50",
    event_count: 12,
    first_event_at: now,
    last_event_at: now,
    created_at: now,
    match_context: {
      type: "threshold",
      count: 12,
      threshold: 8,
      window: "5m",
      group: { src_ip: "203.0.113.50" },
      matched: [{ field: "src_ip", op: "re", expected: "x", actual: "203.0.113.50" }],
    },
    incident_id: null,
    assignee_id: null,
    assignee_name: null,
    acknowledged_at: null,
    closed_at: null,
    ...over,
  };
}

const rows = [row(1), row(2, { severity: "critical" }), row(3)];

function detail(id: number): AlertDetail {
  const a = rows.find((r) => r.id === id) ?? row(id);
  return {
    alert: a,
    rule: {
      id: a.rule_id,
      title: a.rule_title,
      description: "Many failed logons.",
      severity: a.severity,
      logic_type: "threshold",
      primary_tactic: "credential-access",
      techniques: [
        {
          id: "T1110.001",
          name: "Password Guessing",
          url: "https://attack.mitre.org/techniques/T1110/001/",
        },
      ],
      false_positives: ["Expired password retries"],
    },
    events: [
      {
        id: 99,
        timestamp: a.first_event_at,
        ingested_at: a.first_event_at,
        batch_id: 1,
        source_type: "linux_auth",
        host: "web01",
        user: "root",
        src_ip: "203.0.113.50",
        dst_ip: null,
        src_port: 22,
        dst_port: null,
        process_name: "sshd",
        process_cmdline: null,
        parent_process: null,
        event_code: null,
        action: "ssh_login",
        outcome: "failure",
        dns_query: null,
        url: null,
        http_status: null,
        user_agent: null,
        raw: "Oct 20 02:00:00 web01 sshd[1]: Failed password for root from 203.0.113.50 port 22 ssh2 <img src=x onerror=alert(1)>",
        tags: [],
        extra: {},
      },
    ],
    events_total: 12,
  };
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const calls: { method: string; url: string; body: unknown }[] = [];

beforeEach(() => {
  calls.length = 0;

  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      const method = init?.method ?? "GET";
      const body: unknown = typeof init?.body === "string" ? JSON.parse(init.body) : null;
      calls.push({ method, url, body });
      if (url === "/api/auth/session") return Promise.resolve(json(me));
      if (url.startsWith("/api/alerts?"))
        return Promise.resolve(json({ items: rows, total: 3, offset: 0, limit: 100 }));
      if (url === "/api/alerts/bulk")
        return Promise.resolve(json({ updated: (body as { ids: number[] }).ids, errors: {} }));
      const m = /^\/api\/alerts\/(\d+)(\/history)?/.exec(url.split("?")[0] ?? "");
      if (m && m[2]) return Promise.resolve(json([]));
      if (m && method === "PATCH")
        return Promise.resolve(json({ ...row(Number(m[1])), ...(body as object) }));
      if (m) return Promise.resolve(json(detail(Number(m[1]))));
      if (url === "/api/users/directory")
        return Promise.resolve(json([{ id: 7, display_name: "Ana", role: "analyst" }]));
      return Promise.resolve(json({ error: { code: "not_found", message: "x" } }, 404));
    }),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
});

function renderQueue() {
  const router = createMemoryRouter(routes, { initialEntries: ["/alerts"] });
  render(
    <Providers client={makeQueryClient()}>
      <RouterProvider router={router} />
    </Providers>,
  );
  return router;
}

describe("alert queue", () => {
  it("navigates with j/k and opens the inspector with Enter", async () => {
    const router = renderQueue();
    await screen.findByText("Alert number 1");
    const user = userEvent.setup();
    await user.keyboard("j");
    await user.keyboard("{Enter}");
    await waitFor(() => {
      expect(router.state.location.search).toContain("alert=2");
    });
    const inspector = await screen.findByRole("complementary", { name: "Alert 2" });
    expect(await within(inspector).findByText("Password Guessing")).toBeInTheDocument();
    // Raw log is rendered as text and the matched IP is highlighted.
    expect(inspector.querySelector("img")).toBeNull();
    expect(
      within(inspector)
        .getAllByText("203.0.113.50")
        .some((el) => el.tagName === "MARK"),
    ).toBe(true);

    await user.keyboard("{Escape}");
    await waitFor(() => {
      expect(router.state.location.search).not.toContain("alert=");
    });
  });

  it("selects with x and bulk-closes through the e menu with a verdict", async () => {
    renderQueue();
    await screen.findByText("Alert number 1");
    const user = userEvent.setup();
    await user.keyboard("x");
    await user.keyboard("j");
    await user.keyboard("x");
    expect(await screen.findByRole("toolbar", { name: "Bulk actions" })).toHaveTextContent(
      "2 selected",
    );

    await user.keyboard("e");
    const menu = await screen.findByRole("dialog", { name: "Triage 2 alerts" });
    await user.click(within(menu).getByRole("button", { name: /Close as false positive/ }));
    await waitFor(() => {
      const bulk = calls.find((c) => c.url === "/api/alerts/bulk");
      expect(bulk?.body).toEqual({ ids: [1, 2], status: "closed", verdict: "false_positive" });
    });
  });

  it("requires a verdict to close from the inspector", async () => {
    const router = renderQueue();
    await screen.findByText("Alert number 1");
    await router.navigate("/alerts?alert=1");
    const inspector = await screen.findByRole("complementary", { name: "Alert 1" });
    const user = userEvent.setup();
    await user.click(await within(inspector).findByRole("radio", { name: "Closed" }));
    // No request yet: a verdict must be chosen first.
    expect(calls.some((c) => c.method === "PATCH")).toBe(false);
    await user.click(within(inspector).getByRole("button", { name: "True positive" }));
    await waitFor(() => {
      const patch = calls.find((c) => c.method === "PATCH");
      expect(patch?.body).toEqual({ status: "closed", verdict: "true_positive" });
    });
  });
});
