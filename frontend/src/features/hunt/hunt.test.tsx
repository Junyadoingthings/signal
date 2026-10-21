import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { makeQueryClient, Providers, routes } from "@/app/App";
import { Scrubber } from "@/components/Scrubber";
import { layout } from "@/features/entities/layout";
import type { EventRecord, Me } from "@/lib/types";

const me: Me = {
  csrf_token: "c",
  session_expires_at: new Date(Date.now() + 3600_000).toISOString(),
  user: {
    id: 1,
    email: "a@s.test",
    display_name: "Ana",
    role: "analyst",
    is_active: true,
    created_at: new Date().toISOString(),
    last_login_at: null,
  },
};

const ev: EventRecord = {
  id: 1,
  timestamp: "2026-10-20T12:00:00Z",
  ingested_at: "2026-10-20T12:00:00Z",
  batch_id: 1,
  source_type: "linux_auth",
  host: "web01",
  user: "admin",
  src_ip: "10.0.0.5",
  dst_ip: null,
  src_port: null,
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
  raw: "Failed password for admin <b>x</b>",
  tags: [],
  extra: {},
};

const json = (b: unknown, s = 200) =>
  new Response(JSON.stringify(b), { status: s, headers: { "content-type": "application/json" } });
const urls: string[] = [];

beforeEach(() => {
  urls.length = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      urls.push(url);
      if (url === "/api/auth/session") return Promise.resolve(json(me));
      if (url.startsWith("/api/searches")) return Promise.resolve(json([]));
      if (url.startsWith("/api/hunt/histogram"))
        return Promise.resolve(
          json({ start: "", end: "", bucket_seconds: 3600, buckets: [], total: 0 }),
        );
      if (url.startsWith("/api/hunt?")) {
        const q = new URL(url, "http://x").searchParams.get("q") ?? "";
        if (q.includes("(("))
          return Promise.resolve(
            json(
              {
                error: {
                  code: "invalid_query",
                  message: "missing ')'",
                  details: { pos: 1, fields: ["user"] },
                },
              },
              422,
            ),
          );
        return Promise.resolve(json({ items: [ev], total: 1, offset: 0, limit: 100 }));
      }
      return Promise.resolve(json({ error: { code: "not_found", message: "x" } }, 404));
    }),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
});

function renderHunt(path = "/hunt") {
  const router = createMemoryRouter(routes, { initialEntries: [path] });
  render(
    <Providers client={makeQueryClient()}>
      <RouterProvider router={router} />
    </Providers>,
  );
  return router;
}
const huntQs = () =>
  urls
    .filter((u) => u.startsWith("/api/hunt?"))
    .map((u) => new URL(u, "http://x").searchParams.get("q"));

describe("hunt query bar", () => {
  it("sends the typed query and shows results", async () => {
    const router = renderHunt();
    const user = userEvent.setup();
    await user.type(
      await screen.findByLabelText("Hunt query"),
      "user:admin AND outcome:failure{Enter}",
    );
    expect(await screen.findByText(/ssh_login/)).toBeInTheDocument();
    expect(huntQs()).toContain("user:admin AND outcome:failure");
    expect(router.state.location.search).toContain("q=user%3Aadmin");
  });

  it("shows a positioned error for an invalid query", async () => {
    renderHunt("/hunt?q=((");
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("missing ')'");
    expect(alert).toHaveTextContent("((");
    expect(screen.getByLabelText("Hunt query")).toHaveAttribute("aria-invalid", "true");
  });

  it("renders raw logs as text and pivots on a clicked value", async () => {
    renderHunt("/hunt?q=host:web01");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: /ssh_login/ }));
    expect(document.querySelector("b")).toBeNull(); // <b> in the log is not markup
    await user.click(await screen.findByTitle("Add src_ip:10.0.0.5 to the query"));
    await waitFor(() => {
      expect(huntQs()).toContain("host:web01 AND src_ip:10.0.0.5");
    });
  });
});

describe("scrubber", () => {
  const domain = { start: 0, end: 1_000_000 };

  it("emits a range after a drag and clears with Escape", () => {
    const onSelect = vi.fn();
    const { container } = render(
      <Scrubber histogram={undefined} domain={domain} selection={null} onSelect={onSelect} />,
    );
    const svg = container.querySelector("svg");
    if (!svg) throw new Error("no svg");
    svg.getBoundingClientRect = () => ({
      left: 0,
      top: 0,
      right: 800,
      bottom: 82,
      width: 800,
      height: 82,
      x: 0,
      y: 0,
      toJSON: () => ({}),
    });
    svg.setPointerCapture = () => undefined;
    fireEvent.pointerDown(svg, { clientX: 100, pointerId: 1 });
    fireEvent.pointerMove(svg, { clientX: 300, pointerId: 1 });
    fireEvent.pointerUp(svg, { clientX: 300, pointerId: 1 });
    expect(onSelect).toHaveBeenCalledTimes(1);
    const r = onSelect.mock.calls[0]?.[0] as { start: number; end: number };
    expect(r.end).toBeGreaterThan(r.start);
    fireEvent.keyDown(svg, { key: "Escape" });
    expect(onSelect).toHaveBeenLastCalledWith(null);
  });

  it("ignores a click without a drag", () => {
    const onSelect = vi.fn();
    const { container } = render(
      <Scrubber histogram={undefined} domain={domain} selection={null} onSelect={onSelect} />,
    );
    const svg = container.querySelector("svg");
    if (!svg) throw new Error("no svg");
    svg.getBoundingClientRect = () => ({
      left: 0,
      top: 0,
      right: 800,
      bottom: 82,
      width: 800,
      height: 82,
      x: 0,
      y: 0,
      toJSON: () => ({}),
    });
    svg.setPointerCapture = () => undefined;
    fireEvent.pointerDown(svg, { clientX: 100, pointerId: 1 });
    fireEvent.pointerUp(svg, { clientX: 101, pointerId: 1 });
    expect(onSelect).not.toHaveBeenCalled();
  });
});

describe("graph layout", () => {
  it("centres the entity and keeps hop-2 nodes on the outer ring", () => {
    const nodes = [
      { id: "1", type: "ip" as const, value: "a", event_count: 1, hop: 0 },
      { id: "2", type: "host" as const, value: "b", event_count: 1, hop: 1 },
      { id: "3", type: "user" as const, value: "c", event_count: 1, hop: 2 },
    ];
    const pos = layout(nodes, [
      { source: "1", target: "2", relation: "r", count: 1 },
      { source: "2", target: "3", relation: "r", count: 1 },
    ]);
    expect(pos.get("1")).toEqual({ x: 0, y: 0 });
    const d = (id: string) => Math.hypot(pos.get(id)?.x ?? 0, pos.get(id)?.y ?? 0);
    expect(d("3")).toBeGreaterThan(d("2"));
  });
});
