/** Automated accessibility checks (axe-core) on the main views. jsdom has no layout or
 * colour, so contrast is verified separately from the design tokens; this covers roles,
 * names, labels, landmarks, heading order and ARIA validity. */
import { render, screen } from "@testing-library/react";
import axe from "axe-core";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { makeQueryClient, Providers, routes } from "@/app/App";

const me = {
  csrf_token: "c",
  session_expires_at: "2030-01-01T00:00:00Z",
  user: {
    id: 1,
    email: "a@s.test",
    display_name: "Ada",
    role: "admin",
    is_active: true,
    created_at: "2026-01-01T00:00:00Z",
    last_login_at: null,
  },
};
const zero = { critical: 0, high: 0, medium: 0, low: 0 };
const overview = {
  start: "2026-10-20T00:00:00Z",
  end: "2026-10-21T00:00:00Z",
  bucket_seconds: 1800,
  buckets: [],
  events_total: 5,
  markers: [],
  open_incidents: zero,
  open_alerts: { ...zero, high: 1 },
  noisy_rules: [{ rule_id: "r", title: "Rule", severity: "high", count: 2 }],
  top_entities: [{ type: "host", value: "web01", count: 2, top_severity: "high" }],
  fired_tactics: { execution: 1 },
  mttr_seconds: 120,
  closed_count: 1,
  verdicts: { true_positive: 1 },
};
const matrix = {
  version: "20.0",
  tactics: [
    { id: "TA0002", shortname: "execution", name: "Execution", url: "x", rule_count: 2 },
    { id: "TA0007", shortname: "discovery", name: "Discovery", url: "x", rule_count: 0 },
  ],
};
const json = (b: unknown, s = 200) =>
  new Response(JSON.stringify(b), { status: s, headers: { "content-type": "application/json" } });

beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url === "/api/auth/session") return Promise.resolve(json(me));
      if (url.startsWith("/api/overview")) return Promise.resolve(json(overview));
      if (url === "/api/attack") return Promise.resolve(json(matrix));
      if (url.startsWith("/api/alerts?"))
        return Promise.resolve(json({ items: [], total: 0, offset: 0, limit: 100 }));
      if (url === "/api/rules") return Promise.resolve(json([]));
      if (url.startsWith("/api/hunt/histogram"))
        return Promise.resolve(
          json({ start: "", end: "", bucket_seconds: 60, buckets: [], total: 0 }),
        );
      if (url.startsWith("/api/hunt?"))
        return Promise.resolve(json({ items: [], total: 0, offset: 0, limit: 100 }));
      if (url.startsWith("/api/searches")) return Promise.resolve(json([]));
      if (url.startsWith("/api/ingest/batches"))
        return Promise.resolve(json({ items: [], next_before_id: null }));
      if (url.startsWith("/api/ingest/settings"))
        return Promise.resolve(
          json({ syslog_timezone: "UTC", syslog_year: null, max_upload_bytes: 100 }),
        );
      if (url.startsWith("/api/ingest/tokens")) return Promise.resolve(json([]));
      if (url.startsWith("/api/incidents")) return Promise.resolve(json({ items: [], total: 0 }));
      return Promise.resolve(json({ error: { code: "not_found", message: "x" } }, 404));
    }),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
});

async function violations(path: string, ready: RegExp | string) {
  const router = createMemoryRouter(routes, { initialEntries: [path] });
  render(
    <Providers client={makeQueryClient()}>
      <RouterProvider router={router} />
    </Providers>,
  );
  await screen.findByText(ready, undefined, { timeout: 5000 });
  const res = await axe.run(document.body, {
    rules: {
      "color-contrast": { enabled: false },
      region: { enabled: false },
      "scrollable-region-focusable": { enabled: false },
    },
  });
  return res.violations.map(
    (v) => `${v.id}: ${v.nodes.map((n) => n.html.slice(0, 90)).join(" | ")}`,
  );
}

describe("axe", () => {
  it.each([
    ["/", "Noisiest rules"],
    ["/alerts", /All quiet/],
    ["/hunt", "Hunt"],
    ["/rules", "Rule coverage by tactic"],
    ["/incidents", /No open incidents/],
    ["/ingest", "Batches"],
    ["/admin/audit", "Audit log"],
  ])("%s has no violations", async (path, ready) => {
    expect(await violations(path, ready)).toEqual([]);
  });
});
