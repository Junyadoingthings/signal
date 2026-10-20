import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { makeQueryClient, Providers, routes } from "@/app/App";
import type { AttackMatrix, Me, RuleSummary } from "@/lib/types";

function me(role: "admin" | "analyst"): Me {
  return {
    csrf_token: "csrf-1",
    session_expires_at: new Date(Date.now() + 3600_000).toISOString(),
    user: {
      id: 1,
      email: `${role}@signal.test`,
      display_name: role,
      role,
      is_active: true,
      created_at: new Date().toISOString(),
      last_login_at: null,
    },
  };
}

const rule: RuleSummary = {
  id: "sig-auth-brute-force",
  title: "SSH / RDP brute force",
  severity: "medium",
  enabled: true,
  logic_type: "threshold",
  primary_tactic: "credential-access",
  techniques: [
    {
      id: "T1110.001",
      name: "Password Guessing",
      url: "https://attack.mitre.org/techniques/T1110/001/",
    },
  ],
  hit_count: 3,
  last_fired_at: new Date().toISOString(),
  tags: [],
};

const matrix: AttackMatrix = {
  version: "20.0",
  tactics: [
    {
      id: "TA0006",
      shortname: "credential-access",
      name: "Credential Access",
      url: "x",
      rule_count: 3,
    },
    {
      id: "TA0008",
      shortname: "lateral-movement",
      name: "Lateral Movement",
      url: "x",
      rule_count: 0,
    },
  ],
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

let patches: { url: string; body: string }[] = [];

function mock(role: "admin" | "analyst") {
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url === "/api/auth/session") return Promise.resolve(json(me(role)));
      if (url === "/api/rules" && (init?.method ?? "GET") === "GET")
        return Promise.resolve(json([rule]));
      if (url === "/api/attack") return Promise.resolve(json(matrix));
      if (url.startsWith("/api/rules/") && init?.method === "PATCH") {
        patches.push({ url, body: typeof init.body === "string" ? init.body : "" });
        return Promise.resolve(json({ ...rule, enabled: false }));
      }
      return Promise.resolve(json({ error: { code: "not_found", message: "x" } }, 404));
    }),
  );
}

function renderAt(path: string) {
  const router = createMemoryRouter(routes, { initialEntries: [path] });
  render(
    <Providers client={makeQueryClient()}>
      <RouterProvider router={router} />
    </Providers>,
  );
}

beforeEach(() => {
  patches = [];
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("rules page", () => {
  it("shows ATT&CK coverage including blind spots", async () => {
    mock("analyst");
    renderAt("/rules");
    const strip = await screen.findByRole("region", { name: "Rule coverage by tactic" });
    const lateral = within(strip).getByTitle(/Lateral Movement.*0 rules/);
    expect(lateral).toHaveTextContent("·");
    expect(within(strip).getByTitle(/Credential Access.*3 rules/)).toHaveTextContent("3");
  });

  it("lets admins toggle a rule and blocks analysts", async () => {
    mock("analyst");
    renderAt("/rules");
    const sw = await screen.findByRole("switch", { name: /Disable SSH/ });
    expect(sw).toBeDisabled();
  });

  it("sends the toggle for admins", async () => {
    mock("admin");
    renderAt("/rules");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("switch", { name: /Disable SSH/ }));
    expect(patches).toEqual([
      { url: "/api/rules/sig-auth-brute-force", body: '{"enabled":false}' },
    ]);
  });
});
