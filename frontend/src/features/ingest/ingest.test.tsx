import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { makeQueryClient, Providers, routes } from "@/app/App";
import type { Batch, Me } from "@/lib/types";

const me: Me = {
  csrf_token: "csrf-abc",
  session_expires_at: new Date(Date.now() + 3600_000).toISOString(),
  user: {
    id: 1,
    email: "a@signal.test",
    display_name: "Ada",
    role: "admin",
    is_active: true,
    created_at: new Date().toISOString(),
    last_login_at: null,
  },
};

const batch: Batch = {
  id: 7,
  source_type: "generic_jsonl",
  kind: "upload",
  filename: "fw.jsonl",
  default_host: null,
  size_bytes: 40,
  status: "pending",
  parsed_count: 0,
  unparsed_count: 0,
  duplicate_count: 0,
  tz_assumption: null,
  year_assumption: null,
  error: null,
  created_at: new Date().toISOString(),
  finished_at: null,
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const sent: { headers: Record<string, string>; body: FormData | null }[] = [];

class FakeXHR {
  status = 0;
  responseText = "";
  withCredentials = false;
  upload: {
    onprogress: ((e: { lengthComputable: boolean; loaded: number; total: number }) => void) | null;
  } = {
    onprogress: null,
  };
  onload: (() => void) | null = null;
  onerror: (() => void) | null = null;
  private headers: Record<string, string> = {};
  open() {}
  setRequestHeader(k: string, v: string) {
    this.headers[k] = v;
  }
  abort() {}
  send(body: FormData) {
    sent.push({ headers: this.headers, body });
    this.upload.onprogress?.({ lengthComputable: true, loaded: 1, total: 1 });
    this.status = 202;
    this.responseText = JSON.stringify(batch);
    queueMicrotask(() => this.onload?.());
  }
}

beforeEach(() => {
  sent.length = 0;
  vi.stubGlobal("XMLHttpRequest", FakeXHR);
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url === "/api/auth/session") return Promise.resolve(json(me));
      if (url === "/api/ingest/settings")
        return Promise.resolve(
          json({ syslog_timezone: "UTC", syslog_year: null, max_upload_bytes: 1000 }),
        );
      if (url.startsWith("/api/ingest/batches"))
        return Promise.resolve(json({ items: [], next_before_id: null }));
      if (url === "/api/ingest/tokens") return Promise.resolve(json([]));
      return Promise.resolve(json({ error: { code: "not_found", message: "x" } }, 404));
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function renderIngest() {
  const router = createMemoryRouter(routes, { initialEntries: ["/ingest"] });
  render(
    <Providers client={makeQueryClient()}>
      <RouterProvider router={router} />
    </Providers>,
  );
}

describe("ingest upload", () => {
  it("shows the syslog assumption and an empty state", async () => {
    renderIngest();
    expect(await screen.findByText(/Classic syslog has no year or timezone/)).toBeInTheDocument();
    expect(await screen.findByText(/Nothing ingested yet/)).toBeInTheDocument();
  });

  it("uploads a generic JSONL file with its field mapping and CSRF header", async () => {
    renderIngest();
    const user = userEvent.setup();
    await screen.findByText(/Classic syslog/);

    await user.selectOptions(screen.getByLabelText("Format"), "generic_jsonl");
    await user.type(screen.getByLabelText("Path for timestamp"), "ts");
    await user.click(screen.getByRole("button", { name: /Add field/ }));
    await user.type(screen.getByLabelText("Path for host"), "device.name");

    const file = new File(['{"ts": 1}\n'], "fw.jsonl", { type: "application/json" });
    await user.upload(screen.getByLabelText("Log file"), file);
    await user.click(screen.getByRole("button", { name: "Upload and parse" }));

    expect(await screen.findByText(/batch #7/)).toBeInTheDocument();
    expect(sent).toHaveLength(1);
    const req = sent[0];
    if (!req) throw new Error("no request sent");
    expect(req.headers["X-CSRF-Token"]).toBe("csrf-abc");
    expect(req.body?.get("format")).toBe("generic_jsonl");
    expect(JSON.parse(req.body?.get("field_mapping") as string)).toEqual({
      timestamp: "ts",
      host: "device.name",
    });
  });

  it("refuses files over the size limit before uploading", async () => {
    renderIngest();
    const user = userEvent.setup();
    await screen.findByText(/Classic syslog/);
    await user.upload(screen.getByLabelText("Log file"), new File(["x".repeat(2000)], "big.log"));
    expect(await screen.findByRole("alert")).toHaveTextContent("the limit is");
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Upload and parse" })).toBeDisabled();
    });
    expect(sent).toHaveLength(0);
  });
});
