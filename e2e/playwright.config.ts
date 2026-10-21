import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defineConfig } from "@playwright/test";

// A private API + UI on their own ports and a throwaway database, so `make e2e` never
// touches a running dev server or its data.
const API = 8010;
const UI = 5180;
const dir = mkdtempSync(join(tmpdir(), "signal-e2e-"));

export const ADMIN = { email: "e2e-admin@signal.test", password: "e2e-passphrase-123" };

export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.ts",
  timeout: 90_000,
  fullyParallel: false,
  workers: 1,
  reporter: [["list"]],
  use: { baseURL: `http://localhost:${String(UI)}`, trace: "retain-on-failure" },
  globalSetup: "./global-setup.ts",
  webServer: [
    {
      command: `uv run uvicorn app.main:create_app --factory --host 127.0.0.1 --port ${String(API)}`,
      cwd: "../backend",
      url: `http://127.0.0.1:${String(API)}/api/health`,
      reuseExistingServer: false,
      timeout: 60_000,
      env: {
        SIGNAL_ENV: "dev",
        SIGNAL_DATABASE_URL: `sqlite:///${dir}/e2e.db`,
        SIGNAL_DATA_DIR: dir,
        SIGNAL_ADMIN_EMAIL: ADMIN.email,
        SIGNAL_ADMIN_PASSWORD: ADMIN.password,
        SIGNAL_COOKIE_SECURE: "false",
        SIGNAL_FRONTEND_ORIGIN: `http://localhost:${String(UI)}`,
      },
    },
    {
      command: `npm run dev -- --port ${String(UI)}`,
      cwd: "../frontend",
      url: `http://localhost:${String(UI)}`,
      reuseExistingServer: false,
      timeout: 60_000,
      env: { SIGNAL_API_URL: `http://127.0.0.1:${String(API)}` },
    },
  ],
});
