import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "@playwright/test";
import { ADMIN } from "./playwright.config";

test("sign in → upload sample → see the incident → triage → export the report", async ({ page }) => {
  // 1. sign in
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await page.getByLabel("Email").fill(ADMIN.email);
  await page.getByLabel("Password").fill(ADMIN.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();

  // 2. upload the planted SSH brute-force scenario and wait for it to be parsed
  await page.goto("/ingest");
  await page.getByLabel("Log file").setInputFiles(join(import.meta.dirname, ".data", "web01-auth.log"));
  await page.getByRole("button", { name: "Upload and parse" }).click();
  await expect(page.getByText(/detected Linux auth/)).toBeVisible();
  await expect(page.getByRole("row", { name: /web01-auth\.log/ }).getByText("Done")).toBeVisible({ timeout: 30_000 });

  // 3. detection + correlation produced one critical incident with the right story
  await page.goto("/incidents");
  const incident = page.getByRole("link", { name: /web01.*Credential Access/ });
  await expect(incident).toBeVisible({ timeout: 15_000 });
  await expect(incident).toContainText(/critical/i);
  await incident.click();
  await expect(page.getByRole("img", { name: /Attack storyline/ })).toBeVisible();

  // 4. open the critical alert in the inspector and triage it: investigate, then close with a verdict
  await page.getByRole("button", { name: /Successful logon after brute force/ }).first().click();
  const inspector = page.getByRole("complementary", { name: /Alert \d+/ });
  await expect(inspector.getByText("Why it fired")).toBeVisible();
  await inspector.getByRole("radio", { name: "Investigating" }).click();
  await expect(inspector.getByRole("radio", { name: "Investigating" })).toHaveAttribute("aria-checked", "true");
  await inspector.getByRole("radio", { name: "Closed" }).click();
  await inspector.getByRole("button", { name: "True positive", exact: true }).click();
  await expect(inspector.getByRole("radio", { name: "Closed" })).toHaveAttribute("aria-checked", "true");
  await expect(inspector.getByText("Verdict True positive", { exact: true })).toBeVisible();

  // 5. export the incident report and check its contents
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download Markdown" }).click();
  const file = await download;
  expect(file.suggestedFilename()).toMatch(/^incident-\d+\.md$/);
  const path = await file.path();
  const md = readFileSync(path, "utf8");
  for (const part of ["## Timeline", "T1110.001", "203.0.113.50", "## Indicators of compromise", "verdict none → true positive", "closed · true_positive"]) {
    expect(md).toContain(part);
  }
  expect(md).not.toContain("<script>");
});
