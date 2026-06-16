import { expect, test } from "@playwright/test";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

function rootEnv(name: string): string | undefined {
  const envPath = resolve(process.cwd(), "../.env");
  if (!existsSync(envPath)) return undefined;
  const prefix = `${name}=`;
  return readFileSync(envPath, "utf8")
    .split(/\r?\n/)
    .find((line) => line.startsWith(prefix))
    ?.slice(prefix.length);
}

test("logs in and reads primary pages through the live Compose console proxy", async ({ page }) => {
  const email =
    process.env.OHMYRASP_E2E_ADMIN_EMAIL ??
    process.env.OHMYRASP_BOOTSTRAP_ADMIN_EMAIL ??
    rootEnv("OHMYRASP_BOOTSTRAP_ADMIN_EMAIL") ??
    "admin@ohmyrasp.local";
  const password =
    process.env.OHMYRASP_E2E_ADMIN_PASSWORD ??
    process.env.OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD ??
    rootEnv("OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD");
  if (!password) {
    throw new Error("Set OHMYRASP_E2E_ADMIN_PASSWORD or OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD before running live e2e tests.");
  }

  await page.goto("/login");
  await expect(page.getByRole("heading", { name: "Sign in to the console" })).toBeVisible();
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Enter console" }).click();

  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();

  const session = await page.evaluate(() => {
    const raw = window.localStorage.getItem("ohmyrasp.console.session");
    return raw ? (JSON.parse(raw) as { token?: string }) : {};
  });
  expect(session.token).toBeTruthy();

  const applicationsResponse = await page.request.get("/api/v1/applications", {
    headers: { Authorization: `Bearer ${session.token}` }
  });
  expect(applicationsResponse.ok()).toBeTruthy();
  const applicationsBody = (await applicationsResponse.json()) as { items?: Array<{ id: string; name: string }> };
  expect(applicationsBody.items?.length ?? 0).toBeGreaterThan(0);

  await expect(page.getByText("Security posture")).toBeVisible();
  await expect(page.getByText("Instances online")).toBeVisible();

  for (const section of [
    { link: "Applications", heading: "Applications" },
    { link: "Instances", heading: "Instances" },
    { link: "Policies", heading: "Policies" },
    { link: "Threats", heading: "Threats" },
    { link: "Software & Posture", heading: "Software & Posture" },
    { link: "Observability", heading: "Observability" },
    { link: "Protection Config", heading: "Protection Config" },
    { link: "Access & Audit", heading: "Access & Audit" }
  ]) {
    await page.getByRole("link", { name: section.link, exact: true }).click();
    await expect(page.getByRole("heading", { name: section.heading, exact: true })).toBeVisible();
  }
});
