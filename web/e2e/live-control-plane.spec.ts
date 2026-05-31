import { expect, test } from "@playwright/test";
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

function rootEnv(name: string): string | undefined {
  const envPath = resolve(process.cwd(), "../.env");
  if (!existsSync(envPath)) {
    return undefined;
  }
  const prefix = `${name}=`;
  return readFileSync(envPath, "utf8")
    .split(/\r?\n/)
    .find(line => line.startsWith(prefix))
    ?.slice(prefix.length);
}

test("logs in, creates application scope, operates an Agent, manages access, and reads primary pages through the live Compose web proxy", async ({ page }) => {
  test.setTimeout(60_000);
  const email = process.env.OHMYRASP_E2E_ADMIN_EMAIL ?? rootEnv("OHMYRASP_BOOTSTRAP_ADMIN_EMAIL") ?? "admin@ohmyrasp.local";
  const password = process.env.OHMYRASP_E2E_ADMIN_PASSWORD ?? rootEnv("OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD") ?? "change-me";
  const suffix = Date.now().toString(36);
  const appName = `Live UI ${suffix}`;
  const environmentName = `live-prod-${suffix}`;
  const policyName = `Live Policy ${suffix}`;

  await page.goto("/login");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();

  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByText("Control Domains")).toBeVisible();

  await page.getByRole("link", { name: "Applications" }).click();
  await page.getByLabel("Application Name").fill(appName);
  await page.getByLabel("Description").fill("Created by the live Playwright smoke flow");
  await page.getByRole("button", { name: "Create Application" }).click();
  const applicationStatus = page.getByRole("status").filter({ hasText: `Created application ${appName}.` });
  await expect(applicationStatus).toBeVisible();
  let applicationSecret = (await applicationStatus.textContent())?.match(/Secret: ([^.]+)\./)?.[1] ?? "";
  expect(applicationSecret).not.toBe("");
  await expect(page.getByRole("cell", { name: appName })).toBeVisible();

  await page.locator("#environment-application").selectOption({ label: appName });
  await page.getByLabel("Environment Name").fill(environmentName);
  await page.getByLabel("Kind").selectOption("production");
  await page.getByRole("button", { name: "Create Environment" }).click();
  await expect(page.getByText(`Created environment ${environmentName} for ${appName}.`)).toBeVisible();
  await page.getByRole("button", { name: "Rotate Secret" }).click();
  const rotationStatus = page.getByRole("status").filter({ hasText: `Rotated secret for ${appName}.` });
  await expect(rotationStatus).toBeVisible();
  applicationSecret = (await rotationStatus.textContent())?.match(/Secret: ([^.]+)\./)?.[1] ?? "";
  expect(applicationSecret).not.toBe("");

  await page.getByRole("link", { name: "Agents" }).click();
  await page.locator("#agent-application").selectOption({ label: appName });
  await page.getByLabel("Application Secret").fill(applicationSecret);
  await page.getByLabel("Agent Hostname").fill(`live-agent-${suffix}`);
  await page.getByLabel("Agent Runtime").fill("java");
  await page.getByLabel("Agent Version").fill("1.0.0");
  await page.getByRole("button", { name: "Register Agent" }).click();
  await expect(page.getByText(`Registered Agent live-agent-${suffix}`, { exact: false })).toBeVisible();

  await page.getByRole("link", { name: "Policies" }).click();
  await page.getByLabel("Policy Set Name").fill(policyName);
  await page.getByLabel("Policy Description").fill("Created by the live Playwright smoke flow");
  await page.getByRole("button", { name: "Create Policy Set" }).click();
  await expect(page.getByText(`Created policy set ${policyName}.`)).toBeVisible();
  await expect(page.getByText(policyName).first()).toBeVisible();
  await expect(page.locator("#policy-id")).toContainText(policyName);
  await page.locator("#policy-id").selectOption({ label: policyName });
  await page.getByRole("button", { name: "Create Version" }).click();
  await expect(page.getByText("Created policy version 1.")).toBeVisible();
  await page.getByLabel("Rule Name").fill(`Live edited rule ${suffix}`);
  await page.getByRole("button", { name: "Update Draft" }).click();
  await expect(page.getByText("Updated policy version 1.")).toBeVisible();
  await page.locator("#rollout-scope").selectOption({ label: appName });
  await page.getByLabel("Canary Percent").fill("100");
  await page.getByRole("button", { name: "Roll Out Version" }).click();
  await expect(page.getByText(`Rolled out version 1 to 100% for ${appName}.`)).toBeVisible();

  await page.getByRole("link", { name: "Agents" }).click();
  await expect(page.locator("#agent-operation-agent")).toContainText(`live-agent-${suffix}`);
  await page.locator("#agent-operation-agent").selectOption({ label: `live-agent-${suffix}` });
  await page.getByLabel("Operation Secret").fill(applicationSecret);
  await page.getByLabel("Heartbeat Status").selectOption("offline");
  await page.getByRole("button", { name: "Send Heartbeat" }).click();
  await expect(page.getByText(`Heartbeat accepted for live-agent-${suffix}: offline.`)).toBeVisible();
  await page.getByRole("button", { name: "Pull Policy" }).click();
  await expect(page.getByText(`Pulled policy version 1 (active) with 1 rules for live-agent-${suffix}.`)).toBeVisible();
  await expect(page.getByText("Agent Artifact Catalog")).toBeVisible();
  await expect(page.getByText("Fallback Enabled", { exact: true })).toBeVisible();
  await expect(page.getByText("Agent Artifact Upload")).toBeVisible();
  await page.getByLabel("Agent ZIP").setInputFiles({
    name: `live-agent-${suffix}.zip`,
    mimeType: "application/zip",
    buffer: Buffer.from(
      "UEsDBBQAAAAIAMQOwVzVR9O5HwAAAB0AAAAKAAAAUkVBRE1FLnR4dPPP8K0MSiwuUMjJLEtVKC3IyU9MUUjLrCgpLUrlAgBQSwECFAMUAAAACADEDsFc1UfTuR8AAAAdAAAACgAAAAAAAAAAAAAAgAEAAAAAUkVBRE1FLnR4dFBLBQYAAAAAAQABADgAAABHAAAAAAA=",
      "base64"
    )
  });
  await page.getByLabel("Upload Language Version").fill("21");
  await page.getByRole("button", { name: "Upload Artifact" }).click();
  await expect(page.getByText("Uploaded ohmyrasp-agent-java-linux-21.zip")).toBeVisible();

  await page.getByRole("button", { name: "Reset Token" }).click();
  const daemonTokenStatus = page.getByRole("status").filter({ hasText: "Rotated daemon token:" });
  await expect(daemonTokenStatus).toBeVisible();
  const daemonToken = (await daemonTokenStatus.textContent())?.match(/Rotated daemon token: ([^.]+)$/)?.[1] ?? "";
  expect(daemonToken).not.toBe("");
  const sessionToken = await page.evaluate(() => window.localStorage.getItem("ohmyrasp.session_token"));
  expect(sessionToken).not.toBe("");
  const applicationsResponse = await page.request.get("/api/v1/applications", {
    headers: { Authorization: `Bearer ${sessionToken}` }
  });
  expect(applicationsResponse.ok()).toBeTruthy();
  const applicationsBody: { items: Array<{ id: string; name: string }> } = await applicationsResponse.json();
  const liveApp = applicationsBody.items.find((application) => application.name === appName);
  expect(liveApp).toBeTruthy();
  await page.getByLabel("Artifact Application").selectOption({ label: appName });
  await page.locator("#artifact-language-version").fill("21");
  await page.getByRole("button", { name: "Check Agent Artifact" }).click();
  await expect(page.getByText(`Artifact ohmyrasp-agent-java-linux-21.zip ready for ${appName}.`)).toBeVisible();
  await page.getByRole("button", { name: "Download Agent Artifact" }).click();
  await expect(page.getByText("Downloaded ohmyrasp-agent-java-linux-21.zip", { exact: false })).toBeVisible();
  const daemonApp = await page.request.get(`/api/v1/daemon/app?app_id=${liveApp!.id}`, {
    headers: { "X-OhMyRasp-Daemon-Token": daemonToken }
  });
  expect(daemonApp.ok()).toBeTruthy();
  const daemonAppBody: { application_secret: string; language: string } = await daemonApp.json();
  expect(daemonAppBody.application_secret).toBe(applicationSecret);
  expect(daemonAppBody.language).toBe("java");
  const artifactInfo = await page.request.get(`/api/v1/daemon/artifacts/agent/info?app_id=${liveApp!.id}&language=java&system_type=linux&language_version=21`, {
    headers: { "X-OhMyRasp-Daemon-Token": daemonToken }
  });
  expect(artifactInfo.ok()).toBeTruthy();
  const artifactInfoBody: { md5: string; content_type: string; size: number } = await artifactInfo.json();
  expect(artifactInfoBody.content_type).toBe("application/zip");
  expect(artifactInfoBody.size).toBeGreaterThan(0);
  const artifactDownload = await page.request.get(`/api/v1/daemon/artifacts/agent?app_id=${liveApp!.id}&language=java&system_type=linux&language_version=21`, {
    headers: { "X-OhMyRasp-Daemon-Token": daemonToken }
  });
  expect(artifactDownload.ok()).toBeTruthy();
  const artifactBytes = await artifactDownload.body();
  expect(createHash("md5").update(artifactBytes).digest("hex")).toBe(artifactInfoBody.md5);
  const daemonReport = await page.request.post("/api/v1/daemon/workloads/report", {
    headers: { "X-OhMyRasp-Daemon-Token": daemonToken },
    data: {
      node_name: `live-node-${suffix}`,
      workloads: [
        {
          type: "process",
          pid: 7301,
          cmdline: ["/usr/bin/java", "-jar", `live-${suffix}.jar`]
        }
      ]
    }
  });
  expect(daemonReport.ok()).toBeTruthy();
  await page.reload();
  const workloadRow = page.locator("tr", { hasText: `live-node-${suffix}` });
  await expect(workloadRow).toBeVisible();
  await workloadRow.getByRole("combobox").selectOption({ label: appName });
  await workloadRow.getByRole("button", { name: "Bind", exact: true }).click();
  await expect(page.getByText(`Bound process 7301 to ${appName}.`)).toBeVisible();
  const daemonCommands = await page.request.get("/api/v1/daemon/commands", {
    headers: { "X-OhMyRasp-Daemon-Token": daemonToken }
  });
  expect(daemonCommands.ok()).toBeTruthy();
  const daemonCommandBody: {
    items: Array<{
      application_secret: string;
      language: string;
      workloads: Array<{ id: string; node_name: string; pid?: number }>;
    }>;
  } = await daemonCommands.json();
  expect(daemonCommandBody.items).toHaveLength(1);
  expect(daemonCommandBody.items[0].application_secret).toBe(applicationSecret);
  expect(daemonCommandBody.items[0].language).toBe("java");
  expect(daemonCommandBody.items[0].workloads.some((workload) => workload.node_name === `live-node-${suffix}` && workload.pid === 7301)).toBeTruthy();
  const injectionReport = await page.request.post("/api/v1/daemon/injection-reports", {
    headers: { "X-OhMyRasp-Daemon-Token": daemonToken },
    data: {
      workload_id: daemonCommandBody.items[0].workloads[0].id,
      status: "failed",
      error: "live injection permission denied",
      helper_id: `live-helper-${suffix}`,
      helper_version: "1.0.0"
    }
  });
  expect(injectionReport.ok()).toBeTruthy();
  const injectionBody: { injection_status: string; injection_error: string } = await injectionReport.json();
  expect(injectionBody.injection_status).toBe("failed");
  expect(injectionBody.injection_error).toBe("live injection permission denied");
  await page.reload();
  await expect(workloadRow).toContainText("failed");
  await expect(workloadRow).toContainText("live injection permission denied");
  await workloadRow.getByRole("button", { name: "Unbind", exact: true }).click();
  await expect(page.getByText("Unbound process 7301.")).toBeVisible();

  await page.getByRole("link", { name: "Access & Audit" }).click();
  await page.getByLabel("Allowlist Enabled").check();
  await page.getByLabel("Allowlist Mode").selectOption("enforce");
  await page.getByLabel("Allowlist Entries").fill(`/live/${suffix}\n10.10.0.0/16`);
  await page.getByLabel("Hardening Mode").selectOption("enforce");
  await page.getByLabel("Vulnerability Threshold").selectOption("high");
  await page.getByLabel("Audit Retention Days").fill("730");
  await page.getByRole("button", { name: "Save Protection Configuration" }).click();
  await expect(page.getByText("Protection configuration saved.")).toBeVisible();

  const alertName = `Live Alert ${suffix}`;
  await page.locator("#alert-name").fill(alertName);
  await page.locator("#alert-target").fill(`live-alert-${suffix}`);
  await page.getByRole("button", { name: "Create Alert Rule" }).click();
  await expect(page.getByText("Alert rule created.")).toBeVisible();
  await expect(page.locator("#alert-lifecycle-rule")).toContainText(alertName);
  await page.locator("#alert-lifecycle-rule").selectOption({ label: alertName });
  await page.locator("#alert-lifecycle-name").fill(`Live Alert Disabled ${suffix}`);
  await page.locator("#alert-lifecycle-description").fill("Disabled by the live Playwright smoke flow");
  await page.locator("#alert-lifecycle-severity").selectOption("medium");
  await page.locator("#alert-lifecycle-condition").fill("severity == medium");
  await page.locator("#alert-lifecycle-target").fill(`live-alert-disabled-${suffix}`);
  await page.locator("#alert-lifecycle-enabled").uncheck();
  await page.getByRole("button", { name: "Update Alert Rule" }).click();
  await expect(page.getByText(`Updated alert rule Live Alert Disabled ${suffix}.`)).toBeVisible();

  const userEmail = `live-user-${suffix}@ohmyrasp.local`;
  await page.getByLabel("Email").fill(userEmail);
  await page.getByLabel("Name").nth(1).fill(`Live User ${suffix}`);
  await page.getByRole("button", { name: "Create User" }).click();
  await expect(page.getByText("User created.")).toBeVisible();
  await expect(page.locator("#user-lifecycle-user")).toContainText(`Live User ${suffix}`);
  await page.locator("#user-lifecycle-user").selectOption({ label: `Live User ${suffix}` });
  await page.getByLabel("User Display Name").fill(`Live Disabled ${suffix}`);
  await page.getByLabel("User Role").selectOption("viewer");
  await page.getByLabel("Disable User").check();
  await page.getByRole("button", { name: "Update User" }).click();
  await expect(page.getByText(`Updated user ${userEmail}.`)).toBeVisible();

  for (const section of [
    { label: "Applications", path: "/applications", heading: "Applications" },
    { label: "Agents", path: "/agents", heading: "Agents" },
    { label: "Policies", path: "/policies", heading: "Policies" },
    { label: "Events", path: "/events", heading: "Events" },
    { label: "Observability", path: "/observability", heading: "Observability" },
    { label: "Access & Audit", path: "/access", heading: "Access & Audit" }
  ]) {
    await page.getByRole("link", { name: section.label }).click();
    await expect(page).toHaveURL(new RegExp(`${section.path}$`));
    await expect(page.getByRole("heading", { name: section.heading, level: 1 })).toBeVisible();
    if (section.path === "/events") {
      await expect(page.getByText("Event Query")).toBeVisible();
      await page.getByLabel("Event Application").selectOption({ label: appName });
      await page.getByLabel("Event Severity").selectOption("critical");
      await page.getByLabel("Event Hook").fill("sql");
      await page.getByLabel("Event Limit").fill("50");
      await expect(page.getByRole("button", { name: "Clear Filters" })).toBeVisible();
      await page.getByLabel("Dependency Application").selectOption({ label: appName });
      await page.getByLabel("Dependency Ecosystem").fill("maven");
      await page.getByLabel("Dependency Severity").selectOption("critical");
      await page.getByLabel("Dependency Limit").fill("50");
      await expect(page.getByRole("button", { name: "Clear Dependency Filters" })).toBeVisible();
      await page.getByLabel("Baseline Application").selectOption({ label: appName });
      await page.getByLabel("Baseline Severity").selectOption("medium");
      await page.getByLabel("Baseline Status").selectOption("warning");
      await page.getByLabel("Baseline Limit").fill("50");
      await expect(page.getByRole("button", { name: "Clear Baseline Filters" })).toBeVisible();
    } else if (section.path === "/observability") {
      await expect(page.getByRole("heading", { name: "Observability Filters" })).toBeVisible();
      await page.getByLabel("Observability Application").selectOption({ label: appName });
      await page.getByLabel("Observability Policy").selectOption({ label: policyName });
      await expect(page.getByRole("button", { name: "Clear Observability Filters" })).toBeVisible();
    } else if (section.path === "/access") {
      await expect(page.getByText("Open Source Self-Hosted")).toBeVisible();
      await expect(page.getByText("Not required")).toBeVisible();
    }
  }

  await expect.poll(async () => page.evaluate(() => window.localStorage.getItem("ohmyrasp.session_token"))).not.toBe("");
});
