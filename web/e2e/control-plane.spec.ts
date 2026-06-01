import { expect, type Page, type Route, test } from "@playwright/test";
import { Buffer } from "node:buffer";

test("logs in through the API-backed form", async ({ page }) => {
  const api = await mockControlPlaneApi(page);

  await page.goto("/login");
  await expect(page.getByRole("heading", { name: "Sign in to OhMyRasp" })).toBeVisible();
  await page.getByLabel("Language").selectOption("zh");
  await expect(page.getByRole("heading", { name: "登录 OhMyRasp" })).toBeVisible();
  await page.locator("select").first().selectOption("ja");
  await expect(page.getByRole("heading", { name: "OhMyRasp にサインイン" })).toBeVisible();
  await page.locator("select").first().selectOption("en");
  await expect(page.getByRole("heading", { name: "Sign in to OhMyRasp" })).toBeVisible();

  await page.getByLabel("Email").fill("admin@ohmyrasp.local");
  await page.getByLabel("Password").fill("change-me");
  await page.getByRole("button", { name: "Sign in" }).click();

  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByText("Control Domains")).toBeVisible();
  await expect(page.getByText("admin@ohmyrasp.local")).toBeVisible();
  await expect.poll(async () => page.evaluate(() => window.localStorage.getItem("ohmyrasp.session_token"))).toBe("e2e-token");
  await expect.poll(() => api.authorizedPaths).toContain("/api/v1/analytics/overview");
});

test("protects authenticated routes and renders explicit fallback pages", async ({ page }) => {
  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByRole("heading", { name: "Sign in to OhMyRasp" })).toBeVisible();

  await page.goto("/noaccess");
  await expect(page.getByRole("heading", { name: "No access" })).toBeVisible();
  await expect(page.getByText("Your account does not have permission to open this page.")).toBeVisible();

  await page.goto("/does-not-exist");
  await expect(page.getByRole("heading", { name: "Page not found" })).toBeVisible();
  await page.getByLabel("Language").selectOption("zh");
  await expect(page.getByRole("heading", { name: "页面不存在" })).toBeVisible();
});

test("navigates primary control-plane sections with an authenticated session", async ({ page }) => {
  const api = await mockControlPlaneApi(page);
  await page.addInitScript(() => {
    window.localStorage.setItem("ohmyrasp.session_token", "e2e-token");
    window.localStorage.setItem("ohmyrasp.session_user_email", "admin@ohmyrasp.local");
    window.localStorage.setItem("ohmyrasp.session_user_name", "Default Admin");
  });

  await page.goto("/");
  await expect(page.getByText("Control Domains")).toBeVisible();
  await expect(page.getByText("Attack Trend")).toBeVisible();
  await expect(page.getByText("User-Agent Sources")).toBeVisible();

  for (const section of [
    { label: "Applications", path: "/applications", heading: "Applications", evidence: "Playwright managed application" },
    { label: "Agents", path: "/agents", heading: "Agents", evidence: "pol_default v3" },
    { label: "Policies", path: "/policies", heading: "Policies", evidence: "SQL and command protections" },
    { label: "Events", path: "/events", heading: "Events", evidence: "SQL tautology blocked" },
    { label: "Observability", path: "/observability", heading: "Observability", evidence: "Rule Overhead" },
    { label: "Access & Audit", path: "/access", heading: "Access & Audit", evidence: "auth.login" }
  ]) {
    await page.getByRole("link", { name: section.label }).click();
    await expect(page).toHaveURL(new RegExp(`${section.path}$`));
    await expect(page.getByRole("heading", { name: section.heading, level: 1 })).toBeVisible();
    await expect(page.getByText(section.evidence).first()).toBeVisible();
    if (section.path === "/events") {
      await expect(page.getByText("Event Query")).toBeVisible();
      await page.getByLabel("Event Severity").selectOption("critical");
      await page.getByLabel("Event Hook").fill("sql");
      await expect
        .poll(() => api.authorizedURLs.some(path => path.startsWith("/api/v1/events/attack?") && path.includes("severity=critical") && path.includes("hook=sql")))
        .toBe(true);
      await page.getByRole("button", { name: "Clear Filters" }).click();
      await page.getByLabel("Dependency Name").fill("spring-web");
      await page.getByLabel("Dependency Ecosystem").fill("maven");
      await page.getByLabel("Dependency Severity").selectOption("critical");
      await expect
        .poll(() =>
          api.authorizedURLs.some(
            path =>
              path.startsWith("/api/v1/dependencies?") &&
              path.includes("name=spring-web") &&
              path.includes("ecosystem=maven") &&
              path.includes("vulnerability_severity=critical")
          )
        )
        .toBe(true);
      await page.getByRole("button", { name: "Clear Dependency Filters" }).click();
      await page.getByLabel("Baseline Status").selectOption("warning");
      await page.getByLabel("Baseline Severity").selectOption("medium");
      await page.getByLabel("Baseline Category").fill("runtime");
      await expect
        .poll(() =>
          api.authorizedURLs.some(
            path =>
              path.startsWith("/api/v1/baseline-findings?") &&
              path.includes("status=warning") &&
              path.includes("severity=medium") &&
              path.includes("category=runtime")
          )
        )
        .toBe(true);
      await page.getByRole("button", { name: "Clear Baseline Filters" }).click();
    } else if (section.path === "/observability") {
      await expect(page.getByRole("heading", { name: "Observability Filters" })).toBeVisible();
      await page.getByLabel("Observability Application").selectOption({ label: "Managed API" });
      await page.getByLabel("Observability Policy").selectOption({ label: "Default Web Protection" });
      await expect
        .poll(() =>
          api.authorizedURLs.some(
            path => path.startsWith("/api/v1/analytics/observability?") && path.includes("application_id=app_managed") && path.includes("policy_id=pol_default")
          )
        )
        .toBe(true);
      await page.getByRole("button", { name: "Clear Observability Filters" }).click();
    } else if (section.path === "/access") {
      await expect(page.getByText("Open Source Self-Hosted")).toBeVisible();
      await expect(page.getByText("Not required")).toBeVisible();
      await expect(page.getByText("System Version")).toBeVisible();
      await expect(page.getByText("go1.26.0")).toBeVisible();
      await page.getByLabel("User Search").fill("Default");
      await page.getByLabel("Role Filter").selectOption("admin");
      await page.getByLabel("Status Filter").selectOption("active");
      await expect
        .poll(() =>
          api.authorizedURLs.some(
            path => path.startsWith("/api/v1/users?") && path.includes("search=Default") && path.includes("role=admin") && path.includes("status=active")
          )
        )
        .toBe(true);
      await page.getByRole("button", { name: "Clear User Filters" }).click();
    }
  }

  for (const legacyRoute of [
    { path: "/log/exceptions", heading: "Events", evidence: "Unhandled exception captured" },
    { path: "/log/crash", heading: "Events", evidence: "Agent crash captured" },
    { path: "/log/audit", heading: "Access & Audit", evidence: "auth.login" },
    { path: "/platform", heading: "Access & Audit", evidence: "User Administration" },
    { path: "/platform/user", heading: "Access & Audit", evidence: "User Lifecycle" },
    { path: "/settings/panel", heading: "Access & Audit", evidence: "Public Console URL" },
    { path: "/settings/alarm", heading: "Access & Audit", evidence: "Alert Interval Seconds" },
    { path: "/settings/systemInfo", heading: "Access & Audit", evidence: "System Version" },
    { path: "/settings/poolVersion", heading: "Agents", evidence: "Agent Artifact Catalog" },
    { path: "/settings/version", heading: "Agents", evidence: "Agent Artifact Upload" }
  ]) {
    await page.goto(legacyRoute.path);
    await expect(page).toHaveURL(new RegExp(`${legacyRoute.path}$`));
    await expect(page.getByRole("heading", { name: legacyRoute.heading, level: 1 })).toBeVisible();
    await expect(page.getByText(legacyRoute.evidence).first()).toBeVisible();
  }
});

test("supports header shortcuts and mobile primary navigation", async ({ page }) => {
  await mockControlPlaneApi(page);
  await page.setViewportSize({ width: 390, height: 800 });
  await page.addInitScript(() => {
    window.localStorage.setItem("ohmyrasp.session_token", "e2e-token");
    window.localStorage.setItem("ohmyrasp.session_user_email", "admin@ohmyrasp.local");
    window.localStorage.setItem("ohmyrasp.session_user_name", "Default Admin");
  });

  await page.goto("/");
  await page.getByRole("link", { name: "Validate Rule" }).click();
  await expect(page).toHaveURL(/\/policies$/);
  await expect(page.getByRole("heading", { name: "Policies", level: 1 })).toBeVisible();

  await page.getByRole("link", { name: "Register Agent" }).click();
  await expect(page).toHaveURL(/\/agents$/);
  await expect(page.getByRole("heading", { name: "Agents", level: 1 })).toBeVisible();

  await page.getByRole("navigation", { name: "Primary mobile" }).getByRole("link", { name: "Access & Audit" }).click();
  await expect(page).toHaveURL(/\/access$/);
  await expect(page.getByRole("heading", { name: "Access & Audit", level: 1 })).toBeVisible();
});

test("submits application, environment, Agent operations, policy, setting, alert, and user lifecycle workflows", async ({ page }) => {
  const api = await mockControlPlaneApi(page);
  await page.addInitScript(() => {
    window.localStorage.setItem("ohmyrasp.session_token", "e2e-token");
    window.localStorage.setItem("ohmyrasp.session_user_email", "admin@ohmyrasp.local");
    window.localStorage.setItem("ohmyrasp.session_user_name", "Default Admin");
  });

  await page.goto("/applications");
  await page.getByLabel("Application Name").fill("Orders API");
  await page.getByLabel("Description").fill("Order processing service");
  await page.getByRole("button", { name: "Create Application" }).click();
  await expect(page.getByText("Created application Orders API. Secret: orders-secret.")).toBeVisible();

  await page.getByLabel("Environment Name").fill("production");
  await page.getByLabel("Kind").selectOption("production");
  await page.getByRole("button", { name: "Create Environment" }).click();
  await expect(page.getByText("Created environment production for Managed API.")).toBeVisible();
  await page.getByRole("button", { name: "Rotate Secret" }).click();
  await expect(page.getByText("Rotated secret for Managed API. Secret: rotated-managed-secret.")).toBeVisible();
  const exportDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export Applications" }).click();
  await exportDownload;
  await expect(page.getByText("Exported 1 applications.")).toBeVisible();
  await page.getByRole("button", { name: "Delete Application" }).click();
  await expect(page.getByText("Deleted application Managed API.")).toBeVisible();

  await page.goto("/agents");
  await page.getByLabel("Application Secret").fill("rotated-managed-secret");
  await page.getByLabel("Agent Hostname").fill("api-2");
  await page.getByLabel("Agent Runtime").fill("java");
  await page.getByRole("textbox", { name: "Agent Version", exact: true }).fill("1.0.1");
  await page.getByRole("button", { name: "Register Agent" }).click();
  await expect(page.getByText("Registered Agent api-2 as agt_api_2.")).toBeVisible();
  await expect(page.getByText("Agent Inventory")).toBeVisible();
  await page.getByLabel("Agent Search").fill("api-1");
  await page.getByLabel("Agent Remark api-1").fill("production primary");
  await page.getByRole("button", { name: "Save Remark" }).click();
  await expect(page.getByText("Saved remark for production primary (api-1).")).toBeVisible();
  await page.getByRole("button", { name: "Ignore Agent" }).click();
  await expect(page.getByText("Ignored production primary (api-1).")).toBeVisible();
  await page.getByRole("button", { name: "Restore Agent" }).click();
  await expect(page.getByText("Restored production primary (api-1).")).toBeVisible();
  const agentCsvDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export Agent CSV" }).click();
  await agentCsvDownload;
  await page.getByLabel("Agent Search").fill("api-2");
  await page.getByLabel("Select api-2").check();
  await page.getByRole("button", { name: "Batch Delete Agents" }).click();
  await expect(page.getByText("Deleted 1 Agents.")).toBeVisible();
  await page.getByLabel("Agent Search").fill("");
  await page.getByLabel("Heartbeat Status").selectOption("offline");
  await page.getByRole("button", { name: "Send Heartbeat" }).click();
  await expect(page.getByText("Heartbeat accepted for api-1: offline.")).toBeVisible();
  await page.getByRole("button", { name: "Pull Policy" }).click();
  await expect(page.getByText("Pulled policy version 3 (active) with 1 rules for api-1.")).toBeVisible();
  await page.getByRole("button", { name: "Reveal Token" }).click();
  await expect(page.getByText("Daemon token: daemon-token")).toBeVisible();
  await page.getByRole("button", { name: "Reset Token" }).click();
  await expect(page.getByText("Rotated daemon token: rotated-daemon-token")).toBeVisible();
  await expect(page.getByText("Agent Artifact Catalog")).toBeVisible();
  await expect(page.getByText("agent-java-linux-17.zip")).toBeVisible();
  await expect(page.getByText("Agent Artifact Upload")).toBeVisible();
  await page.getByLabel("Agent ZIP").setInputFiles({
    name: "operator-agent.zip",
    mimeType: "application/zip",
    buffer: Buffer.from("mock zip package")
  });
  await page.getByLabel("Upload System Type").selectOption("linux");
  await page.getByLabel("Upload Language Version").fill("21");
  await page.getByRole("button", { name: "Upload Artifact" }).click();
  await expect(page.getByText("Uploaded ohmyrasp-agent-java-linux-21.zip")).toBeVisible();
  await page.getByLabel("Artifact Application").selectOption({ label: "Managed API" });
  await page.getByRole("button", { name: "Check Agent Artifact" }).click();
  await expect(page.getByText("Artifact ohmyrasp-agent-java-linux-unknown.zip ready for Managed API.")).toBeVisible();
  await expect(page.getByText("f1d2d2f924e986ac86fdf7b36c94bcdf").last()).toBeVisible();
  await page.getByRole("button", { name: "Download Agent Artifact" }).click();
  await expect(page.getByText("Downloaded ohmyrasp-agent-java-linux-unknown.zip", { exact: false })).toBeVisible();
  await page.getByRole("button", { name: "Bind", exact: true }).first().click();
  await expect(page.getByText("Bound process 4242 to Managed API.")).toBeVisible();
  await page.getByRole("button", { name: "Unbind", exact: true }).first().click();
  await expect(page.getByText("Unbound process 4242.")).toBeVisible();

  await page.goto("/policies");
  await page.getByLabel("Policy Set Name").fill("Runtime Protection");
  await page.getByLabel("Policy Description").fill("Application-specific Java RASP policy set");
  await page.getByRole("button", { name: "Create Policy Set" }).click();
  await expect(page.getByText("Created policy set Runtime Protection.")).toBeVisible();

  await page.getByLabel("Rule Name").fill("Block command execution");
  await page.getByLabel("Expression").fill("Runtime.exec");
  await page.getByRole("button", { name: "Validate Draft" }).click();
  await expect(page.getByText("Rule validation passed.")).toBeVisible();

  await page.getByRole("button", { name: "Test Draft" }).click();
  await expect(page.getByText("Rule test matched: block at 80% confidence.")).toBeVisible();

  await page.getByRole("button", { name: "Create Version" }).click();
  await expect(page.getByText("Created policy version 4.")).toBeVisible();

  await page.getByLabel("Rule Name").fill("Block edited command execution");
  await page.getByRole("button", { name: "Update Draft" }).click();
  await expect(page.getByText("Updated policy version 4.")).toBeVisible();

  await page.getByLabel("Rollout Scope").selectOption({ label: "Managed API" });
  await page.getByLabel("Canary Percent").fill("50");
  await page.getByRole("button", { name: "Roll Out Version" }).click();
  await expect(page.getByText("Rolled out version 4 to 50% for Managed API.")).toBeVisible();
  await page.getByRole("button", { name: "Restore Defaults" }).click();
  await expect(page.getByText("Restored default algorithms as draft version 5.")).toBeVisible();

  await page.goto("/events");
  await expect(page.getByText("Event Recycle Bin")).toBeVisible();
  await page.getByLabel("Recycle Event ID").selectOption("evt_1");
  await page.getByRole("button", { name: "Move Event To Recycle Bin" }).click();
  await expect(page.getByText("Moved 1 event.")).toBeVisible();
  await page.getByRole("button", { name: "Restore Event" }).click();
  await expect(page.getByText("Restored 1 event.")).toBeVisible();
  await page.getByRole("button", { name: "Move Event To Recycle Bin" }).click();
  await expect(page.getByText("Moved 1 event.")).toBeVisible();
  await page.getByRole("button", { name: "Permanently Delete Event" }).click();
  await expect(page.getByText("Purged 1 event.")).toBeVisible();

  await page.goto("/access");
  await page.getByLabel("Public Console URL").fill("http://localhost:18091");
  await page.getByLabel("Allowlist Enabled").check();
  await page.getByLabel("Allowlist Mode").selectOption("enforce");
  await page.getByLabel("Allowlist Entries").fill("/admin/*\n10.0.0.0/8");
  await page.getByLabel("Hardening Mode").selectOption("enforce");
  await page.getByLabel("Block Process Execution").uncheck();
  await page.getByLabel("Vulnerability Threshold").selectOption("high");
  await page.getByLabel("Attack Retention Days").fill("120");
  await page.getByLabel("Performance Retention Days").fill("45");
  await page.getByLabel("Dependency Retention Days").fill("400");
  await page.getByLabel("Audit Retention Days").fill("730");
  await page.getByRole("button", { name: "Save Protection Configuration" }).click();
  await expect(page.getByText("Protection configuration saved.")).toBeVisible();
  await page.getByLabel("Cleanup Before").fill("2026-01-01");
  await page.getByLabel("Cleanup Application ID").fill("app_managed");
  await page.getByRole("button", { name: "Preview Cleanup" }).click();
  await expect(page.getByText("Previewed cleanup for 7 records.")).toBeVisible();
  await page.getByLabel("Cleanup Confirmation").fill("CLEAR_OPERATIONAL_DATA");
  await page.getByRole("button", { name: "Apply Cleanup" }).click();
  await expect(page.getByText("Applied cleanup for 7 records.")).toBeVisible();

  await page.getByLabel("Value JSON").fill('{"version":"1.2.0"}');
  await page.getByRole("button", { name: "Save Setting" }).click();
  await expect(page.getByText("Setting saved.")).toBeVisible();

  await page.locator("#alert-name").fill("Critical attack escalation");
  await page.locator("#alert-target").fill("secops-pager");
  await page.getByRole("button", { name: "Create Alert Rule" }).click();
  await expect(page.getByText("Alert rule created.")).toBeVisible();

  await page.locator("#alert-lifecycle-rule").selectOption({ label: "Critical attack event" });
  await page.locator("#alert-lifecycle-name").fill("Critical attack escalation updated");
  await page.locator("#alert-lifecycle-description").fill("Escalate critical and high attacks");
  await page.locator("#alert-lifecycle-severity").selectOption("high");
  await page.locator("#alert-lifecycle-condition").fill("severity == high");
  await page.locator("#alert-lifecycle-target").fill("secops-primary");
  await page.locator("#alert-lifecycle-enabled").uncheck();
  await page.getByRole("button", { name: "Update Alert Rule" }).click();
  await expect(page.getByText("Updated alert rule Critical attack escalation updated.")).toBeVisible();

  await page.getByLabel("Email").fill("new-analyst@ohmyrasp.local");
  await page.getByLabel("Name").nth(1).fill("New Analyst");
  await page.getByLabel("Password").fill("new-analyst-password");
  await page.getByRole("button", { name: "Create User" }).click();
  await expect(page.getByText("User created.")).toBeVisible();

  await page.getByLabel("User Account").selectOption({ label: "Default Admin" });
  await page.getByLabel("User Display Name").fill("Default Administrator");
  await page.getByLabel("User Role").selectOption("admin");
  await page.getByLabel("Disable User").check();
  await page.getByRole("button", { name: "Update User" }).click();
  await expect(page.getByText("Updated user admin@ohmyrasp.local.")).toBeVisible();

  expect(api.writeRequests).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        method: "POST",
        path: "/api/v1/applications",
        body: { name: "Orders API", description: "Order processing service" }
      }),
      expect.objectContaining({
        method: "POST",
        path: "/api/v1/applications/app_managed/environments",
        body: { name: "production", kind: "production" }
      }),
      expect.objectContaining({
        authorization: "Bearer e2e-token",
        method: "POST",
        path: "/api/v1/applications/app_managed/secret/rotate",
        body: {}
      }),
      expect.objectContaining({
        authorization: "Bearer e2e-token",
        method: "DELETE",
        path: "/api/v1/applications/app_managed",
        body: {}
      }),
      expect.objectContaining({
        applicationID: "app_managed",
        applicationSecret: "rotated-managed-secret",
        authorization: undefined,
        method: "POST",
        path: "/api/v1/agents/register",
        body: { environment_id: "env_prod", hostname: "api-2", runtime: "java", version: "1.0.1" }
      }),
      expect.objectContaining({
        authorization: "Bearer e2e-token",
        method: "PUT",
        path: "/api/v1/agents/agt_api_1/alias",
        body: { alias: "production primary" }
      }),
      expect.objectContaining({
        authorization: "Bearer e2e-token",
        method: "POST",
        path: "/api/v1/agents/agt_api_1/ignore",
        body: { ignored: true }
      }),
      expect.objectContaining({
        authorization: "Bearer e2e-token",
        method: "POST",
        path: "/api/v1/agents/agt_api_1/ignore",
        body: { ignored: false }
      }),
      expect.objectContaining({
        authorization: "Bearer e2e-token",
        method: "POST",
        path: "/api/v1/agents/batch-delete",
        body: { ids: ["agt_api_2"] }
      }),
      expect.objectContaining({
        applicationID: "app_managed",
        applicationSecret: "rotated-managed-secret",
        authorization: undefined,
        method: "POST",
        path: "/api/v1/agents/agt_api_1/heartbeat",
        body: { status: "offline" }
      }),
      expect.objectContaining({
        authorization: "Bearer e2e-token",
        method: "POST",
        path: "/api/v1/daemon/token/reset",
        body: {}
      }),
      expect.objectContaining({
        authorization: "Bearer e2e-token",
        method: "POST",
        path: "/api/v1/daemon/workloads/wrk_node_process/bind",
        body: { application_id: "app_managed" }
      }),
      expect.objectContaining({
        authorization: "Bearer e2e-token",
        method: "POST",
        path: "/api/v1/daemon/workloads/wrk_node_process/unbind",
        body: {}
      }),
      expect.objectContaining({
        method: "POST",
        path: "/api/v1/policies",
        body: { name: "Runtime Protection", description: "Application-specific Java RASP policy set" }
      }),
      expect.objectContaining({
        method: "POST",
        path: "/api/v1/policies/validate",
        body: expect.objectContaining({
          rules: [expect.objectContaining({ name: "Block command execution", expression: "Runtime.exec" })]
        })
      }),
      expect.objectContaining({
        method: "POST",
        path: "/api/v1/policies/test",
        body: expect.objectContaining({
          rule: expect.objectContaining({ name: "Block command execution", expression: "Runtime.exec" }),
          event: expect.objectContaining({ hook: "sql", message: "SQL tautology blocked" })
        })
      }),
      expect.objectContaining({
        method: "POST",
        path: "/api/v1/policies/pol_default/versions",
        body: expect.objectContaining({
          rules: [expect.objectContaining({ name: "Block command execution", expression: "Runtime.exec" })]
        })
      }),
      expect.objectContaining({
        method: "POST",
        path: "/api/v1/policies/pol_default/rollout",
        body: { version: 4, canary_percent: 50, application_id: "app_managed" }
      }),
      expect.objectContaining({
        method: "POST",
        path: "/api/v1/policies/pol_default/restore-default",
        body: {}
      }),
      expect.objectContaining({
        method: "POST",
        path: "/api/v1/events/recycle-bin/delete",
        body: { ids: ["evt_1"] }
      }),
      expect.objectContaining({
        method: "POST",
        path: "/api/v1/events/recycle-bin/restore",
        body: { ids: ["evt_1"] }
      }),
      expect.objectContaining({
        method: "POST",
        path: "/api/v1/events/recycle-bin/purge",
        body: { ids: ["evt_1"] }
      }),
      expect.objectContaining({
        method: "PUT",
        path: "/api/v1/system-settings/server.public_url",
        body: { value: { url: "http://localhost:18091" } }
      }),
      expect.objectContaining({
        method: "PUT",
        path: "/api/v1/system-settings/protection.allowlist",
        body: { value: { enabled: true, mode: "enforce", entries: ["/admin/*", "10.0.0.0/8"] } }
      }),
      expect.objectContaining({
        method: "PUT",
        path: "/api/v1/system-settings/protection.hardening",
        body: { value: { mode: "enforce", block_reflection_abuse: true, block_process_execution: false } }
      }),
      expect.objectContaining({
        method: "PUT",
        path: "/api/v1/system-settings/dependency.vulnerability_policy",
        body: { value: { fail_on_severity: "high", block_known_exploited: true } }
      }),
      expect.objectContaining({
        method: "PUT",
        path: "/api/v1/system-settings/alerts.delivery",
        body: { value: { interval_seconds: 300 } }
      }),
      expect.objectContaining({
        method: "PUT",
        path: "/api/v1/system-settings/events.retention",
        body: { value: { attack_days: 120, performance_days: 45, dependency_days: 400, audit_days: 730 } }
      }),
      expect.objectContaining({
        method: "POST",
        path: "/api/v1/maintenance/cleanup",
        body: expect.objectContaining({ application_id: "app_managed", before: "2026-01-01T00:00:00.000Z", dry_run: true })
      }),
      expect.objectContaining({
        method: "POST",
        path: "/api/v1/maintenance/cleanup",
        body: expect.objectContaining({
          application_id: "app_managed",
          before: "2026-01-01T00:00:00.000Z",
          dry_run: false,
          confirmation: "CLEAR_OPERATIONAL_DATA"
        })
      }),
      expect.objectContaining({
        method: "PUT",
        path: "/api/v1/system-settings/agent.minimum_version",
        body: { value: { version: "1.2.0" } }
      }),
      expect.objectContaining({
        method: "POST",
        path: "/api/v1/alert-rules",
        body: expect.objectContaining({ name: "Critical attack escalation", target: "secops-pager" })
      }),
      expect.objectContaining({
        method: "PUT",
        path: "/api/v1/alert-rules/alr_critical_attack",
        body: {
          name: "Critical attack escalation updated",
          description: "Escalate critical and high attacks",
          enabled: false,
          event_type: "attack",
          severity: "high",
          condition: "severity == high",
          target: "secops-primary"
        }
      }),
      expect.objectContaining({
        method: "POST",
        path: "/api/v1/users",
        body: expect.objectContaining({ email: "new-analyst@ohmyrasp.local", name: "New Analyst", roles: ["security_engineer"] })
      }),
      expect.objectContaining({
        method: "PUT",
        path: "/api/v1/users/usr_admin",
        body: { name: "Default Administrator", roles: ["admin"], disabled: true }
      })
    ])
  );
  expect(api.writeRequests.filter(request => !["/api/v1/agents/register", "/api/v1/agents/agt_api_1/heartbeat"].includes(request.path)).every(request => request.authorization === "Bearer e2e-token")).toBe(true);
  expect(api.agentCredentialPaths).toEqual(expect.arrayContaining(["/api/v1/agents/agt_api_1/heartbeat", "/api/v1/agents/agt_api_1/policy"]));
});

async function mockControlPlaneApi(page: Page) {
  const authorizedPaths: string[] = [];
  const authorizedURLs: string[] = [];
  const agentCredentialPaths: string[] = [];
  const writeRequests: Array<{ applicationID?: string; applicationSecret?: string; authorization?: string; body: unknown; method: string; path: string }> = [];

  await page.route("**/api/v1/**", async route => {
    const request = route.request();
    const url = new URL(request.url());
    const auth = request.headers().authorization;
    if (auth === "Bearer e2e-token") {
      authorizedPaths.push(url.pathname);
      authorizedURLs.push(`${url.pathname}${url.search}`);
    }
    if (request.headers()["x-ohmyrasp-app-id"] && request.headers()["x-ohmyrasp-app-secret"]) {
      agentCredentialPaths.push(url.pathname);
    }

    if (request.method() === "GET" && url.pathname === "/api/v1/daemon/app") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          application_id: url.searchParams.get("app_id") ?? "app_managed",
          application_secret: "rotated-managed-secret",
          language: "java"
        })
      });
      return;
    }

    if (request.method() === "GET" && url.pathname === "/api/v1/daemon/artifacts/agent/info") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          filename: "ohmyrasp-agent-java-linux-unknown.zip",
          content_type: "application/zip",
          md5: "f1d2d2f924e986ac86fdf7b36c94bcdf",
          size: 4096,
          language: url.searchParams.get("language") ?? "java",
          system_type: url.searchParams.get("system_type") ?? "linux",
          language_version: url.searchParams.get("language_version") ?? "unknown"
        })
      });
      return;
    }

    if (request.method() === "GET" && url.pathname === "/api/v1/daemon/artifacts/agent") {
      await route.fulfill({
        status: 200,
        contentType: "application/zip",
        headers: {
          "Content-Disposition": 'attachment; filename="ohmyrasp-agent-java-linux-unknown.zip"',
          "X-OhMyRasp-Agent-MD5": "f1d2d2f924e986ac86fdf7b36c94bcdf"
        },
        body: "mock-zip"
      });
      return;
    }

    if (url.pathname === "/api/v1/auth/login") {
      const body = request.postDataJSON() as { email?: string; password?: string };
      if (body.email !== "admin@ohmyrasp.local" || body.password !== "change-me") {
        await route.fulfill({
          status: 401,
          contentType: "application/json",
          body: JSON.stringify({ error: "unauthorized", message: "invalid credentials" })
        });
        return;
      }
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          session: {
            token: "e2e-token",
            user_id: "usr_admin",
            expires_at: "2026-06-01T00:00:00Z"
          },
          user: {
            id: "usr_admin",
            email: "admin@ohmyrasp.local",
            name: "Default Admin",
            roles: ["admin", "security_engineer"],
            created_at: "2026-05-31T00:00:00Z",
            updated_at: "2026-05-31T00:00:00Z"
          }
        })
      });
      return;
    }

    if (request.method() !== "GET") {
      const body = request.postData() ? request.postDataJSON() as Record<string, unknown> : {};
      writeRequests.push({
        applicationID: request.headers()["x-ohmyrasp-app-id"],
        applicationSecret: request.headers()["x-ohmyrasp-app-secret"],
        authorization: auth,
        body,
        method: request.method(),
        path: url.pathname
      });
      await fulfillWrite(route, url.pathname, request.method(), body);
      return;
    }

    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(apiFixtures[url.pathname] ?? { items: [] })
    });
  });

  return { agentCredentialPaths, authorizedPaths, authorizedURLs, writeRequests };
}

async function fulfillWrite(route: Route, path: string, method: string, body: Record<string, unknown>) {
  if (method === "POST" && path === "/api/v1/applications") {
    await route.fulfill({
      status: 201,
      contentType: "application/json",
      body: JSON.stringify({
        id: "app_orders",
        name: body.name,
        description: body.description ?? "",
        secret: "orders-secret",
        created_at: "2026-05-31T01:00:00Z",
        environment_ids: []
      })
    });
    return;
  }

  if (method === "POST" && path === "/api/v1/applications/app_managed/environments") {
    await route.fulfill({
      status: 201,
      contentType: "application/json",
      body: JSON.stringify({
        id: "env_prod_new",
        application_id: "app_managed",
        name: body.name,
        kind: body.kind,
        created_at: "2026-05-31T01:00:00Z"
      })
    });
    return;
  }

  if (method === "POST" && path === "/api/v1/applications/app_managed/secret/rotate") {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        id: "app_managed",
        name: "Managed API",
        description: "Playwright managed application",
        secret: "rotated-managed-secret",
        created_at: "2026-05-31T00:00:00Z",
        environment_ids: ["env_prod", "env_staging", "env_prod_new"]
      })
    });
    return;
  }

  if (method === "DELETE" && path === "/api/v1/applications/app_managed") {
    await route.fulfill({ status: 204 });
    return;
  }

  if (method === "POST" && path === "/api/v1/agents/register") {
    const agent = {
      id: "agt_api_2",
      application_id: "app_managed",
      environment_id: body.environment_id,
      hostname: body.hostname,
      runtime: body.runtime,
      version: body.version,
      status: "online",
      last_seen_at: "2026-05-31T01:00:00Z"
    };
    const agents = apiFixtures["/api/v1/agents"] as { items: Array<Record<string, unknown>> };
    if (!agents.items.some(item => item.id === agent.id)) {
      agents.items.push(agent);
    }
    await route.fulfill({
      status: 201,
      contentType: "application/json",
      body: JSON.stringify(agent)
    });
    return;
  }

  if (method === "PUT" && path === "/api/v1/agents/agt_api_1/alias") {
    const agents = apiFixtures["/api/v1/agents"] as { items: Array<Record<string, unknown>> };
    const agent = agents.items.find(item => item.id === "agt_api_1");
    if (agent) {
      agent.alias = body.alias;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(agent)
    });
    return;
  }

  if (method === "POST" && path === "/api/v1/agents/agt_api_1/ignore") {
    const agents = apiFixtures["/api/v1/agents"] as { items: Array<Record<string, unknown>> };
    const agent = agents.items.find(item => item.id === "agt_api_1");
    if (agent && body.ignored) {
      agent.ignored_at = "2026-05-31T01:00:00Z";
    } else if (agent) {
      delete agent.ignored_at;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(agent)
    });
    return;
  }

  if (method === "POST" && path === "/api/v1/agents/batch-delete") {
    const ids = body.ids as string[];
    const agents = apiFixtures["/api/v1/agents"] as { items: Array<Record<string, unknown>> };
    const before = agents.items.length;
    agents.items = agents.items.filter(item => !ids.includes(String(item.id)));
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ ids, count: before - agents.items.length })
    });
    return;
  }

  if (method === "POST" && path === "/api/v1/agents/agt_api_1/heartbeat") {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        id: "agt_api_1",
        application_id: "app_managed",
        environment_id: "env_prod",
        hostname: "api-1",
        runtime: "java",
        version: "1.0.0",
        status: body.status,
        last_seen_at: "2026-05-31T01:00:00Z",
        policy_id: "pol_default",
        policy_version: 3
      })
    });
    return;
  }

  if (method === "POST" && path === "/api/v1/daemon/token/reset") {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        access_token: "rotated-daemon-token",
        updated_at: "2026-05-31T01:00:00Z"
      })
    });
    return;
  }

  if (method === "POST" && path === "/api/v1/agent-artifacts") {
    const item = {
      filename: `ohmyrasp-agent-${body.language}-${body.system_type}-${body.language_version}.zip`,
      content_type: "application/zip",
      md5: "2df64a3a9912a4cddf4241b9f2cbe944",
      size: 16,
      language: body.language,
      system_type: body.system_type,
      language_version: body.language_version,
      source: "uploaded",
      updated_at: "2026-05-31T01:00:00Z"
    };
    const catalog = apiFixtures["/api/v1/agent-artifacts"] as { items: unknown[] };
    catalog.items.push(item);
    await route.fulfill({
      status: 201,
      contentType: "application/json",
      body: JSON.stringify(item)
    });
    return;
  }

  if (method === "POST" && path === "/api/v1/daemon/workloads/wrk_node_process/bind") {
    const workloads = apiFixtures["/api/v1/daemon/workloads"] as { items: Array<Record<string, unknown>> };
    workloads.items[0].application_id = body.application_id;
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(workloads.items[0])
    });
    return;
  }

  if (method === "POST" && path === "/api/v1/daemon/workloads/wrk_node_process/unbind") {
    const workloads = apiFixtures["/api/v1/daemon/workloads"] as { items: Array<Record<string, unknown>> };
    delete workloads.items[0].application_id;
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(workloads.items[0])
    });
    return;
  }

  if (method === "POST" && path === "/api/v1/policies") {
    await route.fulfill({
      status: 201,
      contentType: "application/json",
      body: JSON.stringify({
        id: "pol_runtime",
        name: body.name,
        description: body.description ?? "",
        created_at: "2026-05-31T01:00:00Z",
        versions: []
      })
    });
    return;
  }

  if (method === "POST" && path === "/api/v1/policies/validate") {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ valid: true, errors: [] })
    });
    return;
  }

  if (method === "POST" && path === "/api/v1/policies/test") {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ matched: true, action: "block", algorithm: "process_match", confidence: 80 })
    });
    return;
  }

  if (method === "POST" && path === "/api/v1/policies/pol_default/versions") {
    const rules = body.rules as unknown[];
    await route.fulfill({
      status: 201,
      contentType: "application/json",
      body: JSON.stringify({
        ...policyFixture(),
        versions: [
          policyFixture().active,
          {
            version: 4,
            status: "draft",
            canary_percent: 0,
            created_at: "2026-05-31T01:00:00Z",
            rules
          }
        ]
      })
    });
    return;
  }

  if (method === "PUT" && path === "/api/v1/policies/pol_default/versions/4/rules") {
    const rules = body.rules as unknown[];
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        ...policyFixture(),
        versions: [
          policyFixture().active,
          {
            version: 4,
            status: "draft",
            canary_percent: 0,
            created_at: "2026-05-31T01:00:00Z",
            rules
          }
        ]
      })
    });
    return;
  }

  if (method === "POST" && path === "/api/v1/policies/pol_default/rollout") {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        ...policyFixture(),
        active: {
          version: body.version,
          status: "active",
          canary_percent: body.canary_percent,
          created_at: "2026-05-31T01:00:00Z",
          rules: policyFixture().active.rules
        }
      })
    });
    return;
  }

  if (method === "POST" && path === "/api/v1/policies/pol_default/restore-default") {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        ...policyFixture(),
        versions: [
          policyFixture().active,
          {
            version: 5,
            status: "draft",
            canary_percent: 0,
            created_at: "2026-05-31T01:05:00Z",
            rules: [
              {
                id: "rul_default_sql",
                name: "Default sql userinput",
                hook: "sql",
                algorithm: "sql_userinput",
                action: "block",
                severity: "critical",
                expression: "algorithm == \"sql_userinput\"",
                tags: ["default", "sql"],
                description: "Built-in default detector rule restored from the algorithm catalog."
              }
            ]
          }
        ]
      })
    });
    return;
  }

  if (method === "PUT" && path.startsWith("/api/v1/system-settings/")) {
    const key = decodeURIComponent(path.slice("/api/v1/system-settings/".length));
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        key,
        value: body.value,
        updated_by: "usr_admin",
        updated_at: "2026-05-31T01:00:00Z"
      })
    });
    return;
  }

  if (method === "POST" && path === "/api/v1/maintenance/cleanup") {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        dry_run: body.dry_run,
        before: body.before,
        application_id: body.application_id,
        counts: {
          events: 2,
          dependencies: 1,
          baseline_findings: 1,
          alert_deliveries: 1,
          clickhouse_events: 1,
          clickhouse_rollups: 1
        }
      })
    });
    return;
  }

  if (method === "POST" && path === "/api/v1/events/recycle-bin/delete") {
    const ids = body.ids as string[];
    const deleted = apiFixtures["/api/v1/events/recycle-bin"] as { items: Array<Record<string, unknown>> };
    for (const id of ids) {
      for (const eventPath of ["/api/v1/events/attack", "/api/v1/events/hook", "/api/v1/events/performance", "/api/v1/events/crash", "/api/v1/events/error"]) {
        const active = apiFixtures[eventPath] as { items: Array<Record<string, unknown>> };
        const index = active.items.findIndex(item => item.id === id);
        if (index >= 0) {
          const [event] = active.items.splice(index, 1);
          deleted.items.push({ ...event, deleted_at: "2026-05-31T01:00:00Z", deleted_by: "usr_admin" });
        }
      }
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ ids, count: ids.length })
    });
    return;
  }

  if (method === "POST" && path === "/api/v1/events/recycle-bin/restore") {
    const ids = body.ids as string[];
    const deleted = apiFixtures["/api/v1/events/recycle-bin"] as { items: Array<Record<string, unknown>> };
    for (const id of ids) {
      const index = deleted.items.findIndex(item => item.id === id);
      if (index >= 0) {
        const [event] = deleted.items.splice(index, 1);
        const type = String(event.type);
        const active = apiFixtures[`/api/v1/events/${type}`] as { items: Array<Record<string, unknown>> };
        const { deleted_at, deleted_by, ...restored } = event;
        void deleted_at;
        void deleted_by;
        active.items.push(restored);
      }
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ ids, count: ids.length })
    });
    return;
  }

  if (method === "POST" && path === "/api/v1/events/recycle-bin/purge") {
    const ids = body.ids as string[];
    const deleted = apiFixtures["/api/v1/events/recycle-bin"] as { items: Array<Record<string, unknown>> };
    deleted.items = deleted.items.filter(item => !ids.includes(String(item.id)));
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ ids, count: ids.length })
    });
    return;
  }

  if (method === "POST" && path === "/api/v1/alert-rules") {
    await route.fulfill({
      status: 201,
      contentType: "application/json",
      body: JSON.stringify({
        id: "alr_new",
        ...body,
        created_at: "2026-05-31T01:00:00Z",
        updated_at: "2026-05-31T01:00:00Z"
      })
    });
    return;
  }

  if (method === "PUT" && path === "/api/v1/alert-rules/alr_critical_attack") {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        id: "alr_critical_attack",
        ...body,
        created_at: "2026-05-31T00:00:00Z",
        updated_at: "2026-05-31T01:00:00Z"
      })
    });
    return;
  }

  if (method === "POST" && path === "/api/v1/users") {
    await route.fulfill({
      status: 201,
      contentType: "application/json",
      body: JSON.stringify({
        id: "usr_new",
        email: body.email,
        name: body.name,
        roles: body.roles,
        created_at: "2026-05-31T01:00:00Z",
        updated_at: "2026-05-31T01:00:00Z"
      })
    });
    return;
  }

  if (method === "PUT" && path === "/api/v1/users/usr_admin") {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        id: "usr_admin",
        email: "admin@ohmyrasp.local",
        name: body.name,
        roles: body.roles,
        created_at: "2026-05-31T00:00:00Z",
        updated_at: "2026-05-31T01:00:00Z",
        disabled_at: body.disabled ? "2026-05-31T01:00:00Z" : undefined
      })
    });
    return;
  }

  await route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({})
  });
}

function policyFixture() {
  return {
    id: "pol_default",
    name: "Default Web Protection",
    description: "SQL and command protections",
    created_at: "2026-05-31T00:00:00Z",
    active: {
      version: 3,
      status: "active",
      canary_percent: 100,
      created_at: "2026-05-31T00:00:00Z",
      rules: [
        {
          id: "rul_sql",
          name: "Block SQL",
          hook: "sql",
          algorithm: "sql_userinput",
          action: "block",
          severity: "high",
          expression: "' OR '1'='1",
          tags: ["sql"],
          description: "Blocks SQL tautologies"
        }
      ]
    },
    versions: []
  };
}

const apiFixtures: Record<string, unknown> = {
  "/api/v1/analytics/overview": {
    application_count: 2,
    agent_count: 3,
    online_agents: 2,
    event_count: 5,
    events_by_type: { attack: 5 },
    events_by_severity: { critical: 1, high: 4 },
    attack_trend: [
      { bucket_start: "2026-05-30T00:00:00Z", count: 2 },
      { bucket_start: "2026-05-31T00:00:00Z", count: 3 }
    ],
    attacks_by_hook: { sql: 3, command: 2 },
    attacks_by_algorithm: { sql_policy: 3, command_userinput: 2 },
    attacks_by_user_agent: { "curl/8.0": 3, "sqlmap/1.8": 2 },
    crash_count: 1
  },
  "/api/v1/applications": {
    items: [
      {
        id: "app_managed",
        name: "Managed API",
        description: "Playwright managed application",
        created_at: "2026-05-31T00:00:00Z",
        environment_ids: ["env_prod", "env_staging"]
      }
    ]
  },
  "/api/v1/applications/export": {
    items: [
      {
        id: "app_managed",
        name: "Managed API",
        description: "Playwright managed application",
        created_at: "2026-05-31T00:00:00Z",
        environment_ids: ["env_prod", "env_staging"]
      }
    ]
  },
  "/api/v1/agents": {
    items: [
      {
        id: "agt_api_1",
        application_id: "app_managed",
        environment_id: "env_prod",
        hostname: "api-1",
        runtime: "java",
        version: "1.0.0",
        status: "online",
        last_seen_at: "2026-05-31T00:00:00Z",
        policy_id: "pol_default",
        policy_version: 3
      }
    ]
  },
  "/api/v1/agents/agt_api_1/policy": policyFixture().active,
  "/api/v1/daemon/token": {
    access_token: "daemon-token",
    updated_at: "2026-05-31T00:00:00Z"
  },
  "/api/v1/daemon/workloads": {
    items: [
      {
        id: "wrk_node_process",
        node_name: "node-a",
        type: "process",
        pid: 4242,
        cmdline: ["/usr/bin/java", "-jar", "app.jar"],
        observed_at: "2026-05-31T00:00:00Z",
        updated_at: "2026-05-31T00:00:00Z"
      },
      {
        id: "wrk_node_container",
        node_name: "node-a",
        type: "container",
        container_id: "ctr_abc",
        container_name: "managed-api",
        image_tag: "managed:1.0.0",
        observed_at: "2026-05-31T00:00:00Z",
        updated_at: "2026-05-31T00:00:00Z"
      }
    ]
  },
  "/api/v1/agent-artifacts": {
    artifact_dir_configured: true,
    generated_bootstrap_enabled: false,
    items: [
      {
        filename: "agent-java-linux-17.zip",
        content_type: "application/zip",
        md5: "f1d2d2f924e986ac86fdf7b36c94bcdf",
        size: 4096,
        language: "java",
        system_type: "linux",
        language_version: "17",
        source: "filesystem",
        updated_at: "2026-05-31T00:00:00Z"
      }
    ]
  },
  "/api/v1/policies": {
    items: [policyFixture()]
  },
  "/api/v1/policies/algorithms": {
    items: [
      { hook: "process", algorithms: ["process_match"] },
      { hook: "command", algorithms: ["command_common", "command_userinput"] },
      { hook: "sql", algorithms: ["sql_policy", "sql_regex", "sql_userinput"] },
      { hook: "jndi", algorithms: ["jndi_disable_all"] }
    ]
  },
  "/api/v1/events/attack": {
    items: [
      {
        id: "evt_1",
        type: "attack",
        application_id: "app_managed",
        environment_id: "env_prod",
        agent_id: "agt_api_1",
        policy_id: "pol_default",
        policy_version: 3,
        hook: "sql",
        algorithm: "sql_userinput",
        severity: "critical",
        message: "SQL tautology blocked",
        occurred_at: "2026-05-31T00:00:00Z"
      }
    ]
  },
  "/api/v1/events/hook": {
    items: [
      {
        id: "evt_hook_1",
        type: "hook",
        application_id: "app_managed",
        environment_id: "env_prod",
        agent_id: "agt_api_1",
        hook: "servlet",
        severity: "low",
        message: "Servlet hook sampled",
        occurred_at: "2026-05-31T00:00:00Z"
      }
    ]
  },
  "/api/v1/events/performance": {
    items: [
      {
        id: "evt_perf_1",
        type: "performance",
        application_id: "app_managed",
        environment_id: "env_prod",
        agent_id: "agt_api_1",
        hook: "sql",
        severity: "low",
        message: "Policy overhead sampled",
        occurred_at: "2026-05-31T00:00:00Z"
      }
    ]
  },
  "/api/v1/events/crash": {
    items: [
      {
        id: "evt_crash_1",
        type: "crash",
        application_id: "app_managed",
        environment_id: "env_prod",
        agent_id: "agt_api_1",
        severity: "high",
        message: "Agent crash captured",
        occurred_at: "2026-05-31T00:00:00Z"
      }
    ]
  },
  "/api/v1/events/error": {
    items: [
      {
        id: "evt_error_1",
        type: "error",
        application_id: "app_managed",
        environment_id: "env_prod",
        agent_id: "agt_api_1",
        hook: "servlet",
        severity: "high",
        message: "Unhandled exception captured",
        occurred_at: "2026-05-31T00:00:00Z",
        attributes: {
          exception_class: "java.lang.IllegalStateException",
          stack: "CheckoutController.checkout:42"
        }
      }
    ]
  },
  "/api/v1/events/recycle-bin": {
    items: []
  },
  "/api/v1/dependencies": {
    items: [
      {
        id: "dep_1",
        application_id: "app_managed",
        agent_id: "agt_api_1",
        name: "spring-web",
        version: "6.2.0",
        ecosystem: "maven",
        package_path: "org/springframework/spring-web/6.2.0/spring-web-6.2.0.jar",
        licenses: ["Apache-2.0"],
        vulnerabilities: [
          {
            id: "CVE-2026-0001",
            severity: "critical",
            cvss: 9.1,
            known_exploited: true,
            fixed_version: "6.2.1"
          }
        ],
        observed_at: "2026-05-31T00:00:00Z"
      }
    ]
  },
  "/api/v1/dependencies/export": {
    items: [
      {
        id: "dep_1",
        application_id: "app_managed",
        agent_id: "agt_api_1",
        name: "spring-web",
        version: "6.2.0",
        ecosystem: "maven",
        package_path: "org/springframework/spring-web/6.2.0/spring-web-6.2.0.jar",
        licenses: ["Apache-2.0"],
        vulnerabilities: [
          {
            id: "CVE-2026-0001",
            severity: "critical",
            cvss: 9.1,
            known_exploited: true,
            fixed_version: "6.2.1"
          }
        ],
        observed_at: "2026-05-31T00:00:00Z"
      }
    ]
  },
  "/api/v1/dependencies/summary": {
    dependency_count: 1,
    vulnerable_dependency_count: 1,
    known_exploited_count: 1,
    dependencies_by_ecosystem: { maven: 1 },
    vulnerabilities_by_severity: { critical: 1 }
  },
  "/api/v1/baseline-findings": {
    items: [
      {
        id: "bsl_1",
        application_id: "app_managed",
        environment_id: "env_prod",
        agent_id: "agt_api_1",
        check_id: "jvm.security_manager",
        title: "JVM security manager disabled",
        category: "runtime",
        severity: "medium",
        status: "warning",
        resource: "api-1",
        remediation: "Enable explicit runtime hardening before rollout.",
        attributes: { runtime: "java" },
        observed_at: "2026-05-31T00:00:00Z"
      }
    ]
  },
  "/api/v1/analytics/observability": {
    rule_overhead: [
      {
        policy_id: "pol_default",
        policy_version: 3,
        rule_id: "rul_sql",
        hook: "sql",
        executions: 100,
        blocked: 4,
        average_latency_us: 410,
        p95_latency_us: 1800,
        max_latency_us: 2400
      }
    ],
    hook_latency: [{ hook: "sql", calls: 100, average_latency_us: 410, p95_latency_us: 1800, max_latency_us: 2400 }],
    agent_overhead: [{ agent_id: "agt_api_1", samples: 60, cpu_overhead_pct: 1.4, memory_overhead_bytes: 52428800, hook_latency_p95_us: 1800, rule_eval_p95_us: 900 }],
    policy_performance: [{ policy_id: "pol_default", policy_version: 3, samples: 60, cpu_overhead_pct: 1.4, hook_latency_p95_us: 1800, rule_eval_p95_us: 900 }]
  },
  "/api/v1/audit-logs": {
    items: [
      {
        id: "aud_1",
        actor_id: "usr_admin",
        action: "auth.login",
        resource: "session",
        details: { email: "admin@ohmyrasp.local" },
        created_at: "2026-05-31T00:00:00Z"
      }
    ]
  },
  "/api/v1/system-settings": {
    items: [
      { key: "server.public_url", value: { url: "" }, updated_by: "system", updated_at: "2026-05-31T00:00:00Z" },
      { key: "agent.minimum_version", value: { version: "1.0.0" }, updated_by: "usr_admin", updated_at: "2026-05-31T00:00:00Z" },
      { key: "alerts.delivery", value: { interval_seconds: 300 }, updated_by: "system", updated_at: "2026-05-31T00:00:00Z" },
      { key: "events.retention", value: { attack_days: 180, performance_days: 30, dependency_days: 365, audit_days: 365 }, updated_by: "system", updated_at: "2026-05-31T00:00:00Z" },
      { key: "protection.allowlist", value: { enabled: false, mode: "monitor", entries: [] }, updated_by: "system", updated_at: "2026-05-31T00:00:00Z" },
      {
        key: "protection.hardening",
        value: { mode: "monitor", block_reflection_abuse: true, block_process_execution: true },
        updated_by: "system",
        updated_at: "2026-05-31T00:00:00Z"
      },
      {
        key: "dependency.vulnerability_policy",
        value: { fail_on_severity: "critical", block_known_exploited: true },
        updated_by: "system",
        updated_at: "2026-05-31T00:00:00Z"
      }
    ]
  },
  "/api/v1/system/edition": {
    edition: "oss_self_hosted",
    display_name: "Open Source Self-Hosted",
    deployment_model: "single_organization_self_hosted",
    license_required: false,
    license_enforcement: "none",
    license_status: "not_applicable",
    note: "Open-source self-hosted deployments do not require a license key and do not enforce license limits."
  },
  "/api/v1/system/version": {
    component: "ohmyrasp-control-api",
    version: "dev",
    commit: "local",
    build_time: "2026-06-01T00:00:00Z",
    go_version: "go1.26.0"
  },
  "/api/v1/users": {
    items: [
      {
        id: "usr_admin",
        email: "admin@ohmyrasp.local",
        name: "Default Admin",
        roles: ["admin", "security_engineer"],
        created_at: "2026-05-31T00:00:00Z",
        updated_at: "2026-05-31T00:00:00Z"
      }
    ]
  },
  "/api/v1/alert-rules": {
    items: [
      {
        id: "alr_critical_attack",
        name: "Critical attack event",
        description: "Notify on critical attacks",
        enabled: true,
        event_type: "attack",
        severity: "critical",
        condition: "severity == critical",
        target: "security-operations",
        created_at: "2026-05-31T00:00:00Z",
        updated_at: "2026-05-31T00:00:00Z"
      }
    ]
  },
  "/api/v1/alert-deliveries": {
    items: [
      {
        id: "adl_1",
        alert_rule_id: "alr_critical_attack",
        alert_rule_name: "Critical attack event",
        event_id: "evt_1",
        event_type: "attack",
        severity: "critical",
        target: "security-operations",
        status: "queued",
        attempts: 0,
        created_at: "2026-05-31T00:00:00Z"
      }
    ]
  }
};
