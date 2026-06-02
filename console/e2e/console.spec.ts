import { expect, test, type Page, type Route } from "@playwright/test";

type RequestRecord = { method: string; path: string; query: string; body: unknown; headers: Record<string, string> };

function json(route: Route, data: unknown, status = 200) {
  return route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(data)
  });
}

async function setupConsole(page: Page, roles: string[] = ["admin"]) {
  const requests: RequestRecord[] = [];
  const state = {
    applications: [
      {
        id: "app_main",
        name: "Main App",
        description: "primary",
        environment_ids: ["env_prod"],
        policy_id: "policy_default",
        policy_version: 1,
        created_at: "2026-06-01T00:00:00Z"
      },
      {
        id: "app_side",
        name: "Side App",
        description: "shared",
        environment_ids: [],
        policy_id: "policy_default",
        policy_version: 1,
        created_at: "2026-06-01T00:00:00Z"
      }
    ],
    policies: [
      {
        id: "policy_default",
        name: "Default Policy",
        description: "default",
        created_at: "2026-06-01T00:00:00Z",
        active: {
          version: 1,
          status: "active",
          canary_percent: 100,
          created_at: "2026-06-01T00:00:00Z",
          rules: [
            {
              id: "rule_sql",
              name: "SQL Injection",
              hook: "sql",
              algorithm: "regex",
              action: "block",
              severity: "high",
              expression: "(?i)union",
              tags: ["default"],
              description: "default"
            }
          ]
        },
        versions: [
          {
            version: 1,
            status: "active",
            canary_percent: 100,
            created_at: "2026-06-01T00:00:00Z",
            rules: [
              {
                id: "rule_sql",
                name: "SQL Injection",
                hook: "sql",
                algorithm: "regex",
                action: "block",
                severity: "high",
                expression: "(?i)union",
                tags: ["default"],
                description: "default"
              }
            ]
          }
        ]
      }
    ],
    agents: [
      {
        id: "agent_1",
        application_id: "app_main",
        environment_id: "env_prod",
        hostname: "node-a",
        runtime: "java",
        version: "25",
        status: "online",
        policy_id: "policy_default",
        policy_version: 1,
        last_seen_at: "2026-06-02T00:00:00Z"
      }
    ],
    alertRules: [
      {
        id: "alert_1",
        application_id: "app_main",
        name: "Critical attacks",
        description: "",
        enabled: true,
        event_type: "attack",
        severity: "critical",
        condition: "",
        target: "https://hooks.example/critical",
        created_at: "2026-06-01T00:00:00Z",
        updated_at: "2026-06-01T00:00:00Z"
      }
    ],
    events: [
      {
        id: "event_1",
        type: "attack",
        application_id: "app_main",
        environment_id: "env_prod",
        agent_id: "agent_1",
        policy_id: "policy_default",
        policy_version: 1,
        hook: "sql",
        algorithm: "regex",
        severity: "high",
        message: "union select",
        occurred_at: "2026-06-02T00:00:00Z",
        attributes: { sql: "select 1" }
      }
    ],
    recycle: [
      {
        id: "event_old",
        type: "attack",
        application_id: "app_main",
        environment_id: "env_prod",
        agent_id: "agent_1",
        hook: "sql",
        algorithm: "regex",
        severity: "low",
        message: "old event",
        occurred_at: "2026-06-01T00:00:00Z",
        deleted_at: "2026-06-02T00:00:00Z",
        attributes: {}
      }
    ]
  };

  await page.addInitScript(({ sessionRoles }) => {
    localStorage.setItem(
      "ohmyrasp.console.session",
      JSON.stringify({
        token: "test-token",
        user: { id: "user_1", email: "admin@example.test", name: "Admin", roles: sessionRoles }
      })
    );
    localStorage.setItem("ohmyrasp.console.scope", JSON.stringify({ applicationId: "app_main", environmentId: null }));
  }, { sessionRoles: roles });

  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname.replace("/api/v1", "");
    const body = request.postData() ? request.postDataJSON() : null;
    requests.push({ method: request.method(), path, query: url.search, body, headers: request.headers() });

    if (request.method() === "GET" && path === "/applications") return json(route, { items: state.applications });
    if (request.method() === "POST" && path === "/applications") {
      const app = { id: "app_new", environment_ids: [], policy_id: "", policy_version: 0, created_at: "2026-06-02T00:00:00Z", secret: "new-secret", ...(body as object) };
      state.applications.push(app as (typeof state.applications)[number]);
      return json(route, app);
    }
    if (request.method() === "DELETE" && path.startsWith("/applications/")) return json(route, {});
    if (request.method() === "POST" && path.endsWith("/secret/rotate")) return json(route, { ...state.applications[0], secret: "rotated-secret" });
    if (request.method() === "POST" && path.includes("/environments")) {
      state.applications[0].environment_ids.push("env_stage");
      return json(route, { id: "env_stage", application_id: "app_main", ...(body as object) });
    }
    if (request.method() === "GET" && path === "/applications/app_main/settings") {
      return json(route, { items: [{ application_id: "app_main", key: "protection.hardening", value: { mode: "monitor" } }] });
    }
    if (request.method() === "GET" && path === "/applications/app_main/environments/env_prod/settings") {
      return json(route, { items: [{ application_id: "app_main", environment_id: "env_prod", key: "protection.hardening", value: { mode: "monitor" } }] });
    }
    if (request.method() === "PUT" && path.includes("/settings")) return json(route, { application_id: "app_main", ...(body as object) });

    if (request.method() === "GET" && path === "/agents") return json(route, { items: state.agents });
    if (request.method() === "POST" && path === "/agents/register") {
      const agent = { id: "agent_registered", application_id: "app_main", status: "online", ...(body as object) };
      state.agents.push(agent as (typeof state.agents)[number]);
      return json(route, agent);
    }
    if (request.method() === "PUT" && path.includes("/alias")) return json(route, state.agents[0]);
    if (request.method() === "POST" && path.includes("/ignore")) return json(route, { ...state.agents[0], ignored_at: new Date().toISOString() });
    if (request.method() === "DELETE" && path.startsWith("/agents/")) return json(route, { ids: ["agent_1"], count: 1 });

    if (request.method() === "GET" && path === "/agent-artifacts") {
      return json(route, {
        artifact_dir_configured: true,
        generated_bootstrap_enabled: true,
        items: [
          {
            filename: "ohmyrasp-agent-java-linux-x64-25.zip",
            content_type: "application/zip",
            md5: "abcd",
            size: 4096,
            language: "java",
            system_type: "linux-x64",
            language_version: "25",
            source: "managed",
            updated_at: "2026-06-02T00:00:00Z"
          }
        ]
      });
    }
    if (request.method() === "POST" && path === "/agent-artifacts") return json(route, { filename: "agent.zip", md5: "efgh", size: 10 });

    if (request.method() === "GET" && path === "/events/recycle-bin") return json(route, { items: state.recycle });
    if (request.method() === "POST" && path === "/events/recycle-bin/delete") return json(route, { ids: ["event_1"], count: 1 });
    if (request.method() === "POST" && path === "/events/recycle-bin/restore") return json(route, { ids: ["event_old"], count: 1 });
    if (request.method() === "POST" && path === "/events/recycle-bin/purge") return json(route, { ids: ["event_old"], count: 1 });
    if (request.method() === "GET" && path.startsWith("/events/")) return json(route, { items: path === "/events/attack" ? state.events : [] });

    if (request.method() === "GET" && path === "/policies") return json(route, { items: state.policies });
    if (request.method() === "POST" && path === "/policies") return json(route, { id: "policy_new", versions: [], active: null, created_at: "2026-06-02T00:00:00Z", ...(body as object) });
    if (request.method() === "POST" && path === "/policies/validate") return json(route, { valid: true, errors: [] });
    if (request.method() === "POST" && path === "/policies/test") return json(route, { matched: true, action: "block", algorithm: "regex", confidence: 90 });
    if (request.method() === "POST" && path.endsWith("/versions")) return json(route, state.policies[0]);
    if (request.method() === "POST" && path.endsWith("/rollout")) return json(route, state.policies[0]);
    if (request.method() === "POST" && path.endsWith("/rollback")) return json(route, state.policies[0]);
    if (request.method() === "POST" && path.endsWith("/restore-default")) return json(route, state.policies[0]);

    if (request.method() === "GET" && path === "/alert-rules") return json(route, { items: state.alertRules });
    if (request.method() === "POST" && path === "/alert-rules") return json(route, { id: "alert_new", ...(body as object) });
    if (request.method() === "PUT" && path.startsWith("/alert-rules/")) return json(route, { id: "alert_1", ...(body as object) });
    if (request.method() === "GET" && path === "/alert-deliveries") {
      return json(route, { items: [{ id: "delivery_1", alert_rule_id: "alert_1", alert_rule_name: "Critical attacks", event_id: "event_1", event_type: "attack", severity: "critical", target: "https://hooks.example", status: "delivered", attempts: 1, created_at: "2026-06-02T00:00:00Z", delivered_at: "2026-06-02T00:00:00Z" }] });
    }
    if (request.method() === "GET" && path === "/users") {
      return json(route, { items: [{ id: "user_1", email: "admin@example.test", name: "Admin", roles: ["admin"], created_at: "2026-06-01T00:00:00Z" }] });
    }
    if (request.method() === "POST" && path === "/users") return json(route, { id: "user_new", ...(body as object) });
    if (request.method() === "PUT" && path.startsWith("/users/")) return json(route, { id: "user_1", ...(body as object) });
    if (request.method() === "GET" && path === "/audit-logs") return json(route, { items: [] });
    if (request.method() === "GET" && path === "/system/version") return json(route, { component: "api", version: "dev", commit: "test", build_time: "2026-06-02T00:00:00Z", go_version: "go1.25" });
    if (request.method() === "GET" && path === "/system/edition") return json(route, { display_name: "OSS Edition", features: ["self_hosted"] });
    if (request.method() === "POST" && path === "/maintenance/cleanup") return json(route, { dry_run: Boolean((body as { dry_run?: boolean }).dry_run), before: "2026-05-26", counts: { events: 2, dependencies: 1 } });
    if (request.method() === "GET" && path.startsWith("/analytics/")) {
      return json(route, { application_count: 1, agent_count: 1, online_agents: 1, event_count: 1, crash_count: 0, events_by_type: {}, events_by_severity: {}, attack_trend: [], attacks_by_hook: {}, attacks_by_algorithm: {}, attacks_by_user_agent: {} });
    }
    return json(route, { items: [] });
  });

  return { requests, state };
}

test("application management and environment-scoped protection use real API contracts", async ({ page }) => {
  const { requests } = await setupConsole(page);

  await page.goto("/applications");
  const appForm = page.locator("section").filter({ hasText: "Create application" });
  await appForm.getByLabel("Name").fill("Payments");
  await appForm.getByLabel("Description").fill("PCI workload");
  await appForm.getByRole("button", { name: "Create" }).click();
  await expect(page.getByText("Application created. Secret: new-secret")).toBeVisible();

  const envForm = page.locator("section").filter({ hasText: "Create environment" });
  await envForm.getByLabel("Name").fill("staging");
  await envForm.getByRole("button", { name: "Create" }).click();
  await expect(page.getByText("Environment created.")).toBeVisible();

  await page.getByTitle("Rotate secret").first().click();
  await expect(page.getByText("Secret rotated. New secret: rotated-secret")).toBeVisible();

  await page.addInitScript(() => {
    localStorage.setItem("ohmyrasp.console.scope", JSON.stringify({ applicationId: "app_main", environmentId: "env_prod" }));
  });
  await page.goto("/protection");
  const hardening = page.locator("section").filter({ hasText: "Hardening" });
  await hardening.getByLabel("Mode").selectOption("enforce");
  await hardening.getByRole("button", { name: "Save" }).click();
  await expect(page.getByText("Settings are scoped to the selected environment.")).toBeVisible();

  expect(
    requests.some(
      (request) =>
        request.method === "PUT" &&
        request.path === "/applications/app_main/environments/env_prod/settings" &&
        (request.body as { value?: { mode?: string } }).value?.mode === "enforce"
    )
  ).toBeTruthy();
});

test("instances expose onboarding, artifacts, mobile nav, and RBAC correctly", async ({ page }) => {
  const { requests } = await setupConsole(page);
  await page.goto("/instances");

  const register = page.locator("section").filter({ hasText: "Register Agent" });
  await register.getByLabel("Application secret").fill("app-secret");
  await register.getByLabel("Hostname").fill("node-b");
  await register.getByRole("button", { name: "Register" }).click();
  await expect(page.getByText(/Agent registered/)).toBeVisible();

  await page.setInputFiles('input[type="file"]', {
    name: "agent.zip",
    mimeType: "application/zip",
    buffer: Buffer.from("zip")
  });
  await page.getByRole("button", { name: "Upload" }).click();
  await expect(page.getByText("Artifact uploaded.")).toBeVisible();

  expect(requests.some((request) => request.path === "/agents/register" && request.headers["x-ohmyrasp-app-secret"] === "app-secret")).toBeTruthy();
  expect(requests.some((request) => request.path === "/agent-artifacts" && request.method === "POST")).toBeTruthy();

  const viewerPage = await page.context().newPage();
  await setupConsole(viewerPage, ["viewer"]);
  await viewerPage.setViewportSize({ width: 390, height: 760 });
  await viewerPage.goto("/instances");
  await expect(viewerPage.getByTitle("Rename")).toHaveCount(0);
  await viewerPage.getByLabel("Open navigation").click();
  await expect(viewerPage.getByRole("link", { name: /Applications/ })).toBeVisible();
  await viewerPage.close();
});

test("policy lifecycle validates, tests, versions, restores, and rolls out scoped policy", async ({ page }) => {
  const { requests } = await setupConsole(page);
  await page.goto("/policies");

  const create = page.locator("section").filter({ hasText: "Create policy" });
  await create.getByLabel("Name").fill("Payments policy");
  await create.getByRole("button", { name: "Create" }).click();

  await page.getByRole("button", { name: "Validate" }).click();
  await expect(page.getByText("Rule validation passed.")).toBeVisible();
  await page.getByRole("button", { name: "Test" }).click();
  await expect(page.getByText(/Rule test:/)).toBeVisible();
  await page.getByRole("button", { name: "Add version" }).click();
  await expect(page.getByText("Policy version created.")).toBeVisible();
  await page.getByRole("button", { name: "Restore defaults" }).click();
  await expect(page.getByText("Default rules restored.")).toBeVisible();
  await page.getByRole("button", { name: "Rollout" }).click();
  await expect(page.getByText("Policy rolled out.")).toBeVisible();

  expect(requests.some((request) => request.path === "/policies/validate")).toBeTruthy();
  expect(requests.some((request) => request.path === "/policies/test")).toBeTruthy();
  expect(
    requests.some(
      (request) => request.path.endsWith("/rollout") && (request.body as { application_id?: string; canary_percent?: number }).application_id === "app_main"
    )
  ).toBeTruthy();
});

test("access workflows scope alerts, manage users, and confirm maintenance cleanup", async ({ page }) => {
  const { requests } = await setupConsole(page);
  await page.goto("/settings/alarm");
  await expect(page.getByText("Create alert rule")).toBeVisible();

  const alertForm = page.locator("section").filter({ hasText: "Create alert rule" });
  await alertForm.getByLabel("Name").fill("High attacks");
  await alertForm.getByLabel("Target").fill("https://hooks.example/high");
  await alertForm.getByRole("button", { name: "Create" }).click();

  await page.getByRole("button", { name: "Operators" }).click();
  const userForm = page.locator("section").filter({ hasText: "Create operator" });
  await userForm.getByLabel("Email").fill("viewer@example.test");
  await userForm.getByLabel("Name").fill("Viewer");
  await userForm.getByLabel("Password").fill("password-123");
  await userForm.getByRole("button", { name: "Create" }).click();
  await page.getByRole("button", { name: "Disable" }).click();

  await page.getByRole("button", { name: "System" }).click();
  await page.getByRole("button", { name: "Preview" }).click();
  await expect(page.getByText("Cleanup preview: 3 records.")).toBeVisible();
  await page.getByLabel("Confirmation").fill("CLEAR_OPERATIONAL_DATA");
  await page.getByRole("button", { name: "Apply cleanup" }).click();
  await expect(page.getByText("Cleanup applied: 3 records.")).toBeVisible();

  expect(requests.some((request) => request.path === "/alert-rules" && request.query.includes("application_id=app_main"))).toBeTruthy();
  expect(requests.some((request) => request.path === "/users" && request.method === "POST")).toBeTruthy();
  expect(requests.some((request) => request.path.startsWith("/users/") && request.method === "PUT")).toBeTruthy();
  expect(requests.some((request) => request.path === "/maintenance/cleanup" && (request.body as { confirmation?: string }).confirmation === "CLEAR_OPERATIONAL_DATA")).toBeTruthy();
});

test("threat recycle-bin actions move, restore, and purge events", async ({ page }) => {
  const { requests } = await setupConsole(page);
  await page.goto("/threats");

  await page.getByTitle("Move to recycle bin").click();
  await page.getByRole("button", { name: "Recycle bin", exact: true }).click();
  await page.getByTitle("Restore").click();
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByTitle("Purge").click();

  expect(requests.some((request) => request.path === "/events/recycle-bin/delete")).toBeTruthy();
  expect(requests.some((request) => request.path === "/events/recycle-bin/restore")).toBeTruthy();
  expect(requests.some((request) => request.path === "/events/recycle-bin/purge")).toBeTruthy();
});
