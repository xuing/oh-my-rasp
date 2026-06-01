import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import i18n from "../i18n";
import { AccessPage, AgentsPage, ApplicationsPage, EventsPage, ObservabilityPage, OverviewPage, PoliciesPage } from "./pages";

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn(mockFetch));
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("OverviewPage", () => {
  it("renders dashboard metrics from the API response", async () => {
    renderWithQueryClient(<OverviewPage />);

    await waitFor(() => expect(screen.getByText("3/4")).toBeTruthy());
    expect(screen.getByText("Control Domains")).toBeTruthy();
    expect(screen.getByText("Policy Lifecycle")).toBeTruthy();
    expect(screen.getByText("Online Agents")).toBeTruthy();
    expect(screen.getByText("Attack Trend")).toBeTruthy();
    expect(screen.getByText("User-Agent Sources")).toBeTruthy();
    expect(screen.getByText("curl/8.0")).toBeTruthy();
    expect(screen.getByText("command_userinput")).toBeTruthy();
    expect(screen.queryByText("132/141")).toBeNull();
  });

  it("renders localized dashboard labels in Chinese and Japanese", async () => {
    await i18n.changeLanguage("zh");
    const { unmount } = renderWithQueryClient(<OverviewPage />);

    expect(screen.getByText("控制域")).toBeTruthy();
    expect(screen.getByText("策略生命周期")).toBeTruthy();
    expect(screen.getByText("在线 Agent")).toBeTruthy();

    unmount();
    await i18n.changeLanguage("ja");
    renderWithQueryClient(<OverviewPage />);

    expect(screen.getByText("制御ドメイン")).toBeTruthy();
    expect(screen.getByText("ポリシーライフサイクル")).toBeTruthy();
    expect(screen.getByText("オンライン Agent")).toBeTruthy();
  });
});

describe("ObservabilityPage", () => {
  it("renders empty telemetry tables instead of seeded samples", async () => {
    renderWithQueryClient(<ObservabilityPage />);

    await waitFor(() => expect(screen.getAllByText("No samples").length).toBeGreaterThan(0));
    expect(screen.getByText("Rule Overhead")).toBeTruthy();
    expect(screen.getByText("Hook Latency")).toBeTruthy();
    expect(screen.getByText("Agent Overhead")).toBeTruthy();
    expect(screen.getByText("Policy Impact")).toBeTruthy();
    expect(screen.getByText("Observability Filters")).toBeTruthy();
    expect(screen.getByLabelText("Observability Application")).toBeTruthy();
    expect(screen.getByLabelText("Observability Policy")).toBeTruthy();
    expect(screen.queryByText("pol_demo")).toBeNull();
    expect(screen.queryByText("agt_demo_1")).toBeNull();
  });
});

describe("Live data pages", () => {
  it("renders empty operational states without fallback records", async () => {
    renderWithQueryClient(
      <>
        <ApplicationsPage />
        <AgentsPage />
        <PoliciesPage />
        <EventsPage />
        <AccessPage />
      </>
    );

    await waitFor(() => expect(screen.getAllByText("No applications").length).toBeGreaterThan(0));
    expect(screen.getAllByText("No Agents").length).toBeGreaterThan(0);
    expect(screen.getAllByText("No policies").length).toBeGreaterThan(0);
    expect(screen.getAllByText("No events").length).toBeGreaterThan(0);
    expect(screen.getByText("No dependency observations")).toBeTruthy();
    expect(screen.getByText("No baseline findings")).toBeTruthy();
    expect(screen.getAllByText("No users").length).toBeGreaterThan(0);
    expect(screen.getAllByText("No alert rules").length).toBeGreaterThan(0);
    expect(screen.getByText("No alert deliveries")).toBeTruthy();
    expect(screen.getByText("No audit logs")).toBeTruthy();
    expect(screen.queryByText("Payments API")).toBeNull();
    expect(screen.queryByText("payments-1")).toBeNull();
    expect(screen.queryByText("Web Protection")).toBeNull();
    expect(screen.queryByText("SQL tautology detected in checkout search parameter")).toBeNull();
    expect(screen.queryByText("spring-web")).toBeNull();
    expect(screen.queryByText("Default Admin")).toBeNull();
  });
});

function renderWithQueryClient(element: ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false
      }
    }
  });

  return render(<QueryClientProvider client={queryClient}>{element}</QueryClientProvider>);
}

async function mockFetch(input: RequestInfo | URL) {
  const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url, "http://127.0.0.1");
  const body = responseForPath(url.pathname);
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

function responseForPath(path: string) {
  if (path === "/api/v1/analytics/overview") {
    return {
      application_count: 4,
      agent_count: 4,
      online_agents: 3,
      event_count: 2,
      events_by_type: { attack: 1, hook: 1 },
      events_by_severity: { critical: 1, low: 1 },
      attack_trend: [{ bucket_start: "2026-05-31T00:00:00Z", count: 1 }],
      attacks_by_hook: { command: 1 },
      attacks_by_algorithm: { command_userinput: 1 },
      attacks_by_user_agent: { "curl/8.0": 1 },
      crash_count: 1
    };
  }
  if (path === "/api/v1/analytics/observability") {
    return {
      rule_overhead: [],
      hook_latency: [],
      agent_overhead: [],
      policy_performance: []
    };
  }
  if (path === "/api/v1/agent-artifacts") {
    return {
      artifact_dir_configured: false,
      generated_bootstrap_enabled: false,
      items: []
    };
  }
  if (path === "/api/v1/system/edition") {
    return {
      edition: "oss_self_hosted",
      display_name: "Open Source Self-Hosted",
      deployment_model: "single_organization_self_hosted",
      license_required: false,
      license_enforcement: "none",
      license_status: "not_applicable",
      note: ""
    };
  }
  return { items: [] };
}
