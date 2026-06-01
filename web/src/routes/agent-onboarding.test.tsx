import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AgentOnboardingPage } from "./agent-onboarding";
import { MaintainClearDataPage, PlatformUserPage, SettingsAlarmPage } from "./legacy-focus";

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn(mockFetch));
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("AgentOnboardingPage", () => {
  it("renders a focused add instance workflow with generated install commands", async () => {
    renderWithQueryClient(<AgentOnboardingPage />);

    expect(screen.getByText("Add Instance")).toBeTruthy();
    await waitFor(() => expect(screen.getByText("Checkout API")).toBeTruthy());
    expect(screen.getByText("Manual Java Agent")).toBeTruthy();
    expect(screen.getByText(/-Dohmyrasp.app_id=app_checkout/)).toBeTruthy();
    expect(screen.getByText("Runtime evidence")).toBeTruthy();
  });
});

describe("legacy focused routes", () => {
  it("places the intended legacy destination at the top of the route", () => {
    renderWithQueryClient(
      <>
        <MaintainClearDataPage />
        <SettingsAlarmPage />
        <PlatformUserPage />
      </>
    );

    expect(screen.getAllByText("Maintenance Cleanup").length).toBeGreaterThan(0);
    expect(screen.getByText("Alarm Settings")).toBeTruthy();
    expect(screen.getAllByText("User Administration").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Focused legacy route").length).toBe(3);
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
  if (path === "/api/v1/applications") {
    return {
      items: [
        {
          created_at: "2026-06-01T00:00:00Z",
          description: "checkout",
          environment_ids: ["env_checkout"],
          id: "app_checkout",
          name: "Checkout API"
        }
      ]
    };
  }
  if (path === "/api/v1/system/edition") {
    return {
      edition: "oss_self_hosted",
      display_name: "Open Source Self-Hosted",
      deployment_model: "single_organization_self_hosted",
      license_enforcement: "none",
      license_required: false,
      license_status: "not_applicable",
      note: ""
    };
  }
  if (path === "/api/v1/system/version") {
    return {
      built_at: "",
      commit: "",
      version: "test"
    };
  }
  return { items: [] };
}
