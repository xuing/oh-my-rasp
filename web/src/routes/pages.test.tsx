import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import type { ReactElement } from "react";
import { describe, expect, it } from "vitest";
import i18n from "../i18n";
import { AccessPage, AgentsPage, ApplicationsPage, EventsPage, ObservabilityPage, OverviewPage, PoliciesPage } from "./pages";

describe("OverviewPage", () => {
  it("renders the control-plane dashboard shell", async () => {
    renderWithQueryClient(<OverviewPage />);

    expect(screen.getByText("Control Domains")).toBeTruthy();
    expect(screen.getByText("Policy Lifecycle")).toBeTruthy();
    expect(screen.getByText("Online Agents")).toBeTruthy();
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
  it("renders telemetry tables from the fallback report", () => {
    renderWithQueryClient(<ObservabilityPage />);

    expect(screen.getByText("Rule Overhead")).toBeTruthy();
    expect(screen.getByText("Hook Latency")).toBeTruthy();
    expect(screen.getByText("Agent Overhead")).toBeTruthy();
    expect(screen.getByText("Policy Impact")).toBeTruthy();
    expect(screen.getByText("Observability Filters")).toBeTruthy();
    expect(screen.getByLabelText("Observability Application")).toBeTruthy();
    expect(screen.getByLabelText("Observability Policy")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Clear Observability Filters" })).toBeTruthy();
  });
});

describe("Live data pages", () => {
  it("renders fallback application, Agent, policy, event, and audit views", () => {
    renderWithQueryClient(
      <>
        <ApplicationsPage />
        <AgentsPage />
        <PoliciesPage />
        <EventsPage />
        <AccessPage />
      </>
    );

    expect(screen.getAllByText("Payments API").length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "Create Application" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Create Environment" })).toBeTruthy();
    expect(screen.getAllByText("payments-1").length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "Register Agent" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Send Heartbeat" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Pull Policy" })).toBeTruthy();
    expect(screen.getByText("Daemon Workloads")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Reveal Token" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Reset Token" })).toBeTruthy();
    expect(screen.getByText("Agent Artifact Upload")).toBeTruthy();
    expect(screen.getByLabelText("Agent ZIP")).toBeTruthy();
    expect(screen.getByLabelText("Upload System Type")).toBeTruthy();
    expect(screen.getByLabelText("Upload Language Version")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Upload Artifact" })).toBeTruthy();
    expect(screen.getByText("Agent Artifact Catalog")).toBeTruthy();
    expect(screen.getByText("agent-java-linux-17.zip")).toBeTruthy();
    expect(screen.getByText("Generated Bootstrap")).toBeTruthy();
    expect(screen.getByText("Agent Bootstrap Artifact")).toBeTruthy();
    expect(screen.getByLabelText("Artifact Application")).toBeTruthy();
    expect(screen.getByLabelText("Artifact Daemon Token")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Check Agent Artifact" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Download Agent Artifact" })).toBeTruthy();
    expect(screen.getAllByText("Web Protection").length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "Create Policy Set" })).toBeTruthy();
    expect(screen.getByLabelText("Rollout Scope")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Validate Draft" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Test Draft" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Update Draft" })).toBeTruthy();
    expect(screen.getByText("SQL tautology detected in checkout search parameter")).toBeTruthy();
    expect(screen.getByText("Servlet hook completed with 1.7 ms latency")).toBeTruthy();
    expect(screen.getByText("Agent overhead sample within policy budget")).toBeTruthy();
    expect(screen.getByText("Agent crash report captured during class transform")).toBeTruthy();
    expect(screen.getByText("Event Query")).toBeTruthy();
    expect(screen.getByLabelText("Event Application")).toBeTruthy();
    expect(screen.getByLabelText("Event Environment")).toBeTruthy();
    expect(screen.getByLabelText("Event Agent")).toBeTruthy();
    expect(screen.getByLabelText("Event Policy")).toBeTruthy();
    expect(screen.getByLabelText("Event Severity")).toBeTruthy();
    expect(screen.getByLabelText("Event Hook")).toBeTruthy();
    expect(screen.getByLabelText("Occurred After")).toBeTruthy();
    expect(screen.getByLabelText("Occurred Before")).toBeTruthy();
    expect(screen.getByLabelText("Event Limit")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Clear Filters" })).toBeTruthy();
    expect(screen.getByText("Event Recycle Bin")).toBeTruthy();
    expect(screen.getByLabelText("Recycle Event ID")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Move Event To Recycle Bin" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Restore Event" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Permanently Delete Event" })).toBeTruthy();
    expect(screen.getByText("Dependency Inventory")).toBeTruthy();
    expect(screen.getByLabelText("Dependency Application")).toBeTruthy();
    expect(screen.getByLabelText("Dependency Agent")).toBeTruthy();
    expect(screen.getByLabelText("Dependency Name")).toBeTruthy();
    expect(screen.getByLabelText("Dependency Ecosystem")).toBeTruthy();
    expect(screen.getByLabelText("Dependency Severity")).toBeTruthy();
    expect(screen.getByLabelText("Observed After")).toBeTruthy();
    expect(screen.getByLabelText("Observed Before")).toBeTruthy();
    expect(screen.getByLabelText("Dependency Limit")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Clear Dependency Filters" })).toBeTruthy();
    expect(screen.getByText("spring-web")).toBeTruthy();
    expect(screen.getAllByText("Baseline Findings").length).toBeGreaterThan(0);
    expect(screen.getByLabelText("Baseline Application")).toBeTruthy();
    expect(screen.getByLabelText("Baseline Environment")).toBeTruthy();
    expect(screen.getByLabelText("Baseline Agent")).toBeTruthy();
    expect(screen.getByLabelText("Baseline Severity")).toBeTruthy();
    expect(screen.getByLabelText("Baseline Status")).toBeTruthy();
    expect(screen.getByLabelText("Baseline Category")).toBeTruthy();
    expect(screen.getByLabelText("Baseline Limit")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Clear Baseline Filters" })).toBeTruthy();
    expect(screen.getByText("User Administration")).toBeTruthy();
    expect(screen.getByText("User Lifecycle")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Update User" })).toBeTruthy();
    expect(screen.getAllByText("Default Admin").length).toBeGreaterThan(0);
    expect(screen.getByText("Edition Status")).toBeTruthy();
    expect(screen.getByText("Open Source Self-Hosted")).toBeTruthy();
    expect(screen.getByText("Not required")).toBeTruthy();
    expect(screen.getByText("Protection Configuration")).toBeTruthy();
    expect(screen.getByLabelText("Allowlist Enabled")).toBeTruthy();
    expect(screen.getByLabelText("Hardening Mode")).toBeTruthy();
    expect(screen.getByLabelText("Vulnerability Threshold")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Save Protection Configuration" })).toBeTruthy();
    expect(screen.getByText("Maintenance Cleanup")).toBeTruthy();
    expect(screen.getByLabelText("Cleanup Before")).toBeTruthy();
    expect(screen.getByLabelText("Cleanup Application ID")).toBeTruthy();
    expect(screen.getByLabelText("Cleanup Confirmation")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Preview Cleanup" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Apply Cleanup" })).toBeTruthy();
    expect(screen.getByText("System Settings")).toBeTruthy();
    expect(screen.getByText("agent.minimum_version")).toBeTruthy();
    expect(screen.getByText("Alert Lifecycle")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Update Alert Rule" })).toBeTruthy();
    expect(screen.getByText("Alert Rules")).toBeTruthy();
    expect(screen.getAllByText("Critical attack event").length).toBeGreaterThan(0);
    expect(screen.getByText("Alert Delivery History")).toBeTruthy();
    expect(screen.getByText("policy.rollout")).toBeTruthy();
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
