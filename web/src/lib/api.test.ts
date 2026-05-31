import { describe, expect, it } from "vitest";
import {
  agentsFallback,
  applicationsFallback,
  alertDeliveriesFallback,
  alertRulesFallback,
  attackEventsFallback,
  auditLogsFallback,
  baselineFindingsFallback,
  dependenciesFallback,
  eventFallbackByType,
  observabilityFallback,
  overviewFallback,
  policiesFallback,
  systemSettingsFallback,
  usersFallback
} from "./api";

describe("overviewFallback", () => {
  it("returns stable dashboard data when the API is not reachable during local UI development", () => {
    const overview = overviewFallback();

    expect(overview.application_count).toBeGreaterThan(0);
    expect(overview.agent_count).toBeGreaterThanOrEqual(overview.online_agents);
    expect(overview.events_by_type).toMatchObject({
      attack: expect.any(Number),
      hook: expect.any(Number),
      performance: expect.any(Number),
      crash: expect.any(Number),
      dependency: expect.any(Number)
    });
  });
});

describe("observabilityFallback", () => {
  it("returns every telemetry table the observability route expects", () => {
    const report = observabilityFallback();

    expect(report.rule_overhead[0]).toMatchObject({
      policy_id: expect.any(String),
      rule_id: expect.any(String),
      p95_latency_us: expect.any(Number)
    });
    expect(report.hook_latency.length).toBeGreaterThan(0);
    expect(report.agent_overhead[0].cpu_overhead_pct).toBeGreaterThan(0);
    expect(report.policy_performance[0].policy_version).toBeGreaterThan(0);
  });
});

describe("resource fallbacks", () => {
  it("returns stable list data for pages backed by authenticated APIs", () => {
    expect(applicationsFallback().items[0].environment_ids.length).toBeGreaterThan(0);
    expect(agentsFallback().items.some(agent => agent.status === "online")).toBe(true);
    expect(policiesFallback().items[0].active?.version).toBeGreaterThan(0);
    expect(attackEventsFallback().items[0].severity).toBe("critical");
    expect(eventFallbackByType("hook").items[0].type).toBe("hook");
    expect(eventFallbackByType("performance").items[0].type).toBe("performance");
    expect(eventFallbackByType("crash").items[0].type).toBe("crash");
    expect(dependenciesFallback().items[0]).toMatchObject({ name: "spring-web", ecosystem: "maven", vulnerabilities: [{ severity: "critical" }] });
    expect(baselineFindingsFallback().items[0]).toMatchObject({ check_id: "jvm.security_manager", status: "warning" });
    expect(auditLogsFallback().items[0].action).toBe("policy.rollout");
    expect(systemSettingsFallback().items[0].key).toBe("agent.minimum_version");
    expect(usersFallback().items[0].roles).toContain("admin");
    expect(alertDeliveriesFallback().items[0].status).toBe("queued");
    expect(alertRulesFallback().items[0]).toMatchObject({
      name: "Critical attack event",
      enabled: true
    });
  });
});
