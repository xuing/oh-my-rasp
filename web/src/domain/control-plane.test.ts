import { describe, expect, it } from "vitest";
import { eventPipelines, navigationSections, policyLifecycle, type ControlCapability } from "./control-plane";

describe("control-plane navigation model", () => {
  it("covers every top-level capability requested by the control platform objective", () => {
    const expected: ControlCapability[] = [
      "agent-registration",
      "agent-heartbeat",
      "policy-pull",
      "event-reporting",
      "rule-editing",
      "rule-validation",
      "rule-testing",
      "policy-versioning",
      "canary-release",
      "rollback",
      "event-analysis",
      "overhead-observability",
      "rbac",
      "audit-log"
    ];

    const actual = new Set(navigationSections.flatMap(section => section.capabilities));
    expect(expected.filter(capability => !actual.has(capability))).toEqual([]);
  });

  it("keeps the policy lifecycle in deployable order", () => {
    expect(policyLifecycle).toEqual(["Draft", "Validate", "Test", "Version", "Canary", "Promote", "Rollback"]);
  });

  it("models all event ingestion families named in the backend objective", () => {
    expect(eventPipelines.map(pipeline => pipeline.type)).toEqual(["attack", "hook", "performance", "crash", "error", "dependency"]);
  });
});
