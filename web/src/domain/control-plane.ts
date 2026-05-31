export type NavPath = "/" | "/applications" | "/agents" | "/policies" | "/events" | "/observability" | "/access";

export type ControlCapability =
  | "agent-registration"
  | "agent-heartbeat"
  | "policy-pull"
  | "event-reporting"
  | "rule-editing"
  | "rule-validation"
  | "rule-testing"
  | "policy-versioning"
  | "canary-release"
  | "rollback"
  | "event-analysis"
  | "overhead-observability"
  | "rbac"
  | "audit-log";

export type NavigationSection = {
  path: NavPath;
  label: string;
  description: string;
  capabilities: ControlCapability[];
  icon: "layout" | "app" | "agent" | "policy" | "event" | "chart" | "shield";
};

export const navigationSections: NavigationSection[] = [
  {
    path: "/",
    label: "Overview",
    description: "Fleet posture, active policy versions, high-risk event trend, and online Agent health.",
    capabilities: ["event-analysis", "overhead-observability"],
    icon: "layout"
  },
  {
    path: "/applications",
    label: "Applications",
    description: "Single-organization inventory of applications and deployment environments.",
    capabilities: ["agent-registration"],
    icon: "app"
  },
  {
    path: "/agents",
    label: "Agents",
    description: "Java Agent registration, heartbeat status, version drift, and assigned policy view.",
    capabilities: ["agent-registration", "agent-heartbeat", "policy-pull", "event-reporting"],
    icon: "agent"
  },
  {
    path: "/policies",
    label: "Policies",
    description: "Rule editing, validation, testing, versioning, canary rollout, and rollback workflows.",
    capabilities: ["rule-editing", "rule-validation", "rule-testing", "policy-versioning", "canary-release", "rollback"],
    icon: "policy"
  },
  {
    path: "/events",
    label: "Events",
    description: "Attack, Hook, crash, performance, and dependency reports with queryable timeline.",
    capabilities: ["event-reporting", "event-analysis"],
    icon: "event"
  },
  {
    path: "/observability",
    label: "Observability",
    description: "Rule overhead, Hook latency, Agent overhead, and policy-version performance impact.",
    capabilities: ["overhead-observability"],
    icon: "chart"
  },
  {
    path: "/access",
    label: "Access & Audit",
    description: "Enterprise login, RBAC, operation audit logs, alerts, and system settings.",
    capabilities: ["rbac", "audit-log"],
    icon: "shield"
  }
];

export const policyLifecycle = ["Draft", "Validate", "Test", "Version", "Canary", "Promote", "Rollback"] as const;

export const eventPipelines = [
  { type: "attack", target: "ClickHouse", retention: "hot analytical queries" },
  { type: "hook", target: "ClickHouse", retention: "rule and hook execution detail" },
  { type: "performance", target: "ClickHouse", retention: "latency and overhead time series" },
  { type: "crash", target: "PostgreSQL + ClickHouse", retention: "incident workflow and analytics" },
  { type: "dependency", target: "PostgreSQL", retention: "application software bill of materials" }
] as const;

export const seededMetrics = {
  applications: 4,
  environments: 9,
  agentsOnline: 132,
  agentsTotal: 141,
  attackEvents24h: 37,
  p95HookLatencyMs: 1.8,
  policyVersions: 18,
  openAlerts: 6
};
