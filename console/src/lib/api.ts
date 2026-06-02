import { authToken, clearSession, saveSession, type SessionUser } from "./session";

const BASE = "/api/v1";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

type Query = Record<string, string | number | boolean | undefined | null>;

function qs(query?: Query): string {
  if (!query) return "";
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null || v === "") continue;
    params.set(k, String(v));
  }
  const s = params.toString();
  return s ? `?${s}` : "";
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  extraHeaders?: Record<string, string>
): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json", ...extraHeaders };
  const token = authToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";

  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body)
  });

  if (res.status === 401) {
    clearSession();
    throw new ApiError(401, "Session expired. Please sign in again.");
  }

  const text = await res.text();
  const data = text ? safeJson(text) : null;

  if (!res.ok) {
    let message = res.statusText || `Request failed (${res.status})`;
    if (data && typeof data === "object" && "error" in data) {
      message = String((data as { error: unknown }).error);
    }
    throw new ApiError(res.status, message);
  }
  return data as T;
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

const items = <T>(p: Promise<{ items: T[] }>): Promise<T[]> => p.then((r) => r.items ?? []);

/* ============================== Types ============================== */

export interface Application {
  id: string;
  name: string;
  description?: string;
  secret?: string;
  environment_ids?: string[];
  policy_id?: string;
  policy_version?: number;
  created_at?: string;
}

export interface Environment {
  id: string;
  application_id: string;
  name: string;
  kind: string;
  policy_id?: string;
  policy_version?: number;
  created_at?: string;
}

export interface Agent {
  id: string;
  application_id: string;
  environment_id?: string;
  hostname?: string;
  alias?: string;
  runtime?: string;
  version?: string;
  status?: string;
  policy_id?: string;
  policy_version?: number;
  last_seen_at?: string;
  ignored_at?: string | null;
}

export interface Rule {
  id: string;
  name: string;
  hook: string;
  algorithm: string;
  action: string;
  severity: string;
  expression?: string;
  tags?: string[];
  description?: string;
}

export interface PolicyVersion {
  version: number;
  status: string;
  rules: Rule[];
  canary_percent?: number;
  created_at?: string;
  published_at?: string;
}

export interface PolicySet {
  id: string;
  name: string;
  description?: string;
  created_at?: string;
  active?: PolicyVersion | null;
  versions: PolicyVersion[];
}

export interface PolicyAlgorithm {
  hook: string;
  algorithms: string[];
}

export interface SecurityEvent {
  id: string;
  type: string;
  application_id: string;
  environment_id?: string;
  agent_id?: string;
  policy_id?: string;
  policy_version?: number;
  hook?: string;
  algorithm?: string;
  severity?: string;
  message?: string;
  occurred_at?: string;
  attributes?: Record<string, unknown>;
  deleted_at?: string | null;
}

export interface SecurityEventQuery {
  application_id?: string;
  environment_id?: string;
  agent_id?: string;
  severity?: string;
  hook?: string;
  algorithm?: string;
  limit?: number;
}

export interface DependencyVulnerability {
  id: string;
  severity: string;
  cvss?: number;
  fixed_version?: string;
  known_exploited?: boolean;
}
export interface Dependency {
  id: string;
  application_id: string;
  agent_id?: string;
  ecosystem: string;
  name: string;
  version: string;
  package_path?: string;
  licenses?: string[];
  observed_at?: string;
  vulnerabilities?: DependencyVulnerability[];
}
export interface DependencySummary {
  total: number;
  vulnerable: number;
  by_severity?: Record<string, number>;
}

export interface BaselineFinding {
  id: string;
  application_id: string;
  environment_id?: string;
  agent_id?: string;
  check_id: string;
  title: string;
  category?: string;
  resource?: string;
  severity?: string;
  status?: string;
  remediation?: string;
  observed_at?: string;
  attributes?: Record<string, unknown>;
}

export interface TrendPoint {
  bucket_start: string;
  count: number;
}
export interface Overview {
  application_count: number;
  agent_count: number;
  online_agents: number;
  event_count: number;
  crash_count: number;
  events_by_type: Record<string, number>;
  events_by_severity: Record<string, number>;
  attack_trend: TrendPoint[];
  attacks_by_hook: Record<string, number>;
  attacks_by_algorithm: Record<string, number>;
  attacks_by_user_agent: Record<string, number>;
}

export interface HookLatency {
  hook: string;
  calls: number;
  average_latency_us: number;
  p50_latency_us: number;
  p95_latency_us: number;
  max_latency_us: number;
}
export interface AgentOverhead {
  agent_id: string;
  cpu_overhead_pct: number;
  memory_overhead_bytes: number;
  hook_latency_p95_us: number;
  rule_eval_p95_us: number;
  samples: number;
}
export interface PolicyPerformance {
  policy_id: string;
  policy_version: number;
  cpu_overhead_pct: number;
  hook_latency_p95_us: number;
  rule_eval_p95_us: number;
  samples: number;
}
export interface RuleOverhead {
  policy_id: string;
  rule_id: string;
  hook: string;
  execution_count: number;
  average_latency_us: number;
  p95_latency_us: number;
}
export interface ObservabilityReport {
  rule_overhead: RuleOverhead[];
  hook_latency: HookLatency[];
  agent_overhead: AgentOverhead[];
  policy_performance: PolicyPerformance[];
}

export interface SystemSetting {
  key: string;
  value: Record<string, unknown>;
  updated_by?: string;
  updated_at?: string;
}
export interface ApplicationSetting extends SystemSetting {
  application_id: string;
  environment_id?: string;
}
export interface ApplicationConfig {
  application_id: string;
  environment_id?: string;
  settings: ApplicationSetting[];
}

export interface AlertRule {
  id: string;
  name: string;
  description?: string;
  application_id?: string;
  event_type: string;
  severity: string;
  target: string;
  enabled: boolean;
}
export interface AlertDelivery {
  id: string;
  alert_rule_id: string;
  alert_rule_name: string;
  event_id: string;
  event_type: string;
  severity: string;
  target: string;
  status: string;
  attempts: number;
  last_error?: string;
  created_at?: string;
  delivered_at?: string | null;
}

export interface AuditLog {
  id: string;
  actor_id: string;
  action: string;
  resource: string;
  details?: Record<string, unknown>;
  created_at?: string;
}

export interface User {
  id: string;
  email: string;
  name: string;
  roles: string[];
  created_at?: string;
  updated_at?: string;
  disabled_at?: string | null;
}

export interface SystemVersion {
  component: string;
  version: string;
  commit?: string;
  build_time?: string;
  go_version?: string;
}
export interface EditionStatus {
  edition?: string;
  display_name?: string;
  features?: string[];
}

/* ============================== Endpoints ============================== */

export const api = {
  async login(email: string, password: string) {
    const res = await request<{ session: { token: string }; user: SessionUser }>(
      "POST",
      "/auth/login",
      { email, password }
    );
    saveSession({ token: res.session.token, user: res.user });
    return res;
  },
  me: () => request<{ user: SessionUser }>("GET", "/me"),

  applications: () => items<Application>(request("GET", "/applications")),
  createApplication: (input: { name: string; description?: string }) =>
    request<Application>("POST", "/applications", input),
  deleteApplication: (appID: string) => request<void>("DELETE", `/applications/${enc(appID)}`),
  rotateSecret: (appID: string) => request<Application>("POST", `/applications/${enc(appID)}/secret/rotate`),
  createEnvironment: (appID: string, input: { name: string; kind: string }) =>
    request<Environment>("POST", `/applications/${enc(appID)}/environments`, input),

  applicationSettings: (appID: string) =>
    items<ApplicationSetting>(request("GET", `/applications/${enc(appID)}/settings`)),
  updateApplicationSetting: (appID: string, key: string, value: Record<string, unknown>) =>
    request<ApplicationSetting>("PUT", `/applications/${enc(appID)}/settings`, { key, value }),

  agents: (query?: SecurityEventQuery) => items<Agent>(request("GET", `/agents${qs(query as Query)}`)),
  setAgentAlias: (agentID: string, alias: string) =>
    request<Agent>("PUT", `/agents/${enc(agentID)}/alias`, { alias }),
  setAgentIgnored: (agentID: string, ignored: boolean) =>
    request<Agent>("POST", `/agents/${enc(agentID)}/ignore`, { ignored }),
  deleteAgent: (agentID: string) => request<void>("DELETE", `/agents/${enc(agentID)}`),

  policies: () => items<PolicySet>(request("GET", "/policies")),
  algorithms: () => items<PolicyAlgorithm>(request("GET", "/policies/algorithms")),
  createPolicy: (input: { name: string; description?: string }) =>
    request<PolicySet>("POST", "/policies", input),
  addPolicyVersion: (policyID: string, rules: Rule[]) =>
    request<PolicySet>("POST", `/policies/${enc(policyID)}/versions`, { rules }),
  rolloutPolicy: (policyID: string, input: { version: number; canary_percent: number; application_id?: string; environment_id?: string }) =>
    request<PolicySet>("POST", `/policies/${enc(policyID)}/rollout`, input),
  rollbackPolicy: (policyID: string) => request<PolicySet>("POST", `/policies/${enc(policyID)}/rollback`, {}),

  events: (type: "attack" | "error" | "crash", query?: SecurityEventQuery) =>
    items<SecurityEvent>(request("GET", `/events/${type}${qs(query as Query)}`)),
  recycleBin: (query?: SecurityEventQuery) =>
    items<SecurityEvent>(request("GET", `/events/recycle-bin${qs(query as Query)}`)),

  dependencies: (query?: SecurityEventQuery) =>
    items<Dependency>(request("GET", `/dependencies${qs(query as Query)}`)),
  dependencySummary: () => request<DependencySummary>("GET", "/dependencies/summary"),
  baselineFindings: (query?: SecurityEventQuery) =>
    items<BaselineFinding>(request("GET", `/baseline-findings${qs(query as Query)}`)),

  overview: (query?: { application_id?: string; environment_id?: string }) =>
    request<Overview>("GET", `/analytics/overview${qs(query as Query)}`),
  observability: (query?: { application_id?: string; environment_id?: string }) =>
    request<ObservabilityReport>("GET", `/analytics/observability${qs(query as Query)}`),

  systemSettings: () => items<SystemSetting>(request("GET", "/system-settings")),
  alertRules: () => items<AlertRule>(request("GET", "/alert-rules")),
  alertDeliveries: () => items<AlertDelivery>(request("GET", "/alert-deliveries")),
  auditLogs: () => items<AuditLog>(request("GET", "/audit-logs")),
  users: (query?: { search?: string; role?: string; status?: string }) =>
    items<User>(request("GET", `/users${qs(query as Query)}`)),

  version: () => request<SystemVersion>("GET", "/system/version"),
  edition: () => request<EditionStatus>("GET", "/system/edition")
};

function enc(v: string): string {
  return encodeURIComponent(v);
}
