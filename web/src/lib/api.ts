import { useQuery } from "@tanstack/react-query";
import { seededMetrics } from "../domain/control-plane";

export type OverviewResponse = {
  application_count: number;
  agent_count: number;
  online_agents: number;
  event_count: number;
  events_by_type: Record<string, number>;
  events_by_severity: Record<string, number>;
};

export type ListResponse<T> = {
  items: T[];
};

export type Application = {
  id: string;
  name: string;
  description: string;
  secret?: string;
  created_at: string;
  policy_id?: string;
  policy_version?: number;
  environment_ids: string[];
};

export type ApplicationCreateInput = {
  name: string;
  description?: string;
};

export type Environment = {
  id: string;
  application_id: string;
  name: string;
  kind: string;
  created_at: string;
  policy_id?: string;
  policy_version?: number;
};

export type EnvironmentCreateInput = {
  name: string;
  kind?: string;
};

export type Agent = {
  id: string;
  application_id: string;
  environment_id: string;
  hostname: string;
  runtime: string;
  version: string;
  status: string;
  last_seen_at: string;
  policy_id?: string;
  policy_version?: number;
};

export type AgentRegistrationInput = {
  application_id: string;
  application_secret: string;
  environment_id: string;
  hostname: string;
  runtime?: string;
  version: string;
};

export type AgentCredentialInput = {
  application_id: string;
  application_secret: string;
};

export type DaemonAccessToken = {
  access_token: string;
  updated_at: string;
};

export type DaemonApplicationCredential = {
  application_id: string;
  application_secret: string;
  language: string;
};

export type AgentArtifactInfo = {
  filename: string;
  content_type: string;
  md5: string;
  size: number;
  language: string;
  system_type: string;
  language_version: string;
};

export type AgentArtifactCatalogItem = {
  filename: string;
  content_type: string;
  md5: string;
  size: number;
  language: string;
  system_type: string;
  language_version: string;
  source: string;
  updated_at: string;
};

export type AgentArtifactCatalog = {
  artifact_dir_configured: boolean;
  generated_bootstrap_enabled: boolean;
  items: AgentArtifactCatalogItem[];
};

export type AgentArtifactDownload = {
  blob: Blob;
  filename: string;
  md5: string;
  contentType: string;
};

export type AgentArtifactUploadInput = {
  filename?: string;
  language: "java";
  system_type: string;
  language_version: string;
  content_base64: string;
};

export type DaemonWorkload = {
  id: string;
  application_id?: string;
  node_name: string;
  type: "process" | "container";
  pid?: number;
  cmdline?: string[];
  container_id?: string;
  container_name?: string;
  image_id?: string;
  image_tag?: string;
  injection_status?: "injected" | "failed" | "uninstalled";
  injection_error?: string;
  injection_helper_id?: string;
  injection_helper_version?: string;
  injection_reported_at?: string;
  injection_status_updated_at?: string;
  observed_at: string;
  updated_at: string;
};

export type DaemonWorkloadInput = {
  type: "process" | "container";
  pid?: number;
  cmdline?: string[];
  container_id?: string;
  container_name?: string;
  image_id?: string;
  image_tag?: string;
  observed_at?: string;
};

export type DaemonWorkloadReport = {
  node_name: string;
  workloads: DaemonWorkloadInput[];
};

export type Rule = {
  id: string;
  name: string;
  hook: string;
  algorithm: string;
  action: string;
  severity: string;
  expression: string;
  tags: string[];
  description: string;
};

export type RuleInput = {
  id?: string;
  name: string;
  hook: string;
  algorithm?: string;
  action?: string;
  severity?: string;
  expression: string;
  tags?: string[];
  description?: string;
};

export type RuleValidation = {
  valid: boolean;
  errors: string[];
};

export type RuleTestResult = {
  matched: boolean;
  action: string;
  algorithm: string;
  confidence: number;
};

export type SecurityEventInput = {
  application_id: string;
  environment_id: string;
  agent_id: string;
  policy_id?: string;
  policy_version?: number;
  hook?: string;
  algorithm?: string;
  severity: string;
  message: string;
  occurred_at?: string;
  attributes?: Record<string, unknown>;
};

export type SecurityEventQuery = {
  application_id?: string;
  environment_id?: string;
  agent_id?: string;
  policy_id?: string;
  severity?: string;
  hook?: string;
  occurred_after?: string;
  occurred_before?: string;
  limit?: number;
};

export type PolicyVersion = {
  version: number;
  status: string;
  rules: Rule[];
  canary_percent: number;
  created_at: string;
  published_at?: string;
};

export type PolicySet = {
  id: string;
  name: string;
  description: string;
  created_at: string;
  active?: PolicyVersion;
  versions: PolicyVersion[];
};

export type PolicySetInput = {
  name: string;
  description?: string;
};

export type PolicyRolloutScope = {
  application_id?: string;
  environment_id?: string;
};

export type SecurityEvent = {
  id: string;
  type: string;
  application_id: string;
  environment_id: string;
  agent_id: string;
  policy_id?: string;
  policy_version?: number;
  hook?: string;
  algorithm?: string;
  severity: string;
  message: string;
  occurred_at: string;
  attributes?: Record<string, unknown>;
  deleted_at?: string;
  deleted_by?: string;
};

export type SecurityEventType = "attack" | "hook" | "performance" | "crash";

export type SecurityEventRecycleBinQuery = SecurityEventQuery & {
  type?: SecurityEventType;
};

export type EventRecycleBinReport = {
  ids: string[];
  count: number;
};

export type DependencyVulnerability = {
  id: string;
  severity: "critical" | "high" | "medium" | "low";
  cvss?: number;
  known_exploited?: boolean;
  fixed_version?: string;
};

export type Dependency = {
  id: string;
  application_id: string;
  agent_id: string;
  name: string;
  version: string;
  ecosystem: string;
  package_path?: string;
  licenses?: string[];
  vulnerabilities?: DependencyVulnerability[];
  observed_at: string;
};

export type DependencyQuery = {
  application_id?: string;
  agent_id?: string;
  name?: string;
  ecosystem?: string;
  vulnerability_severity?: string;
  observed_after?: string;
  observed_before?: string;
  limit?: number;
};

export type BaselineFinding = {
  id: string;
  application_id: string;
  environment_id: string;
  agent_id: string;
  check_id: string;
  title: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "failed" | "warning" | "passed" | "suppressed";
  resource: string;
  remediation?: string;
  attributes?: Record<string, unknown>;
  observed_at: string;
};

export type BaselineFindingQuery = {
  application_id?: string;
  environment_id?: string;
  agent_id?: string;
  severity?: string;
  status?: string;
  category?: string;
  observed_after?: string;
  observed_before?: string;
  limit?: number;
};

export type AuditLog = {
  id: string;
  actor_id: string;
  action: string;
  resource: string;
  details?: Record<string, unknown>;
  created_at: string;
};

export type SystemSetting = {
  key: string;
  value: Record<string, unknown>;
  updated_by?: string;
  updated_at: string;
};

export type EditionStatus = {
  edition: "oss_self_hosted" | string;
  display_name: string;
  deployment_model: "single_organization_self_hosted" | string;
  license_required: boolean;
  license_enforcement: "none" | string;
  license_status: "not_applicable" | string;
  note?: string;
};

export type MaintenanceCleanupRequest = {
  before: string;
  application_id?: string;
  dry_run?: boolean;
  include_events?: boolean;
  include_dependencies?: boolean;
  include_baseline_findings?: boolean;
  include_alert_deliveries?: boolean;
  confirmation?: string;
};

export type MaintenanceCleanupReport = {
  dry_run: boolean;
  before: string;
  application_id?: string;
  counts: Record<string, number>;
};

export type User = {
  id: string;
  email: string;
  name: string;
  roles: string[];
  created_at: string;
  updated_at: string;
  disabled_at?: string;
};

export type AlertRule = {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  event_type: string;
  severity: string;
  condition: string;
  target: string;
  created_at: string;
  updated_at: string;
};

export type AlertRuleInput = {
  name: string;
  description?: string;
  enabled: boolean;
  event_type: string;
  severity: string;
  condition?: string;
  target: string;
};

export type AlertDelivery = {
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
  created_at: string;
  delivered_at?: string;
};

export type RuleOverhead = {
  policy_id: string;
  policy_version: number;
  rule_id: string;
  hook: string;
  executions: number;
  blocked: number;
  average_latency_us: number;
  p95_latency_us: number;
  max_latency_us: number;
};

export type HookLatency = {
  hook: string;
  calls: number;
  average_latency_us: number;
  p95_latency_us: number;
  max_latency_us: number;
};

export type AgentOverhead = {
  agent_id: string;
  samples: number;
  cpu_overhead_pct: number;
  memory_overhead_bytes: number;
  hook_latency_p95_us: number;
  rule_eval_p95_us: number;
};

export type PolicyPerformance = {
  policy_id: string;
  policy_version: number;
  samples: number;
  cpu_overhead_pct: number;
  hook_latency_p95_us: number;
  rule_eval_p95_us: number;
};

export type ObservabilityResponse = {
  rule_overhead: RuleOverhead[];
  hook_latency: HookLatency[];
  agent_overhead: AgentOverhead[];
  policy_performance: PolicyPerformance[];
};

export type ObservabilityFilters = {
  applicationID?: string;
  policyID?: string;
};

export type LoginResponse = {
  session: {
    token: string;
    user_id: string;
    expires_at: string;
  };
  user: User;
};

export type UserRole = "admin" | "security_engineer" | "viewer";

export type UserCreateInput = {
  email: string;
  name: string;
  password: string;
  roles: UserRole[];
};

export type UserUpdateInput = {
  name: string;
  roles: UserRole[];
  disabled: boolean;
};

export type SessionSnapshot = {
  token: string;
  userEmail: string;
  userName: string;
};

export async function loginWithPassword(email: string, password: string): Promise<LoginResponse> {
  const response = await fetch("/api/v1/auth/login", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ email, password })
  });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<LoginResponse>;
}

export function saveSession(result: LoginResponse) {
  if (typeof window === "undefined") {
    return;
  }
  window.localStorage.setItem("ohmyrasp.session_token", result.session.token);
  window.localStorage.setItem("ohmyrasp.session_user_email", result.user.email);
  window.localStorage.setItem("ohmyrasp.session_user_name", result.user.name);
  window.dispatchEvent(new Event("ohmyrasp.session.changed"));
}

export function currentSession(): SessionSnapshot {
  if (typeof window === "undefined") {
    return { token: "", userEmail: "", userName: "" };
  }
  return {
    token: sessionToken(),
    userEmail: window.localStorage.getItem("ohmyrasp.session_user_email") ?? "",
    userName: window.localStorage.getItem("ohmyrasp.session_user_name") ?? ""
  };
}

async function fetchJSON<T>(path: string): Promise<T> {
  const response = await fetch(path, {
    headers: requestHeaders()
  });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<T>;
}

async function sendJSON<T>(path: string, method: "POST" | "PUT", body: unknown): Promise<T> {
  const response = await fetch(path, {
    method,
    headers: {
      ...requestHeaders(),
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<T>;
}

export function createPolicyVersion(policyID: string, rules: RuleInput[]) {
  return sendJSON<PolicySet>(`/api/v1/policies/${encodeURIComponent(policyID)}/versions`, "POST", { rules });
}

export function updatePolicyVersionRules(policyID: string, version: number, rules: RuleInput[]) {
  return sendJSON<PolicySet>(`/api/v1/policies/${encodeURIComponent(policyID)}/versions/${encodeURIComponent(String(version))}/rules`, "PUT", { rules });
}

export function createPolicy(input: PolicySetInput) {
  return sendJSON<PolicySet>("/api/v1/policies", "POST", input);
}

export async function heartbeatAgent(agentID: string, status: string, credentials: AgentCredentialInput) {
  const response = await fetch(`/api/v1/agents/${encodeURIComponent(agentID)}/heartbeat`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      ...agentCredentialHeaders(credentials)
    },
    body: JSON.stringify({ status })
  });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<Agent>;
}

export async function pullAgentPolicy(agentID: string, credentials: AgentCredentialInput) {
  const response = await fetch(`/api/v1/agents/${encodeURIComponent(agentID)}/policy`, {
    headers: {
      Accept: "application/json",
      ...agentCredentialHeaders(credentials)
    }
  });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<PolicyVersion>;
}

export function validateRules(rules: RuleInput[]) {
  return sendJSON<RuleValidation>("/api/v1/policies/validate", "POST", { rules });
}

export function testRule(rule: RuleInput, event: SecurityEventInput) {
  return sendJSON<RuleTestResult>("/api/v1/policies/test", "POST", { rule, event });
}

export function rolloutPolicy(policyID: string, version: number, canaryPercent: number, scope: PolicyRolloutScope = {}) {
  return sendJSON<PolicySet>(`/api/v1/policies/${encodeURIComponent(policyID)}/rollout`, "POST", {
    version,
    canary_percent: canaryPercent,
    ...scope
  });
}

export function rollbackPolicy(policyID: string) {
  return sendJSON<PolicySet>(`/api/v1/policies/${encodeURIComponent(policyID)}/rollback`, "POST", {});
}

export function createApplication(input: ApplicationCreateInput) {
  return sendJSON<Application>("/api/v1/applications", "POST", input);
}

export function createEnvironment(appID: string, input: EnvironmentCreateInput) {
  return sendJSON<Environment>(`/api/v1/applications/${encodeURIComponent(appID)}/environments`, "POST", input);
}

export function rotateApplicationSecret(appID: string) {
  return sendJSON<Application>(`/api/v1/applications/${encodeURIComponent(appID)}/secret/rotate`, "POST", {});
}

export function getDaemonToken() {
  return fetchJSON<DaemonAccessToken>("/api/v1/daemon/token");
}

export function resetDaemonToken() {
  return sendJSON<DaemonAccessToken>("/api/v1/daemon/token/reset", "POST", {});
}

export async function getDaemonApplicationCredential(token: string, applicationID: string) {
  const query = new URLSearchParams({ app_id: applicationID });
  const response = await fetch(`/api/v1/daemon/app?${query.toString()}`, {
    headers: daemonTokenHeaders(token)
  });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<DaemonApplicationCredential>;
}

export async function getAgentArtifactInfo(
  token: string,
  input: {
    applicationID: string;
    language: string;
    systemType: string;
    languageVersion: string;
  }
) {
  const query = new URLSearchParams({
    app_id: input.applicationID,
    language: input.language,
    system_type: input.systemType,
    language_version: input.languageVersion
  });
  const response = await fetch(`/api/v1/daemon/artifacts/agent/info?${query.toString()}`, {
    headers: daemonTokenHeaders(token)
  });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<AgentArtifactInfo>;
}

export async function downloadAgentArtifact(
  token: string,
  input: {
    applicationID: string;
    language: string;
    systemType: string;
    languageVersion: string;
  }
) {
  const query = new URLSearchParams({
    app_id: input.applicationID,
    language: input.language,
    system_type: input.systemType,
    language_version: input.languageVersion
  });
  const response = await fetch(`/api/v1/daemon/artifacts/agent?${query.toString()}`, {
    headers: daemonTokenHeaders(token)
  });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  const blob = await response.blob();
  return {
    blob,
    filename: artifactFilenameFromHeaders(response.headers) || `ohmyrasp-agent-${input.language}-${input.systemType}-${input.languageVersion}.zip`,
    md5: response.headers.get("X-OhMyRasp-Agent-MD5") ?? "",
    contentType: response.headers.get("Content-Type") ?? blob.type
  } satisfies AgentArtifactDownload;
}

export function uploadAgentArtifact(input: AgentArtifactUploadInput) {
  return sendJSON<AgentArtifactCatalogItem>("/api/v1/agent-artifacts", "POST", input);
}

export async function reportDaemonWorkloads(token: string, report: DaemonWorkloadReport) {
  const response = await fetch("/api/v1/daemon/workloads/report", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-OhMyRasp-Daemon-Token": token
    },
    body: JSON.stringify(report)
  });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<ListResponse<DaemonWorkload>>;
}

function daemonTokenHeaders(token: string) {
  return {
    Accept: "application/json",
    "X-OhMyRasp-Daemon-Token": token
  };
}

function artifactFilenameFromHeaders(headers: Headers) {
  const disposition = headers.get("Content-Disposition") ?? "";
  const utf8Match = disposition.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf8Match?.[1]) {
    return decodeURIComponent(utf8Match[1].replace(/^"|"$/g, ""));
  }
  const quotedMatch = disposition.match(/filename="([^"]+)"/i);
  if (quotedMatch?.[1]) {
    return quotedMatch[1];
  }
  const plainMatch = disposition.match(/filename=([^;]+)/i);
  return plainMatch?.[1]?.trim().replace(/^"|"$/g, "") ?? "";
}

export function bindDaemonWorkload(workloadID: string, applicationID: string) {
  return sendJSON<DaemonWorkload>(`/api/v1/daemon/workloads/${encodeURIComponent(workloadID)}/bind`, "POST", { application_id: applicationID });
}

export function unbindDaemonWorkload(workloadID: string) {
  return sendJSON<DaemonWorkload>(`/api/v1/daemon/workloads/${encodeURIComponent(workloadID)}/unbind`, "POST", {});
}

export async function registerAgent(input: AgentRegistrationInput) {
  const response = await fetch("/api/v1/agents/register", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      ...agentCredentialHeaders(input)
    },
    body: JSON.stringify({
      environment_id: input.environment_id,
      hostname: input.hostname,
      runtime: input.runtime,
      version: input.version
    })
  });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<Agent>;
}

function agentCredentialHeaders(credentials: AgentCredentialInput) {
  return {
    "X-OhMyRasp-App-ID": credentials.application_id,
    "X-OhMyRasp-App-Secret": credentials.application_secret
  };
}

export function updateSystemSetting(key: string, value: Record<string, unknown>) {
  return sendJSON<SystemSetting>(`/api/v1/system-settings/${encodeURIComponent(key)}`, "PUT", { value });
}

export function cleanupMaintenanceData(input: MaintenanceCleanupRequest) {
  return sendJSON<MaintenanceCleanupReport>("/api/v1/maintenance/cleanup", "POST", input);
}

export function moveEventsToRecycleBin(ids: string[]) {
  return sendJSON<EventRecycleBinReport>("/api/v1/events/recycle-bin/delete", "POST", { ids });
}

export function restoreEventsFromRecycleBin(ids: string[]) {
  return sendJSON<EventRecycleBinReport>("/api/v1/events/recycle-bin/restore", "POST", { ids });
}

export function purgeEventsFromRecycleBin(ids: string[]) {
  return sendJSON<EventRecycleBinReport>("/api/v1/events/recycle-bin/purge", "POST", { ids });
}

export function createAlertRule(input: AlertRuleInput) {
  return sendJSON<AlertRule>("/api/v1/alert-rules", "POST", input);
}

export function updateAlertRule(alertRuleID: string, input: AlertRuleInput) {
  return sendJSON<AlertRule>(`/api/v1/alert-rules/${encodeURIComponent(alertRuleID)}`, "PUT", input);
}

export function createUser(input: UserCreateInput) {
  return sendJSON<User>("/api/v1/users", "POST", input);
}

export function updateUser(userID: string, input: UserUpdateInput) {
  return sendJSON<User>(`/api/v1/users/${encodeURIComponent(userID)}`, "PUT", input);
}

function requestHeaders() {
  const headers: Record<string, string> = {
    Accept: "application/json"
  };
  const token = sessionToken();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  return headers;
}

function sessionToken() {
  if (typeof window === "undefined") {
    return "";
  }
  return window.localStorage.getItem("ohmyrasp.session_token") ?? window.localStorage.getItem("ohmyrasp.sessionToken") ?? "";
}

export function useOverview() {
  return useQuery({
    queryKey: ["overview"],
    queryFn: () => fetchJSON<OverviewResponse>("/api/v1/analytics/overview"),
    retry: false,
    staleTime: 15_000
  });
}

export function useApplications() {
  return useQuery({
    queryKey: ["applications"],
    queryFn: () => fetchJSON<ListResponse<Application>>("/api/v1/applications"),
    retry: false,
    staleTime: 15_000
  });
}

export function useAgents() {
  return useQuery({
    queryKey: ["agents"],
    queryFn: () => fetchJSON<ListResponse<Agent>>("/api/v1/agents"),
    retry: false,
    staleTime: 15_000
  });
}

export function useDaemonWorkloads() {
  return useQuery({
    queryKey: ["daemon-workloads"],
    queryFn: () => fetchJSON<ListResponse<DaemonWorkload>>("/api/v1/daemon/workloads"),
    retry: false,
    staleTime: 15_000
  });
}

export function useAgentArtifacts() {
  return useQuery({
    queryKey: ["agent-artifacts"],
    queryFn: () => fetchJSON<AgentArtifactCatalog>("/api/v1/agent-artifacts"),
    retry: false,
    staleTime: 15_000
  });
}

export function usePolicies() {
  return useQuery({
    queryKey: ["policies"],
    queryFn: () => fetchJSON<ListResponse<PolicySet>>("/api/v1/policies"),
    retry: false,
    staleTime: 15_000
  });
}

export function useAttackEvents(query: SecurityEventQuery = {}) {
  return useSecurityEvents("attack", query);
}

export function useSecurityEvents(eventType: SecurityEventType, query: SecurityEventQuery = {}) {
  const queryString = apiQueryString(query);
  return useQuery({
    queryKey: ["events", eventType, query],
    queryFn: () => fetchJSON<ListResponse<SecurityEvent>>(`/api/v1/events/${eventType}${queryString}`),
    retry: false,
    staleTime: 15_000
  });
}

export function useDeletedSecurityEvents(query: SecurityEventRecycleBinQuery = {}) {
  const queryString = apiQueryString(query);
  return useQuery({
    queryKey: ["events", "recycle-bin", query],
    queryFn: () => fetchJSON<ListResponse<SecurityEvent>>(`/api/v1/events/recycle-bin${queryString}`),
    retry: false,
    staleTime: 15_000
  });
}

function apiQueryString(query: object) {
  const params = new URLSearchParams();
  Object.entries(query as Record<string, string | number | undefined>).forEach(([key, value]) => {
    if (value === undefined || value === "") {
      return;
    }
    params.set(key, String(value));
  });
  const serialized = params.toString();
  return serialized ? `?${serialized}` : "";
}

export function useDependencies(query: DependencyQuery = {}) {
  const queryString = apiQueryString(query);
  return useQuery({
    queryKey: ["dependencies", query],
    queryFn: () => fetchJSON<ListResponse<Dependency>>(`/api/v1/dependencies${queryString}`),
    retry: false,
    staleTime: 15_000
  });
}

export function useBaselineFindings(query: BaselineFindingQuery = {}) {
  const queryString = apiQueryString(query);
  return useQuery({
    queryKey: ["baseline-findings", query],
    queryFn: () => fetchJSON<ListResponse<BaselineFinding>>(`/api/v1/baseline-findings${queryString}`),
    retry: false,
    staleTime: 15_000
  });
}

export function useAuditLogs() {
  return useQuery({
    queryKey: ["audit-logs"],
    queryFn: () => fetchJSON<ListResponse<AuditLog>>("/api/v1/audit-logs"),
    retry: false,
    staleTime: 15_000
  });
}

export function useSystemSettings() {
  return useQuery({
    queryKey: ["system-settings"],
    queryFn: () => fetchJSON<ListResponse<SystemSetting>>("/api/v1/system-settings"),
    retry: false,
    staleTime: 15_000
  });
}

export function useEditionStatus() {
  return useQuery({
    queryKey: ["system-edition"],
    queryFn: () => fetchJSON<EditionStatus>("/api/v1/system/edition"),
    retry: false,
    staleTime: 60_000
  });
}

export function useUsers() {
  return useQuery({
    queryKey: ["users"],
    queryFn: () => fetchJSON<ListResponse<User>>("/api/v1/users"),
    retry: false,
    staleTime: 15_000
  });
}

export function useAlertRules() {
  return useQuery({
    queryKey: ["alert-rules"],
    queryFn: () => fetchJSON<ListResponse<AlertRule>>("/api/v1/alert-rules"),
    retry: false,
    staleTime: 15_000
  });
}

export function useAlertDeliveries() {
  return useQuery({
    queryKey: ["alert-deliveries"],
    queryFn: () => fetchJSON<ListResponse<AlertDelivery>>("/api/v1/alert-deliveries"),
    retry: false,
    staleTime: 15_000
  });
}

export function useObservability(filters: ObservabilityFilters = {}) {
  const query = new URLSearchParams();
  if (filters.applicationID) {
    query.set("application_id", filters.applicationID);
  }
  if (filters.policyID) {
    query.set("policy_id", filters.policyID);
  }
  const encoded = query.toString();
  const suffix = encoded ? `?${encoded}` : "";
  return useQuery({
    queryKey: ["observability", filters.applicationID ?? "", filters.policyID ?? ""],
    queryFn: () => fetchJSON<ObservabilityResponse>(`/api/v1/analytics/observability${suffix}`),
    retry: false,
    staleTime: 15_000
  });
}

export function overviewFallback(): OverviewResponse {
  return {
    application_count: seededMetrics.applications,
    agent_count: seededMetrics.agentsTotal,
    online_agents: seededMetrics.agentsOnline,
    event_count: seededMetrics.attackEvents24h,
    events_by_type: {
      attack: seededMetrics.attackEvents24h,
      hook: 412,
      performance: 8640,
      crash: 1,
      dependency: 218
    },
    events_by_severity: {
      critical: 2,
      high: 9,
      medium: 20,
      low: 6
    }
  };
}

export function applicationsFallback(): ListResponse<Application> {
  return {
    items: [
      {
        id: "app_payments",
        name: "Payments API",
        description: "PCI scoped checkout and ledger service",
        created_at: "2026-05-31T00:00:00Z",
        environment_ids: ["env_payments_prod", "env_payments_staging"]
      },
      {
        id: "app_admin",
        name: "Admin Portal",
        description: "Internal operations console",
        created_at: "2026-05-31T00:00:00Z",
        environment_ids: ["env_admin_prod"]
      },
      {
        id: "app_gateway",
        name: "Partner Gateway",
        description: "External integration edge service",
        created_at: "2026-05-31T00:00:00Z",
        environment_ids: ["env_gateway_prod", "env_gateway_qa", "env_gateway_dev"]
      }
    ]
  };
}

export function agentsFallback(): ListResponse<Agent> {
  return {
    items: [
      {
        id: "agt_payments_1",
        application_id: "app_payments",
        environment_id: "env_payments_prod",
        hostname: "payments-1",
        runtime: "java",
        version: "1.0.0",
        status: "online",
        last_seen_at: "2026-05-31T00:00:00Z",
        policy_id: "pol_web",
        policy_version: 18
      },
      {
        id: "agt_admin_1",
        application_id: "app_admin",
        environment_id: "env_admin_prod",
        hostname: "admin-1",
        runtime: "java",
        version: "0.9.8",
        status: "online",
        last_seen_at: "2026-05-31T00:00:00Z",
        policy_id: "pol_admin",
        policy_version: 7
      },
      {
        id: "agt_gateway_1",
        application_id: "app_gateway",
        environment_id: "env_gateway_prod",
        hostname: "gateway-1",
        runtime: "java",
        version: "0.9.4",
        status: "offline",
        last_seen_at: "2026-05-30T23:20:00Z",
        policy_id: "pol_gateway",
        policy_version: 4
      }
    ]
  };
}

export function daemonWorkloadsFallback(): ListResponse<DaemonWorkload> {
  return {
    items: [
      {
        id: "wrk_payments_process",
        application_id: "app_payments",
        node_name: "rasp-node-1",
        type: "process",
        pid: 1842,
        cmdline: ["/usr/bin/java", "-jar", "payments.jar"],
        observed_at: "2026-05-31T00:00:00Z",
        updated_at: "2026-05-31T00:00:00Z"
      },
      {
        id: "wrk_gateway_container",
        node_name: "rasp-node-2",
        type: "container",
        container_id: "ctr_gateway",
        container_name: "partner-gateway",
        image_tag: "gateway:2026.05",
        observed_at: "2026-05-31T00:00:00Z",
        updated_at: "2026-05-31T00:00:00Z"
      }
    ]
  };
}

export function policiesFallback(): ListResponse<PolicySet> {
  return {
    items: [
      {
        id: "pol_web",
        name: "Web Protection",
        description: "SQL, command, and deserialization protections for Java services",
        created_at: "2026-05-31T00:00:00Z",
        active: {
          version: 18,
          status: "canary",
          canary_percent: 25,
          created_at: "2026-05-31T00:00:00Z",
          rules: [
            {
              id: "rul_sql",
              name: "Block SQL user input",
              hook: "sql",
              algorithm: "sql_userinput",
              action: "block",
              severity: "high",
              expression: "' OR '1'='1",
              tags: ["sql", "injection"],
              description: "Blocks tautology style SQL probes"
            }
          ]
        },
        versions: [
          {
            version: 18,
            status: "canary",
            canary_percent: 25,
            created_at: "2026-05-31T00:00:00Z",
            rules: []
          },
          {
            version: 17,
            status: "rolled_back",
            canary_percent: 100,
            created_at: "2026-05-30T00:00:00Z",
            rules: []
          }
        ]
      },
      {
        id: "pol_admin",
        name: "Strict Admin",
        description: "Tighter command and file protections for privileged internal tools",
        created_at: "2026-05-31T00:00:00Z",
        active: {
          version: 7,
          status: "active",
          canary_percent: 100,
          created_at: "2026-05-31T00:00:00Z",
          rules: []
        },
        versions: []
      }
    ]
  };
}

export function attackEventsFallback(): ListResponse<SecurityEvent> {
  return eventFallbackByType("attack");
}

export function eventFallbackByType(eventType: SecurityEventType): ListResponse<SecurityEvent> {
  const events: Record<SecurityEventType, SecurityEvent[]> = {
    attack: [
      {
        id: "evt_attack_1",
        type: "attack",
        application_id: "app_payments",
        environment_id: "env_payments_prod",
        agent_id: "agt_payments_1",
        policy_id: "pol_web",
        policy_version: 18,
        hook: "sql",
        algorithm: "sql_userinput",
        severity: "critical",
        message: "SQL tautology detected in checkout search parameter",
        occurred_at: "2026-05-31T00:00:00Z"
      },
      {
        id: "evt_attack_2",
        type: "attack",
        application_id: "app_gateway",
        environment_id: "env_gateway_prod",
        agent_id: "agt_gateway_1",
        policy_id: "pol_gateway",
        policy_version: 4,
        hook: "command",
        algorithm: "command_userinput",
        severity: "high",
        message: "Shell metacharacters detected in integration payload",
        occurred_at: "2026-05-30T23:58:00Z"
      }
    ],
    hook: [
      {
        id: "evt_hook_1",
        type: "hook",
        application_id: "app_payments",
        environment_id: "env_payments_prod",
        agent_id: "agt_payments_1",
        policy_id: "pol_web",
        policy_version: 18,
        hook: "servlet",
        algorithm: "request_trace",
        severity: "low",
        message: "Servlet hook completed with 1.7 ms latency",
        occurred_at: "2026-05-31T00:00:00Z",
        attributes: { latency_us: 1700 }
      }
    ],
    performance: [
      {
        id: "evt_perf_1",
        type: "performance",
        application_id: "app_payments",
        environment_id: "env_payments_prod",
        agent_id: "agt_payments_1",
        policy_id: "pol_web",
        policy_version: 18,
        hook: "sql",
        algorithm: "overhead_sample",
        severity: "low",
        message: "Agent overhead sample within policy budget",
        occurred_at: "2026-05-31T00:00:00Z",
        attributes: { cpu_overhead_pct: 1.4, memory_overhead_bytes: 52428800 }
      }
    ],
    crash: [
      {
        id: "evt_crash_1",
        type: "crash",
        application_id: "app_gateway",
        environment_id: "env_gateway_prod",
        agent_id: "agt_gateway_1",
        severity: "high",
        message: "Agent crash report captured during class transform",
        occurred_at: "2026-05-30T23:30:00Z",
        attributes: { exception: "ClassFormatError" }
      }
    ]
  };

  return {
    items: events[eventType]
  };
}

export function dependenciesFallback(): ListResponse<Dependency> {
  return {
    items: [
      {
        id: "dep_spring_web",
        application_id: "app_payments",
        agent_id: "agt_payments_1",
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
      },
      {
        id: "dep_log4j",
        application_id: "app_gateway",
        agent_id: "agt_gateway_1",
        name: "log4j-core",
        version: "2.17.2",
        ecosystem: "maven",
        licenses: ["Apache-2.0"],
        vulnerabilities: [
          {
            id: "CVE-2021-45046",
            severity: "high",
            fixed_version: "2.17.3"
          }
        ],
        observed_at: "2026-05-30T23:58:00Z"
      }
    ]
  };
}

export function baselineFindingsFallback(): ListResponse<BaselineFinding> {
  return {
    items: [
      {
        id: "bsl_jvm_security_manager",
        application_id: "app_payments",
        environment_id: "env_prod",
        agent_id: "agt_payments_1",
        check_id: "jvm.security_manager",
        title: "JVM security manager disabled",
        category: "runtime",
        severity: "medium",
        status: "warning",
        resource: "payments-api-1",
        remediation: "Enable explicit policy controls before production rollout.",
        attributes: { runtime: "java" },
        observed_at: "2026-05-31T00:02:00Z"
      },
      {
        id: "bsl_agent_policy",
        application_id: "app_gateway",
        environment_id: "env_prod",
        agent_id: "agt_gateway_1",
        check_id: "agent.policy.current",
        title: "Agent policy is current",
        category: "policy",
        severity: "info",
        status: "passed",
        resource: "gateway-1",
        observed_at: "2026-05-31T00:01:00Z"
      }
    ]
  };
}

export function auditLogsFallback(): ListResponse<AuditLog> {
  return {
    items: [
      {
        id: "aud_1",
        actor_id: "usr_admin",
        action: "policy.rollout",
        resource: "pol_web",
        details: { version: 18, canary_percent: 25 },
        created_at: "2026-05-31T00:00:00Z"
      },
      {
        id: "aud_2",
        actor_id: "usr_admin",
        action: "agent.register",
        resource: "agt_payments_1",
        details: { application_id: "app_payments" },
        created_at: "2026-05-30T23:50:00Z"
      }
    ]
  };
}

export function agentArtifactsFallback(): AgentArtifactCatalog {
  return {
    artifact_dir_configured: false,
    generated_bootstrap_enabled: true,
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
  };
}

export function systemSettingsFallback(): ListResponse<SystemSetting> {
  return {
    items: [
      {
        key: "agent.minimum_version",
        value: { version: "1.0.0", enforcement: "warn" },
        updated_by: "system",
        updated_at: "2026-05-31T00:00:00Z"
      },
      {
        key: "events.retention",
        value: { attack_days: 180, performance_days: 30, dependency_days: 365, audit_days: 365 },
        updated_by: "system",
        updated_at: "2026-05-31T00:00:00Z"
      },
      {
        key: "policy.canary",
        value: { default_percent: 25, auto_promote: false },
        updated_by: "system",
        updated_at: "2026-05-31T00:00:00Z"
      },
      {
        key: "protection.allowlist",
        value: { enabled: false, mode: "monitor", entries: [] },
        updated_by: "system",
        updated_at: "2026-05-31T00:00:00Z"
      },
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
  };
}

export function editionStatusFallback(): EditionStatus {
  return {
    edition: "oss_self_hosted",
    display_name: "Open Source Self-Hosted",
    deployment_model: "single_organization_self_hosted",
    license_required: false,
    license_enforcement: "none",
    license_status: "not_applicable",
    note: "Open-source self-hosted deployments do not require a license key and do not enforce license limits."
  };
}

export function usersFallback(): ListResponse<User> {
  return {
    items: [
      {
        id: "usr_admin",
        email: "admin@ohmyrasp.local",
        name: "Default Admin",
        roles: ["admin", "security_engineer"],
        created_at: "2026-05-31T00:00:00Z",
        updated_at: "2026-05-31T00:00:00Z"
      },
      {
        id: "usr_security",
        email: "security@example.test",
        name: "Security Engineer",
        roles: ["security_engineer"],
        created_at: "2026-05-31T00:00:00Z",
        updated_at: "2026-05-31T00:00:00Z"
      },
      {
        id: "usr_viewer",
        email: "viewer@example.test",
        name: "Audit Viewer",
        roles: ["viewer"],
        created_at: "2026-05-31T00:00:00Z",
        updated_at: "2026-05-31T00:00:00Z",
        disabled_at: "2026-05-31T00:00:00Z"
      }
    ]
  };
}

export function alertRulesFallback(): ListResponse<AlertRule> {
  return {
    items: [
      {
        id: "alr_critical_attack",
        name: "Critical attack event",
        description: "Notify security operators when a critical attack event is ingested.",
        enabled: true,
        event_type: "attack",
        severity: "critical",
        condition: "severity == critical",
        target: "security-operations",
        created_at: "2026-05-31T00:00:00Z",
        updated_at: "2026-05-31T00:00:00Z"
      },
      {
        id: "alr_agent_crash",
        name: "Agent crash",
        description: "Open an operational alert when an Agent crash is reported.",
        enabled: true,
        event_type: "crash",
        severity: "high",
        condition: "event_type == crash",
        target: "platform-operations",
        created_at: "2026-05-31T00:00:00Z",
        updated_at: "2026-05-31T00:00:00Z"
      }
    ]
  };
}

export function alertDeliveriesFallback(): ListResponse<AlertDelivery> {
  return {
    items: [
      {
        id: "adl_critical_attack_1",
        alert_rule_id: "alr_critical_attack",
        alert_rule_name: "Critical attack event",
        event_id: "evt_attack_1",
        event_type: "attack",
        severity: "critical",
        target: "security-operations",
        status: "queued",
        attempts: 0,
        created_at: "2026-05-31T00:00:00Z"
      },
      {
        id: "adl_agent_crash_1",
        alert_rule_id: "alr_agent_crash",
        alert_rule_name: "Agent crash",
        event_id: "evt_crash_1",
        event_type: "crash",
        severity: "high",
        target: "platform-operations",
        status: "failed",
        attempts: 3,
        last_error: "delivery target unavailable",
        created_at: "2026-05-30T23:42:00Z"
      }
    ]
  };
}

export function observabilityFallback(): ObservabilityResponse {
  return {
    rule_overhead: [
      {
        policy_id: "pol_demo",
        policy_version: seededMetrics.policyVersions,
        rule_id: "rul_sql",
        hook: "sql",
        executions: 12400,
        blocked: 31,
        average_latency_us: 410,
        p95_latency_us: 1800,
        max_latency_us: 4200
      },
      {
        policy_id: "pol_demo",
        policy_version: seededMetrics.policyVersions,
        rule_id: "rul_cmd",
        hook: "command",
        executions: 3200,
        blocked: 8,
        average_latency_us: 760,
        p95_latency_us: 2400,
        max_latency_us: 6100
      }
    ],
    hook_latency: [
      {
        hook: "command",
        calls: 3200,
        average_latency_us: 760,
        p95_latency_us: 2400,
        max_latency_us: 6100
      },
      {
        hook: "sql",
        calls: 12400,
        average_latency_us: 410,
        p95_latency_us: 1800,
        max_latency_us: 4200
      }
    ],
    agent_overhead: [
      {
        agent_id: "agt_demo_1",
        samples: 1440,
        cpu_overhead_pct: 1.7,
        memory_overhead_bytes: 62914560,
        hook_latency_p95_us: 1800,
        rule_eval_p95_us: 950
      }
    ],
    policy_performance: [
      {
        policy_id: "pol_demo",
        policy_version: seededMetrics.policyVersions,
        samples: 1440,
        cpu_overhead_pct: 1.7,
        hook_latency_p95_us: 1800,
        rule_eval_p95_us: 950
      },
      {
        policy_id: "pol_demo",
        policy_version: seededMetrics.policyVersions - 1,
        samples: 1440,
        cpu_overhead_pct: 1.5,
        hook_latency_p95_us: 1500,
        rule_eval_p95_us: 840
      }
    ]
  };
}
