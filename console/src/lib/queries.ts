import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type SecurityEventQuery } from "./api";
import { useAppScope } from "./app-context";

const REFRESH = 30_000;

export function useApplications() {
  return useQuery({ queryKey: ["applications"], queryFn: api.applications });
}

/** Scope filter derived from the global application context. */
function useScopeFilter(): SecurityEventQuery {
  const scope = useAppScope();
  return {
    application_id: scope.applicationId ?? undefined,
    environment_id: scope.environmentId ?? undefined
  };
}

export function useOverview() {
  const scope = useScopeFilter();
  return useQuery({
    queryKey: ["overview", scope],
    queryFn: () => api.overview(scope),
    refetchInterval: REFRESH,
    enabled: !!scope.application_id
  });
}

export function useObservability() {
  const scope = useScopeFilter();
  return useQuery({
    queryKey: ["observability", scope],
    queryFn: () => api.observability(scope),
    enabled: !!scope.application_id
  });
}

export function useAgents() {
  const scope = useScopeFilter();
  return useQuery({
    queryKey: ["agents", scope],
    queryFn: () => api.agents(scope),
    refetchInterval: REFRESH,
    enabled: !!scope.application_id
  });
}

export function usePolicies() {
  return useQuery({ queryKey: ["policies"], queryFn: api.policies });
}
export function useAlgorithms() {
  return useQuery({ queryKey: ["algorithms"], queryFn: api.algorithms, staleTime: 5 * 60_000 });
}

export function useEvents(type: "attack" | "error" | "crash", extra?: SecurityEventQuery) {
  const scope = useScopeFilter();
  const query = { ...scope, ...extra };
  return useQuery({
    queryKey: ["events", type, query],
    queryFn: () => api.events(type, query),
    enabled: !!scope.application_id
  });
}

export function useRecycleBin(extra?: SecurityEventQuery) {
  const scope = useScopeFilter();
  const query = { ...scope, ...extra };
  return useQuery({
    queryKey: ["recycle-bin", query],
    queryFn: () => api.recycleBin(query),
    enabled: !!scope.application_id
  });
}

export function useDependencies() {
  const scope = useScopeFilter();
  return useQuery({
    queryKey: ["dependencies", scope],
    queryFn: () => api.dependencies(scope),
    enabled: !!scope.application_id
  });
}

export function useBaselineFindings() {
  const scope = useScopeFilter();
  return useQuery({
    queryKey: ["baseline", scope],
    queryFn: () => api.baselineFindings(scope),
    enabled: !!scope.application_id
  });
}

export function useApplicationSettings(appID: string | null, environmentID?: string | null) {
  return useQuery({
    queryKey: ["app-settings", appID, environmentID ?? ""],
    queryFn: () => api.applicationSettings(appID!, environmentID),
    enabled: !!appID
  });
}

export function useAlertRules() {
  const scope = useScopeFilter();
  return useQuery({
    queryKey: ["alert-rules", scope.application_id ?? ""],
    queryFn: () => api.alertRules({ application_id: scope.application_id ?? undefined }),
    enabled: !!scope.application_id
  });
}
export function useAlertDeliveries() {
  const scope = useScopeFilter();
  return useQuery({
    queryKey: ["alert-deliveries", scope.application_id ?? ""],
    queryFn: () => api.alertDeliveries({ application_id: scope.application_id ?? undefined }),
    enabled: !!scope.application_id,
    refetchInterval: REFRESH
  });
}
export function useAuditLogs() {
  return useQuery({ queryKey: ["audit-logs"], queryFn: api.auditLogs });
}
export function useUsers() {
  return useQuery({ queryKey: ["users"], queryFn: () => api.users() });
}
export function useSystemSettings() {
  return useQuery({ queryKey: ["system-settings"], queryFn: api.systemSettings });
}
export function useVersion() {
  return useQuery({ queryKey: ["version"], queryFn: api.version, staleTime: 5 * 60_000 });
}
export function useEdition() {
  return useQuery({ queryKey: ["edition"], queryFn: api.edition, staleTime: 5 * 60_000 });
}
export function useAgentArtifacts() {
  return useQuery({ queryKey: ["agent-artifacts"], queryFn: api.agentArtifacts, staleTime: 30_000 });
}

/** Invalidate a set of query keys after a mutation. */
export function useInvalidator() {
  const qc = useQueryClient();
  return (...keys: string[]) => {
    for (const k of keys) qc.invalidateQueries({ queryKey: [k] });
  };
}

export { useMutation };
