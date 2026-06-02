import { useEffect, useMemo, useState } from "react";
import { CircleDot, FlaskConical, GitBranch, Plus, RotateCcw, Send, ShieldCheck } from "lucide-react";
import { api, type PolicySet, type Rule, type RuleInput, type SecurityEvent } from "../lib/api";
import { useApplications, useEvents, useInvalidator, useMutation, usePolicies } from "../lib/queries";
import { useAppScope } from "../lib/app-context";
import { focusStoredSection } from "../lib/focus";
import { PageHeader, RequireApplication, Grid } from "../components/page";
import { Badge, Button, EmptyState, Field, Mono, Panel, QueryState, SelectInput, Table, Td, TextInput, Th, SeverityTag } from "../components/ui";
import { isPrivileged } from "../lib/session";
import { shortDateTime, titleCase } from "../lib/format";
import { cn } from "../lib/cn";
import { useT } from "../i18n";

export function PoliciesPage() {
  const t = useT();
  useEffect(focusStoredSection, []);
  return (
    <>
      <PageHeader
        eyebrow={t("Enforcement")}
        title={t("Policies")}
        description={t("The detection ruleset assigned to this application, its version lifecycle, and the shared policy pool.")}
      />
      <RequireApplication>{(appId) => <PoliciesBody appId={appId} />}</RequireApplication>
    </>
  );
}

function actionTone(action: string) {
  const a = action.toLowerCase();
  if (a === "block") return "danger" as const;
  if (a === "ignore") return "neutral" as const;
  return "info" as const;
}

function PoliciesBody({ appId }: { appId: string }) {
  const t = useT();
  const policies = usePolicies();
  const apps = useApplications();
  const attacks = useEvents("attack", { limit: 25 });
  const scope = useAppScope();
  const invalidate = useInvalidator();
  const privileged = isPrivileged();
  const app = apps.data?.find((a) => a.id === appId);
  const assignedId = app?.policy_id;
  const assigned = policies.data?.find((p) => p.id === assignedId) ?? null;
  const activeVersion = assigned?.versions.find((v) => v.version === app?.policy_version) ?? assigned?.active ?? null;
  const [selectedPolicyId, setSelectedPolicyId] = useState("");

  useEffect(() => {
    const fallback = assignedId || policies.data?.[0]?.id || "";
    if (!selectedPolicyId && fallback) setSelectedPolicyId(fallback);
    if (selectedPolicyId && policies.data && !policies.data.some((p) => p.id === selectedPolicyId)) setSelectedPolicyId(fallback);
  }, [assignedId, policies.data, selectedPolicyId]);

  const selectedPolicy = policies.data?.find((p) => p.id === selectedPolicyId) ?? assigned ?? policies.data?.[0] ?? null;

  const rollback = useMutation({
    mutationFn: (id: string) => api.rollbackPolicy(id),
    onSuccess: () => invalidate("policies", "applications")
  });

  return (
    <div className="space-y-4" data-section="policy-workflows" tabIndex={-1}>
      <Grid className="lg:grid-cols-[1.5fr_1fr]">
        <Panel
          eyebrow={t("Assigned to this application")}
          title={assigned ? assigned.name : t("No policy assigned")}
          actions={
            assigned && (
              <div className="flex items-center gap-2">
                <Badge tone="signal">
                  <CircleDot className="h-3 w-3" /> v{activeVersion?.version ?? "?"} · {activeVersion?.status ?? "—"}
                </Badge>
                {privileged && (
                  <Button variant="ghost" size="sm" onClick={() => rollback.mutate(assigned.id)} disabled={rollback.isPending}>
                    <RotateCcw className="h-3.5 w-3.5" /> {t("Rollback")}
                  </Button>
                )}
              </div>
            )
          }
        >
          <QueryState isLoading={policies.isLoading} isError={policies.isError} error={policies.error}>
            {!assigned ? (
              <EmptyState
                icon={<ShieldCheck className="h-5 w-5" />}
                title={t("This application has no assigned policy")}
                hint={t("Assign a policy below, or create one. Until then, agents fall back to their built-in defaults.")}
              />
            ) : (activeVersion?.rules ?? []).length === 0 ? (
              <EmptyState title={t("Active version has no rules")} />
            ) : (
              <RulesTable rules={activeVersion!.rules} />
            )}
          </QueryState>
        </Panel>

        <VersionHistory policy={assigned} activeVersion={activeVersion?.version} isLoading={policies.isLoading} isError={policies.isError} error={policies.error} />
      </Grid>

      {privileged && (
        <Grid className="xl:grid-cols-[0.85fr_1.15fr]">
          <CreatePolicyPanel />
          <PolicyEditorPanel
            policies={policies.data ?? []}
            selectedPolicy={selectedPolicy}
            selectedPolicyId={selectedPolicyId}
            onSelect={setSelectedPolicyId}
            appId={appId}
            environmentId={scope.environmentId}
            sampleEvent={attacks.data?.[0]}
          />
        </Grid>
      )}
      {!privileged && <p className="text-[12px] text-faint">{t("You have read-only access. Administrators and security engineers can manage policies.")}</p>}

      <Panel eyebrow={t("Shared pool")} title={t("All policies")}>
        <QueryState
          isLoading={policies.isLoading}
          isError={policies.isError}
          error={policies.error}
          isEmpty={(policies.data ?? []).length === 0}
          emptyTitle={t("No policies defined")}
        >
          <PolicyPool policies={policies.data ?? []} applications={apps.data ?? []} assignedId={assignedId} appName={app?.name ?? ""} envSelected={!!scope.environmentId} />
        </QueryState>
      </Panel>
    </div>
  );
}

function VersionHistory({
  policy,
  activeVersion,
  isLoading,
  isError,
  error
}: {
  policy: PolicySet | null;
  activeVersion?: number;
  isLoading: boolean;
  isError: boolean;
  error: unknown;
}) {
  const t = useT();
  return (
    <Panel eyebrow={t("Lifecycle")} title={t("Version history")}>
      <QueryState isLoading={isLoading} isError={isError} error={error}>
        {!policy ? (
          <p className="py-6 text-center text-[12px] text-faint">{t("No versions")}</p>
        ) : (
          <ol className="space-y-2">
            {[...policy.versions]
              .sort((a, b) => b.version - a.version)
              .map((v) => {
                const current = v.version === activeVersion;
                return (
                  <li
                    key={v.version}
                    className={cn(
                      "flex items-center justify-between rounded-md border px-3 py-2",
                      current ? "border-signal/40 bg-signal/5" : "border-hairline bg-obsidian/50"
                    )}
                  >
                    <div className="flex items-center gap-2.5">
                      <GitBranch className={cn("h-4 w-4", current ? "text-signal" : "text-faint")} />
                      <div>
                        <div className="readout text-[13px] text-ink">v{v.version}</div>
                        <div className="eyebrow text-[10px]">
                          {v.rules.length} {t("rules")}
                        </div>
                      </div>
                    </div>
                    <div className="text-right">
                      <Badge tone={v.status === "active" ? "signal" : v.status === "canary" ? "warn" : "neutral"}>{v.status}</Badge>
                      {typeof v.canary_percent === "number" && v.canary_percent < 100 && (
                        <div className="readout mt-1 text-[10px] text-faint">
                          {v.canary_percent}% {t("canary")}
                        </div>
                      )}
                    </div>
                  </li>
                );
              })}
          </ol>
        )}
      </QueryState>
    </Panel>
  );
}

function CreatePolicyPanel() {
  const t = useT();
  const invalidate = useInvalidator();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const create = useMutation({
    mutationFn: () => api.createPolicy({ name: name.trim(), description: description.trim() || undefined }),
    onSuccess: () => {
      setName("");
      setDescription("");
      invalidate("policies");
    }
  });
  return (
    <Panel title={t("Create policy")} eyebrow={t("Authoring")}>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (name.trim()) create.mutate();
        }}
      >
        <Field label={t("Name")}>
          <TextInput value={name} onChange={(e) => setName(e.target.value)} required />
        </Field>
        <Field label={t("Description")}>
          <TextInput value={description} onChange={(e) => setDescription(e.target.value)} />
        </Field>
        <Button type="submit" variant="primary" disabled={create.isPending || !name.trim()}>
          <Plus className="h-3.5 w-3.5" /> {t("Create")}
        </Button>
      </form>
    </Panel>
  );
}

function PolicyEditorPanel({
  policies,
  selectedPolicy,
  selectedPolicyId,
  onSelect,
  appId,
  environmentId,
  sampleEvent
}: {
  policies: PolicySet[];
  selectedPolicy: PolicySet | null;
  selectedPolicyId: string;
  onSelect: (id: string) => void;
  appId: string;
  environmentId: string | null;
  sampleEvent?: SecurityEvent;
}) {
  const t = useT();
  const invalidate = useInvalidator();
  const [message, setMessage] = useState("");
  const [rule, setRule] = useState<RuleInput>({
    name: "Custom SQLi rule",
    hook: "sql",
    algorithm: "regex",
    action: "block",
    severity: "high",
    expression: "(?i)(union|select|sleep)",
    tags: ["custom"]
  });
  const latestVersion = useMemo(() => Math.max(0, ...((selectedPolicy?.versions ?? []).map((v) => v.version))), [selectedPolicy]);
  const [version, setVersion] = useState("1");
  const [canary, setCanary] = useState("100");

  useEffect(() => setVersion(String(latestVersion || 1)), [latestVersion]);

  const validate = useMutation({
    mutationFn: () => api.validateRules([rule]),
    onSuccess: (result) => setMessage(result.valid ? t("Rule validation passed.") : t("Rule validation failed: {errors}", { errors: result.errors.join("; ") }))
  });
  const test = useMutation({
    mutationFn: () => api.testRule(rule, eventInput(sampleEvent!, appId)),
    onSuccess: (result) => setMessage(t("Rule test: {matched} · {action}", { matched: result.matched ? t("matched") : t("not matched"), action: result.action || "—" }))
  });
  const addVersion = useMutation({
    mutationFn: () => api.addPolicyVersion(selectedPolicy!.id, [rule]),
    onSuccess: () => {
      setMessage(t("Policy version created."));
      invalidate("policies");
    }
  });
  const rollout = useMutation({
    mutationFn: () =>
      api.rolloutPolicy(selectedPolicy!.id, {
        version: Number(version) || latestVersion || 1,
        canary_percent: Math.max(0, Math.min(100, Number(canary) || 0)),
        application_id: appId,
        environment_id: environmentId ?? undefined
      }),
    onSuccess: () => {
      setMessage(t("Policy rolled out."));
      invalidate("policies", "applications");
    }
  });
  const restoreDefaults = useMutation({
    mutationFn: () => api.restoreDefaultPolicy(selectedPolicy!.id),
    onSuccess: () => {
      setMessage(t("Default rules restored."));
      invalidate("policies");
    }
  });

  const disabled = !selectedPolicy;
  return (
    <Panel title={t("Rule authoring")} eyebrow={t("Validate · test · rollout")} data-section="algorithm" tabIndex={-1}>
      <div className="space-y-4">
        <Field label={t("Policy")}>
          <SelectInput value={selectedPolicyId} onChange={(e) => onSelect(e.target.value)} disabled={policies.length === 0}>
            {policies.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </SelectInput>
        </Field>

        <div className="grid gap-3 md:grid-cols-2">
          <Field label={t("Rule")}>
            <TextInput value={rule.name} onChange={(e) => setRule({ ...rule, name: e.target.value })} />
          </Field>
          <Field label={t("Hook")}>
            <TextInput value={rule.hook} onChange={(e) => setRule({ ...rule, hook: e.target.value })} />
          </Field>
          <Field label={t("Algorithm")}>
            <TextInput value={rule.algorithm ?? ""} onChange={(e) => setRule({ ...rule, algorithm: e.target.value })} />
          </Field>
          <Field label={t("Action")}>
            <SelectInput value={rule.action ?? "block"} onChange={(e) => setRule({ ...rule, action: e.target.value })}>
              <option value="block">{t("Block")}</option>
              <option value="log">{t("Log")}</option>
              <option value="ignore">{t("Ignore")}</option>
            </SelectInput>
          </Field>
          <Field label={t("Severity")}>
            <SelectInput value={rule.severity ?? "high"} onChange={(e) => setRule({ ...rule, severity: e.target.value })}>
              <option value="critical">{t("Critical")}</option>
              <option value="high">{t("High")}</option>
              <option value="medium">{t("Medium")}</option>
              <option value="low">{t("Low")}</option>
            </SelectInput>
          </Field>
          <Field label={t("Tags")}>
            <TextInput value={(rule.tags ?? []).join(", ")} onChange={(e) => setRule({ ...rule, tags: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })} />
          </Field>
        </div>

        <Field label={t("Expression")}>
          <textarea
            value={rule.expression}
            onChange={(e) => setRule({ ...rule, expression: e.target.value })}
            rows={3}
            className="readout w-full rounded-md border border-hairline bg-obsidian px-3 py-2 text-[12px] text-ink placeholder:text-faint focus:border-signal/50 focus:outline-hidden focus:ring-2 focus:ring-signal/30"
          />
        </Field>

        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" variant="ghost" onClick={() => validate.mutate()} disabled={validate.isPending}>
            <FlaskConical className="h-3.5 w-3.5" /> {t("Validate")}
          </Button>
          <Button size="sm" variant="ghost" onClick={() => test.mutate()} disabled={test.isPending || !sampleEvent}>
            <FlaskConical className="h-3.5 w-3.5" /> {sampleEvent ? t("Test") : t("No sample event")}
          </Button>
          <Button size="sm" variant="ghost" onClick={() => addVersion.mutate()} disabled={disabled || addVersion.isPending}>
            <GitBranch className="h-3.5 w-3.5" /> {t("Add version")}
          </Button>
          <Button size="sm" variant="ghost" onClick={() => restoreDefaults.mutate()} disabled={disabled || restoreDefaults.isPending}>
            <RotateCcw className="h-3.5 w-3.5" /> {t("Restore defaults")}
          </Button>
        </div>

        <div className="grid gap-3 md:grid-cols-[1fr_1fr_auto]">
          <Field label={t("Version")}>
            <SelectInput value={version} disabled={disabled} onChange={(e) => setVersion(e.target.value)}>
              {(selectedPolicy?.versions ?? [{ version: latestVersion || 1 }]).map((v) => (
                <option key={v.version} value={v.version}>
                  v{v.version}
                </option>
              ))}
            </SelectInput>
          </Field>
          <Field label={t("Canary percent")}>
            <TextInput type="number" min={0} max={100} value={canary} disabled={disabled} onChange={(e) => setCanary(e.target.value)} />
          </Field>
          <div className="flex items-end">
            <Button variant="primary" onClick={() => rollout.mutate()} disabled={disabled || rollout.isPending}>
              <Send className="h-3.5 w-3.5" /> {t("Rollout")}
            </Button>
          </div>
        </div>
        {environmentId && <p className="text-[12px] text-medium">{t("Rollout is scoped to the selected environment.")}</p>}
        {message && <p className="text-[12px] text-signal">{message}</p>}
      </div>
    </Panel>
  );
}

function RulesTable({ rules }: { rules: Rule[] }) {
  const t = useT();
  return (
    <Table>
      <thead>
        <tr>
          <Th>{t("Rule")}</Th>
          <Th>{t("Hook · Algorithm")}</Th>
          <Th>{t("Action")}</Th>
          <Th>{t("Severity")}</Th>
          <Th>{t("Expression")}</Th>
        </tr>
      </thead>
      <tbody>
        {rules.map((r) => (
          <tr key={r.id}>
            <Td>
              <div className="text-[13px] text-ink">{r.name}</div>
              {r.tags && r.tags.length > 0 && <Mono className="text-[11px] text-faint">{r.tags.join(" · ")}</Mono>}
            </Td>
            <Td>
              <div className="text-[13px] text-muted">{titleCase(r.hook)}</div>
              <Mono className="text-[11px] text-faint">{r.algorithm}</Mono>
            </Td>
            <Td>
              <Badge tone={actionTone(r.action)}>{r.action}</Badge>
            </Td>
            <Td>
              <SeverityTag value={r.severity} />
            </Td>
            <Td className="max-w-[260px]">
              <Mono className="line-clamp-1 text-[11px]" title={r.expression}>
                {r.expression || "—"}
              </Mono>
            </Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

function PolicyPool({
  policies,
  applications,
  assignedId,
  appName,
  envSelected
}: {
  policies: PolicySet[];
  applications: { id: string; name: string; policy_id?: string }[];
  assignedId?: string;
  appName: string;
  envSelected: boolean;
}) {
  const t = useT();
  const usage = useMemo(() => {
    const map = new Map<string, string[]>();
    for (const app of applications) {
      if (!app.policy_id) continue;
      map.set(app.policy_id, [...(map.get(app.policy_id) ?? []), app.name]);
    }
    return map;
  }, [applications]);
  return (
    <div className="space-y-2">
      {envSelected && (
        <p className="rounded-md border border-medium/30 bg-medium/5 px-3 py-2 text-[12px] text-medium">
          {t("An environment sub-scope is selected. Policy assignment shown is at the application level; environment overrides take precedence on the agent.")}
        </p>
      )}
      <Table>
        <thead>
          <tr>
            <Th>{t("Policy")}</Th>
            <Th>{t("Active version")}</Th>
            <Th>{t("Rules")}</Th>
            <Th>{t("Created")}</Th>
            <Th>{t("Assignment")}</Th>
          </tr>
        </thead>
        <tbody>
          {policies.map((p) => {
            const active = p.active ?? p.versions.find((v) => v.status === "active");
            const assignedApps = usage.get(p.id) ?? [];
            const shared = assignedApps.length > 1;
            return (
              <tr key={p.id}>
                <Td>
                  <div className="text-[13px] text-ink">{p.name}</div>
                  <Mono className="text-[11px] text-faint">{p.id}</Mono>
                </Td>
                <Td>{active ? <Badge tone="signal">v{active.version}</Badge> : <span className="text-faint">{t("draft")}</span>}</Td>
                <Td>
                  <span className="readout">{active?.rules.length ?? 0}</span>
                </Td>
                <Td>{shortDateTime(p.created_at)}</Td>
                <Td>
                  <div className="flex flex-wrap gap-1">
                    {p.id === assignedId && <Badge tone="signal">{appName || t("this app")}</Badge>}
                    {shared && <Badge tone="warn">{t("shared")}</Badge>}
                    {assignedApps.length === 0 && <span className="text-faint">—</span>}
                  </div>
                </Td>
              </tr>
            );
          })}
        </tbody>
      </Table>
    </div>
  );
}

function eventInput(event: SecurityEvent, appId: string) {
  return {
    application_id: event.application_id || appId,
    environment_id: event.environment_id,
    agent_id: event.agent_id || "sample-agent",
    policy_id: event.policy_id,
    policy_version: event.policy_version,
    hook: event.hook,
    algorithm: event.algorithm,
    severity: event.severity || "high",
    message: event.message || "sample event",
    occurred_at: event.occurred_at,
    attributes: event.attributes
  };
}
