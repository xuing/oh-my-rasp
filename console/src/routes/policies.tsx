import { ShieldCheck, GitBranch, RotateCcw, CircleDot } from "lucide-react";
import { api, type PolicySet, type Rule } from "../lib/api";
import { usePolicies, useApplications, useInvalidator, useMutation } from "../lib/queries";
import { useAppScope } from "../lib/app-context";
import { PageHeader, RequireApplication, Grid } from "../components/page";
import { Panel, QueryState, Table, Th, Td, Badge, SeverityTag, Mono, Button, EmptyState } from "../components/ui";
import { isPrivileged } from "../lib/session";
import { shortDateTime, titleCase } from "../lib/format";
import { cn } from "../lib/cn";
import { useT } from "../i18n";

export function PoliciesPage() {
  const t = useT();
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
  const scope = useAppScope();
  const invalidate = useInvalidator();
  const privileged = isPrivileged();

  const app = apps.data?.find((a) => a.id === appId);
  const assignedId = app?.policy_id;
  const assigned = policies.data?.find((p) => p.id === assignedId) ?? null;
  const activeVersion =
    assigned?.versions.find((v) => v.version === app?.policy_version) ?? assigned?.active ?? null;

  const rollback = useMutation({
    mutationFn: (id: string) => api.rollbackPolicy(id),
    onSuccess: () => invalidate("policies", "applications")
  });

  return (
    <div className="space-y-4">
      <Grid className="lg:grid-cols-[1.6fr_1fr]">
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

        <Panel eyebrow={t("Lifecycle")} title={t("Version history")}>
          <QueryState isLoading={policies.isLoading} isError={policies.isError} error={policies.error}>
            {!assigned ? (
              <p className="py-6 text-center text-[12px] text-faint">{t("No versions")}</p>
            ) : (
              <ol className="space-y-2">
                {[...assigned.versions]
                  .sort((a, b) => b.version - a.version)
                  .map((v) => {
                    const current = v.version === activeVersion?.version;
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
                            <div className="eyebrow text-[10px]">{v.rules.length} {t("rules")}</div>
                          </div>
                        </div>
                        <div className="text-right">
                          <Badge tone={v.status === "active" ? "signal" : v.status === "canary" ? "warn" : "neutral"}>
                            {v.status}
                          </Badge>
                          {typeof v.canary_percent === "number" && v.canary_percent < 100 && (
                            <div className="readout mt-1 text-[10px] text-faint">{v.canary_percent}% {t("canary")}</div>
                          )}
                        </div>
                      </li>
                    );
                  })}
              </ol>
            )}
          </QueryState>
        </Panel>
      </Grid>

      <Panel eyebrow={t("Shared pool")} title={t("All policies")}>
        <QueryState
          isLoading={policies.isLoading}
          isError={policies.isError}
          error={policies.error}
          isEmpty={(policies.data ?? []).length === 0}
          emptyTitle={t("No policies defined")}
        >
          <PolicyPool policies={policies.data ?? []} assignedId={assignedId} appName={app?.name ?? ""} envSelected={!!scope.environmentId} />
        </QueryState>
      </Panel>
    </div>
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
  assignedId,
  appName,
  envSelected
}: {
  policies: PolicySet[];
  assignedId?: string;
  appName: string;
  envSelected: boolean;
}) {
  const t = useT();
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
            return (
              <tr key={p.id}>
                <Td>
                  <div className="text-[13px] text-ink">{p.name}</div>
                  <Mono className="text-[11px] text-faint">{p.id}</Mono>
                </Td>
                <Td>
                  {active ? <Badge tone="signal">v{active.version}</Badge> : <span className="text-faint">{t("draft")}</span>}
                </Td>
                <Td>
                  <span className="readout">{active?.rules.length ?? 0}</span>
                </Td>
                <Td>{shortDateTime(p.created_at)}</Td>
                <Td>
                  {p.id === assignedId ? (
                    <Badge tone="signal">{appName || t("this app")}</Badge>
                  ) : (
                    <span className="text-faint">—</span>
                  )}
                </Td>
              </tr>
            );
          })}
        </tbody>
      </Table>
    </div>
  );
}
