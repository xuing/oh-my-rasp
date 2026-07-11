import { useEffect, useState } from "react";
import { BellRing, Info, Plus, ScrollText, UsersRound } from "lucide-react";
import { api, type AlertRule, type User, type UserRole } from "../lib/api";
import { useAppScope } from "../lib/app-context";
import { focusStoredSection, pendingFocusTarget } from "../lib/focus";
import { useAlertDeliveries, useAlertRules, useAuditLogs, useEdition, useInvalidator, useMutation, useUsers, useVersion } from "../lib/queries";
import { PageHeader, Grid } from "../components/page";
import { Badge, Button, Field, Mono, Panel, QueryState, Segmented, SelectInput, SeverityTag, Table, Td, TextInput, Th } from "../components/ui";
import { relativeTime, shortDateTime, titleCase } from "../lib/format";
import { useT } from "../i18n";

type Tab = "users" | "alerts" | "audit" | "system";

export function AccessPage() {
  const t = useT();
  const [tab, setTab] = useState<Tab>("users");
  const [focusPending, setFocusPending] = useState(false);

  useEffect(() => {
    const target = pendingFocusTarget();
    if (!target) return;
    if (target.startsWith("alert")) setTab("alerts");
    else if (target === "audit") setTab("audit");
    else if (target === "system" || target === "maintenance-cleanup") setTab("system");
    else setTab("users");
    setFocusPending(true);
  }, []);

  useEffect(() => {
    if (!focusPending) return;
    const id = window.setTimeout(() => {
      focusStoredSection();
      setFocusPending(false);
    });
    return () => window.clearTimeout(id);
  }, [focusPending, tab]);

  return (
    <>
      <PageHeader
        eyebrow={t("Administration")}
        title={t("Access & Audit")}
        description={t("Organization-level controls — operators and roles, alert routing, the operation audit trail, and system information.")}
      />
      <div className="mb-4">
        <Segmented
          value={tab}
          onChange={setTab}
          options={[
            { value: "users", label: t("Operators") },
            { value: "alerts", label: t("Alerts") },
            { value: "audit", label: t("Audit") },
            { value: "system", label: t("System") }
          ]}
        />
      </div>
      {tab === "users" && <Users />}
      {tab === "alerts" && <Alerts />}
      {tab === "audit" && <Audit />}
      {tab === "system" && <System />}
    </>
  );
}

function Users() {
  const t = useT();
  const users = useUsers();
  const invalidate = useInvalidator();
  const update = useMutation({
    mutationFn: (input: { user: User; disabled: boolean }) =>
      api.updateUser(input.user.id, {
        name: input.user.name,
        roles: input.user.roles.filter(isUserRole),
        disabled: input.disabled
      }),
    onSuccess: () => invalidate("users", "audit-logs")
  });
  return (
    <Grid className="lg:grid-cols-[0.8fr_1.2fr]" data-section="users" tabIndex={-1}>
      <CreateUserForm />
      <Panel title={t("Operators")} eyebrow={t("Roles")} flush>
        <QueryState isLoading={users.isLoading} isError={users.isError} error={users.error} isEmpty={(users.data ?? []).length === 0} emptyTitle={t("No operators")} emptyIcon={<UsersRound className="h-5 w-5" />}>
          <Table>
            <thead>
              <tr>
                <Th>{t("Operator")}</Th>
                <Th>{t("Roles")}</Th>
                <Th>{t("Status")}</Th>
                <Th>{t("Created")}</Th>
                <Th>{t("Actions")}</Th>
              </tr>
            </thead>
            <tbody>
              {(users.data ?? []).map((u) => (
                <tr key={u.id}>
                  <Td>
                    <div className="text-[13px] text-ink">{u.name}</div>
                    <Mono className="text-[11px] text-faint">{u.email}</Mono>
                  </Td>
                  <Td>
                    <div className="flex flex-wrap gap-1">
                      {u.roles.map((r) => (
                        <Badge key={r} tone={r === "admin" ? "signal" : "neutral"}>
                          {r.replace("_", " ")}
                        </Badge>
                      ))}
                    </div>
                  </Td>
                  <Td>{u.disabled_at ? <Badge tone="danger">{t("disabled")}</Badge> : <Badge tone="signal">{t("active")}</Badge>}</Td>
                  <Td>{shortDateTime(u.created_at)}</Td>
                  <Td>
                    <Button size="sm" variant="subtle" disabled={update.isPending} onClick={() => update.mutate({ user: u, disabled: !u.disabled_at })}>
                      {u.disabled_at ? t("Enable") : t("Disable")}
                    </Button>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </QueryState>
      </Panel>
    </Grid>
  );
}

function CreateUserForm() {
  const t = useT();
  const invalidate = useInvalidator();
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<UserRole>("viewer");
  const create = useMutation({
    mutationFn: () => api.createUser({ email: email.trim(), name: name.trim(), password, roles: [role] }),
    onSuccess: () => {
      setEmail("");
      setName("");
      setPassword("");
      setRole("viewer");
      invalidate("users", "audit-logs");
    }
  });
  return (
    <Panel title={t("Create operator")} eyebrow={t("Access")}>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (email.trim() && name.trim() && password) create.mutate();
        }}
      >
        <Field label={t("Email")}>
          <TextInput type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </Field>
        <Field label={t("Name")}>
          <TextInput value={name} onChange={(e) => setName(e.target.value)} required />
        </Field>
        <Field label={t("Password")}>
          <TextInput type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </Field>
        <Field label={t("Role")}>
          <SelectInput value={role} onChange={(e) => setRole(e.target.value as UserRole)}>
            <option value="viewer">{t("Viewer")}</option>
            <option value="security_engineer">{t("Security engineer")}</option>
            <option value="admin">{t("Admin")}</option>
          </SelectInput>
        </Field>
        <Button type="submit" variant="primary" disabled={create.isPending || !email.trim() || !name.trim() || !password}>
          <Plus className="h-3.5 w-3.5" /> {t("Create")}
        </Button>
      </form>
    </Panel>
  );
}

function Alerts() {
  const t = useT();
  const rules = useAlertRules();
  const deliveries = useAlertDeliveries();
  const [selectedRule, setSelectedRule] = useState<AlertRule | null>(null);
  return (
    <div className="space-y-4" data-section="alert-rules" tabIndex={-1}>
      <AlertRuleForm selectedRule={selectedRule} onClear={() => setSelectedRule(null)} />
      <Grid className="lg:grid-cols-2">
        <Panel eyebrow={t("Routing")} title={t("Alert rules")} flush>
          <QueryState isLoading={rules.isLoading} isError={rules.isError} error={rules.error} isEmpty={(rules.data ?? []).length === 0} emptyTitle={t("No alert rules")} emptyIcon={<BellRing className="h-5 w-5" />}>
            <Table>
              <thead>
                <tr>
                  <Th>{t("Rule")}</Th>
                  <Th>{t("On")}</Th>
                  <Th>{t("Target")}</Th>
                  <Th>{t("State")}</Th>
                </tr>
              </thead>
              <tbody>
                {(rules.data ?? []).map((r) => (
                  <tr
                    key={r.id}
                    className="interactive cursor-pointer"
                    role="button"
                    tabIndex={0}
                    onClick={() => setSelectedRule(r)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        setSelectedRule(r);
                      }
                    }}
                  >
                    <Td>
                      <div className="text-[13px] text-ink">{r.name}</div>
                      <SeverityTag value={r.severity} />
                    </Td>
                    <Td>
                      <Badge tone="neutral">{r.event_type}</Badge>
                    </Td>
                    <Td>
                      <Mono className="text-[11px]">{r.target}</Mono>
                    </Td>
                    <Td>{r.enabled ? <Badge tone="signal">{t("on")}</Badge> : <Badge tone="neutral">{t("off")}</Badge>}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </QueryState>
        </Panel>

        <Panel eyebrow={t("Delivery history")} title={t("Recent deliveries")} flush>
          <QueryState isLoading={deliveries.isLoading} isError={deliveries.isError} error={deliveries.error} isEmpty={(deliveries.data ?? []).length === 0} emptyTitle={t("No deliveries yet")}>
            <Table>
              <thead>
                <tr>
                  <Th>{t("Rule")}</Th>
                  <Th>{t("Status")}</Th>
                  <Th>{t("Tries")}</Th>
                  <Th>{t("When")}</Th>
                </tr>
              </thead>
              <tbody>
                {(deliveries.data ?? []).slice(0, 30).map((d) => {
                  const tone = d.status === "delivered" ? "signal" : d.status === "failed" ? "danger" : "warn";
                  return (
                    <tr key={d.id} title={d.last_error}>
                      <Td>
                        <div className="text-[13px] text-ink">{d.alert_rule_name}</div>
                        <Mono className="text-[11px] text-faint">{d.target}</Mono>
                      </Td>
                      <Td>
                        <Badge tone={tone}>{d.status}</Badge>
                      </Td>
                      <Td>
                        <Mono>{d.attempts}</Mono>
                      </Td>
                      <Td>{relativeTime(d.delivered_at ?? d.created_at)}</Td>
                    </tr>
                  );
                })}
              </tbody>
            </Table>
          </QueryState>
        </Panel>
      </Grid>
    </div>
  );
}

function AlertRuleForm({ selectedRule, onClear }: { selectedRule: AlertRule | null; onClear: () => void }) {
  const t = useT();
  const scope = useAppScope();
  const invalidate = useInvalidator();
  const [name, setName] = useState("");
  const [severity, setSeverity] = useState("critical");
  const [eventType, setEventType] = useState("attack");
  const [target, setTarget] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [condition, setCondition] = useState("");

  useEffect(() => {
    setName(selectedRule?.name ?? "");
    setSeverity(selectedRule?.severity ?? "critical");
    setEventType(selectedRule?.event_type ?? "attack");
    setTarget(selectedRule?.target ?? "");
    setEnabled(selectedRule?.enabled ?? true);
    setCondition(selectedRule?.condition ?? "");
  }, [selectedRule]);

  const save = useMutation({
    mutationFn: () => {
      const input = {
        application_id: scope.applicationId ?? undefined,
        name: name.trim(),
        enabled,
        event_type: eventType,
        severity,
        condition: condition.trim() || undefined,
        target: target.trim()
      };
      return selectedRule ? api.updateAlertRule(selectedRule.id, input) : api.createAlertRule(input);
    },
    onSuccess: () => {
      invalidate("alert-rules", "audit-logs");
      onClear();
    }
  });

  return (
    <Panel title={selectedRule ? t("Edit alert rule") : t("Create alert rule")} eyebrow={t("Routing")}>
      <form
        className="grid gap-3 md:grid-cols-[1fr_0.8fr_0.8fr_1fr_auto]"
        onSubmit={(e) => {
          e.preventDefault();
          if (name.trim() && target.trim()) save.mutate();
        }}
      >
        <Field label={t("Name")}>
          <TextInput value={name} onChange={(e) => setName(e.target.value)} required />
        </Field>
        <Field label={t("Event type")}>
          <SelectInput value={eventType} onChange={(e) => setEventType(e.target.value)}>
            <option value="attack">{t("Attacks")}</option>
            <option value="error">{t("Errors")}</option>
            <option value="crash">{t("Crashes")}</option>
          </SelectInput>
        </Field>
        <Field label={t("Severity")}>
          <SelectInput value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="critical">{t("Critical")}</option>
            <option value="high">{t("High")}</option>
            <option value="medium">{t("Medium")}</option>
            <option value="low">{t("Low")}</option>
          </SelectInput>
        </Field>
        <Field label={t("Target")}>
          <TextInput value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://hooks.example" required />
        </Field>
        <div className="flex items-end gap-2">
          <label className="flex h-9.5 items-center gap-2 text-[12px] text-muted">
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
            {t("Enabled")}
          </label>
          <Button type="submit" variant="primary" disabled={save.isPending || !name.trim() || !target.trim()}>
            {selectedRule ? t("Update") : t("Create")}
          </Button>
        </div>
        <div className="md:col-span-5">
          <Field label={t("Condition")}>
            <TextInput value={condition} onChange={(e) => setCondition(e.target.value)} placeholder="severity == critical" />
          </Field>
        </div>
      </form>
    </Panel>
  );
}

function Audit() {
  const t = useT();
  const logs = useAuditLogs();
  return (
    <Panel flush data-section="audit" tabIndex={-1}>
      <QueryState isLoading={logs.isLoading} isError={logs.isError} error={logs.error} isEmpty={(logs.data ?? []).length === 0} emptyTitle={t("No audit entries")} emptyIcon={<ScrollText className="h-5 w-5" />}>
        <Table>
          <thead>
            <tr>
              <Th>{t("Actor")}</Th>
              <Th>{t("Action")}</Th>
              <Th>{t("Resource")}</Th>
              <Th>{t("When")}</Th>
            </tr>
          </thead>
          <tbody>
            {(logs.data ?? []).slice(0, 100).map((l) => (
              <tr key={l.id}>
                <Td>
                  <Mono>{l.actor_id}</Mono>
                </Td>
                <Td>
                  <Badge tone="info">{l.action}</Badge>
                </Td>
                <Td>
                  <Mono className="text-[11px]" title={JSON.stringify(l.details ?? {})}>
                    {l.resource}
                  </Mono>
                </Td>
                <Td>{relativeTime(l.created_at)}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </QueryState>
    </Panel>
  );
}

function System() {
  const t = useT();
  const version = useVersion();
  const edition = useEdition();
  const v = version.data;
  const e = edition.data;
  return (
    <Grid className="lg:grid-cols-2">
      <Panel eyebrow={t("Build")} title={t("Version")} actions={<Info className="h-4 w-4 text-faint" />} data-section="system" tabIndex={-1}>
        <dl className="divide-y divide-hairline/60 overflow-hidden rounded-md border border-hairline">
          {[
            [t("Component"), v?.component],
            [t("Version"), v?.version],
            [t("Commit"), v?.commit || "—"],
            [t("Built"), v?.build_time || "—"],
            [t("Runtime"), v?.go_version || "—"]
          ].map(([k, val]) => (
            <div key={k} className="flex items-center justify-between px-3 py-2">
              <dt className="eyebrow">{k}</dt>
              <dd className="readout text-[12px] text-ink">{val ?? "—"}</dd>
            </div>
          ))}
        </dl>
      </Panel>
      <Panel eyebrow={t("License")} title={t("Edition")}>
        <div className="space-y-3">
          <div className="display text-lg font-semibold text-ink">{e?.display_name || t("OSS Edition")}</div>
          <div className="flex flex-wrap gap-1.5">
            {(e?.features ?? []).map((f) => (
              <Badge key={f} tone="neutral">
                {titleCase(f)}
              </Badge>
            ))}
            {(e?.features ?? []).length === 0 && <span className="text-[12px] text-faint">{t("Single-organization self-hosted control plane.")}</span>}
          </div>
        </div>
      </Panel>
      <MaintenanceCleanup />
    </Grid>
  );
}

function MaintenanceCleanup() {
  const t = useT();
  const scope = useAppScope();
  const [before, setBefore] = useState(() => new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10));
  const [confirmation, setConfirmation] = useState("");
  const [includeEvents, setIncludeEvents] = useState(true);
  const [includeDependencies, setIncludeDependencies] = useState(true);
  const [includeBaseline, setIncludeBaseline] = useState(true);
  const [includeAlerts, setIncludeAlerts] = useState(true);
  const [message, setMessage] = useState("");
  const cleanup = useMutation({
    mutationFn: (dryRun: boolean) =>
      api.cleanupMaintenanceData({
        before,
        application_id: scope.applicationId ?? undefined,
        dry_run: dryRun,
        include_events: includeEvents,
        include_dependencies: includeDependencies,
        include_baseline_findings: includeBaseline,
        include_alert_deliveries: includeAlerts,
        confirmation: dryRun ? undefined : confirmation
      }),
    onSuccess: (report) => {
      const count = Object.values(report.counts ?? {}).reduce((sum, value) => sum + value, 0);
      setMessage(report.dry_run ? t("Cleanup preview: {count} records.", { count }) : t("Cleanup applied: {count} records.", { count }));
    }
  });
  return (
    <Panel title={t("Maintenance cleanup")} eyebrow={t("Retention")} data-section="maintenance-cleanup" tabIndex={-1}>
      <div className="space-y-3">
        <Field label={t("Before date")}>
          <TextInput type="date" value={before} onChange={(e) => setBefore(e.target.value)} />
        </Field>
        <div className="grid gap-2 sm:grid-cols-2">
          {[
            [t("Events"), includeEvents, setIncludeEvents],
            [t("Dependencies"), includeDependencies, setIncludeDependencies],
            [t("Baseline"), includeBaseline, setIncludeBaseline],
            [t("Alert deliveries"), includeAlerts, setIncludeAlerts]
          ].map(([label, checked, setChecked]) => (
            <label key={String(label)} className="flex items-center gap-2 rounded-md border border-hairline bg-obsidian px-3 py-2 text-[12px] text-muted">
              <input type="checkbox" checked={Boolean(checked)} onChange={(e) => (setChecked as (v: boolean) => void)(e.target.checked)} />
              {label as string}
            </label>
          ))}
        </div>
        <Field label={t("Confirmation")} hint={t("Type CLEAR_OPERATIONAL_DATA before applying cleanup.")}>
          <TextInput value={confirmation} onChange={(e) => setConfirmation(e.target.value)} placeholder="CLEAR_OPERATIONAL_DATA" />
        </Field>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="ghost" onClick={() => cleanup.mutate(true)} disabled={cleanup.isPending || !before}>
            {t("Preview")}
          </Button>
          <Button variant="danger" onClick={() => cleanup.mutate(false)} disabled={cleanup.isPending || confirmation !== "CLEAR_OPERATIONAL_DATA" || !before}>
            {t("Apply cleanup")}
          </Button>
          {message && <span className="text-[12px] text-signal">{message}</span>}
        </div>
      </div>
    </Panel>
  );
}

function isUserRole(role: string): role is UserRole {
  return role === "admin" || role === "security_engineer" || role === "viewer";
}
