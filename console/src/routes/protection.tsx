import { useEffect, useState } from "react";
import { ShieldHalf, ListChecks, BellRing, PackageSearch, Check } from "lucide-react";
import { api } from "../lib/api";
import { useApplicationSettings, useInvalidator, useMutation } from "../lib/queries";
import { PageHeader, RequireApplication, Grid } from "../components/page";
import { Panel, QueryState, Field, TextInput, SelectInput, Button, Badge } from "../components/ui";
import { isPrivileged } from "../lib/session";
import { useT } from "../i18n";

type Json = Record<string, unknown>;
type TFn = (key: string, vars?: Record<string, string | number>) => string;

export function ProtectionPage() {
  const t = useT();
  return (
    <>
      <PageHeader
        eyebrow={t("Configuration")}
        title={t("Protection Config")}
        description={t("Per-application protection posture. These settings are scoped to this application — changing them does not affect other applications.")}
      />
      <RequireApplication>{(appId) => <ProtectionBody appId={appId} />}</RequireApplication>
    </>
  );
}

function ProtectionBody({ appId }: { appId: string }) {
  const t = useT();
  const settings = useApplicationSettings(appId);
  const invalidate = useInvalidator();
  const privileged = isPrivileged();

  const byKey = (key: string): Json => settings.data?.find((s) => s.key === key)?.value ?? {};

  const save = useMutation({
    mutationFn: (v: { key: string; value: Json }) => api.updateApplicationSetting(appId, v.key, v.value),
    onSuccess: () => invalidate("app-settings")
  });

  return (
    <QueryState isLoading={settings.isLoading} isError={settings.isError} error={settings.error}>
      <Grid className="lg:grid-cols-2">
        <HardeningCard t={t} value={byKey("protection.hardening")} disabled={!privileged} onSave={(value) => save.mutate({ key: "protection.hardening", value })} saving={save.isPending} />
        <AllowlistCard t={t} value={byKey("protection.allowlist")} disabled={!privileged} onSave={(value) => save.mutate({ key: "protection.allowlist", value })} saving={save.isPending} />
        <AlarmCard t={t} value={byKey("alerts.delivery")} disabled={!privileged} onSave={(value) => save.mutate({ key: "alerts.delivery", value })} saving={save.isPending} />
        <DependencyCard t={t} value={byKey("dependency.vulnerability_policy")} disabled={!privileged} onSave={(value) => save.mutate({ key: "dependency.vulnerability_policy", value })} saving={save.isPending} />
      </Grid>
      {!privileged && (
        <p className="mt-4 text-[12px] text-faint">{t("You have read-only access. Administrators and security engineers can edit protection configuration.")}</p>
      )}
    </QueryState>
  );
}

function CardShell({
  t,
  icon,
  eyebrow,
  title,
  children,
  onSave,
  saving,
  disabled,
  dirty
}: {
  t: TFn;
  icon: React.ReactNode;
  eyebrow: string;
  title: string;
  children: React.ReactNode;
  onSave: () => void;
  saving: boolean;
  disabled: boolean;
  dirty: boolean;
}) {
  return (
    <Panel
      eyebrow={
        <span className="flex items-center gap-1.5">
          {icon} {eyebrow}
        </span>
      }
      title={title}
      actions={
        <Button variant={dirty ? "primary" : "subtle"} size="sm" onClick={onSave} disabled={disabled || saving || !dirty}>
          {saving ? t("Saving…") : dirty ? <><Check className="h-3.5 w-3.5" /> {t("Save")}</> : t("Saved")}
        </Button>
      }
    >
      <div className="space-y-4">{children}</div>
    </Panel>
  );
}

function Toggle({ label, checked, onChange, disabled }: { label: string; checked: boolean; onChange: (v: boolean) => void; disabled: boolean }) {
  return (
    <label className="flex cursor-pointer items-center justify-between gap-4 rounded-md border border-hairline bg-obsidian px-3 py-2.5">
      <span className="text-[13px] text-muted">{label}</span>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={`relative h-5 w-9 shrink-0 rounded-full transition-colors ${checked ? "bg-signal" : "bg-hairline-bright"} disabled:opacity-40`}
      >
        <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-obsidian transition-all ${checked ? "left-[18px]" : "left-0.5"}`} />
      </button>
    </label>
  );
}

function HardeningCard({ t, value, onSave, saving, disabled }: { t: TFn; value: Json; onSave: (v: Json) => void; saving: boolean; disabled: boolean }) {
  const [mode, setMode] = useState((value.mode as string) ?? "monitor");
  const [reflection, setReflection] = useState((value.block_reflection_abuse as boolean) ?? true);
  const [process, setProcess] = useState((value.block_process_execution as boolean) ?? true);
  useEffect(() => {
    setMode((value.mode as string) ?? "monitor");
    setReflection((value.block_reflection_abuse as boolean) ?? true);
    setProcess((value.block_process_execution as boolean) ?? true);
  }, [value]);
  const dirty = mode !== ((value.mode as string) ?? "monitor") || reflection !== ((value.block_reflection_abuse as boolean) ?? true) || process !== ((value.block_process_execution as boolean) ?? true);

  return (
    <CardShell t={t} icon={<ShieldHalf className="h-3.5 w-3.5" />} eyebrow={t("Runtime")} title={t("Hardening")} disabled={disabled} saving={saving} dirty={dirty} onSave={() => onSave({ mode, block_reflection_abuse: reflection, block_process_execution: process })}>
      <Field label={t("Mode")}>
        <SelectInput value={mode} disabled={disabled} onChange={(e) => setMode(e.target.value)}>
          <option value="monitor">{t("Monitor — log only")}</option>
          <option value="block">{t("Block — enforce")}</option>
        </SelectInput>
      </Field>
      <Toggle label={t("Block reflection abuse")} checked={reflection} onChange={setReflection} disabled={disabled} />
      <Toggle label={t("Block process execution")} checked={process} onChange={setProcess} disabled={disabled} />
    </CardShell>
  );
}

function AllowlistCard({ t, value, onSave, saving, disabled }: { t: TFn; value: Json; onSave: (v: Json) => void; saving: boolean; disabled: boolean }) {
  const initialEntries = ((value.entries as string[]) ?? []).join("\n");
  const [enabled, setEnabled] = useState((value.enabled as boolean) ?? false);
  const [mode, setMode] = useState((value.mode as string) ?? "monitor");
  const [entries, setEntries] = useState(initialEntries);
  useEffect(() => {
    setEnabled((value.enabled as boolean) ?? false);
    setMode((value.mode as string) ?? "monitor");
    setEntries(((value.entries as string[]) ?? []).join("\n"));
  }, [value]);
  const parsed = entries.split("\n").map((s) => s.trim()).filter(Boolean);
  const dirty = enabled !== ((value.enabled as boolean) ?? false) || mode !== ((value.mode as string) ?? "monitor") || entries !== initialEntries;

  return (
    <CardShell t={t} icon={<ListChecks className="h-3.5 w-3.5" />} eyebrow={t("Bypass")} title={t("Allowlist")} disabled={disabled} saving={saving} dirty={dirty} onSave={() => onSave({ enabled, mode, entries: parsed })}>
      <Toggle label={t("Allowlist enabled")} checked={enabled} onChange={setEnabled} disabled={disabled} />
      <Field label={t("Mode")}>
        <SelectInput value={mode} disabled={disabled} onChange={(e) => setMode(e.target.value)}>
          <option value="monitor">{t("Monitor")}</option>
          <option value="block">{t("Block")}</option>
        </SelectInput>
      </Field>
      <Field label={t("Entries")} hint={t("{count} pattern(s) · one per line", { count: parsed.length })}>
        <textarea
          value={entries}
          disabled={disabled}
          onChange={(e) => setEntries(e.target.value)}
          rows={4}
          placeholder="/health&#10;/internal/*"
          className="readout w-full rounded-md border border-hairline bg-obsidian px-3 py-2 text-[12px] text-ink placeholder:text-faint focus:border-signal/50 focus:outline-hidden focus:ring-2 focus:ring-signal/30"
        />
      </Field>
    </CardShell>
  );
}

function AlarmCard({ t, value, onSave, saving, disabled }: { t: TFn; value: Json; onSave: (v: Json) => void; saving: boolean; disabled: boolean }) {
  const initial = String((value.interval_seconds as number) ?? 300);
  const [interval, setInterval] = useState(initial);
  useEffect(() => setInterval(String((value.interval_seconds as number) ?? 300)), [value]);
  const dirty = interval !== initial;
  return (
    <CardShell t={t} icon={<BellRing className="h-3.5 w-3.5" />} eyebrow={t("Notification")} title={t("Alerting")} disabled={disabled} saving={saving} dirty={dirty} onSave={() => onSave({ interval_seconds: Number(interval) || 300 })}>
      <Field label={t("Delivery interval (seconds)")} hint={t("Minimum gap between alert deliveries for this application")}>
        <TextInput type="number" min={0} value={interval} disabled={disabled} onChange={(e) => setInterval(e.target.value)} />
      </Field>
      <p className="text-[12px] text-faint">{t("Alert rules and delivery history are managed under Access & Audit.")}</p>
    </CardShell>
  );
}

function DependencyCard({ t, value, onSave, saving, disabled }: { t: TFn; value: Json; onSave: (v: Json) => void; saving: boolean; disabled: boolean }) {
  const [sev, setSev] = useState((value.fail_on_severity as string) ?? "critical");
  const [exploited, setExploited] = useState((value.block_known_exploited as boolean) ?? true);
  useEffect(() => {
    setSev((value.fail_on_severity as string) ?? "critical");
    setExploited((value.block_known_exploited as boolean) ?? true);
  }, [value]);
  const dirty = sev !== ((value.fail_on_severity as string) ?? "critical") || exploited !== ((value.block_known_exploited as boolean) ?? true);
  return (
    <CardShell t={t} icon={<PackageSearch className="h-3.5 w-3.5" />} eyebrow={t("Supply chain")} title={t("Dependency policy")} disabled={disabled} saving={saving} dirty={dirty} onSave={() => onSave({ fail_on_severity: sev, block_known_exploited: exploited })}>
      <Field label={t("Fail on severity")}>
        <SelectInput value={sev} disabled={disabled} onChange={(e) => setSev(e.target.value)}>
          <option value="critical">{t("Critical")}</option>
          <option value="high">{t("High and above")}</option>
          <option value="medium">{t("Medium and above")}</option>
        </SelectInput>
      </Field>
      <Toggle label={t("Block known-exploited (KEV)")} checked={exploited} onChange={setExploited} disabled={disabled} />
      <div>
        <Badge tone="info">{t("scoped to this application")}</Badge>
      </div>
    </CardShell>
  );
}
