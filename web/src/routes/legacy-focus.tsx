import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Badge } from "../components/ui/badge";
import { Card, CardContent } from "../components/ui/card";
import { AccessPage, AgentsPage, EventsPage, PoliciesPage } from "./pages";

export function MaintainHostsPage() {
  return <FocusedRoute focus="maintainHosts" page={<AgentsPage />} />;
}

export function MaintainClearDataPage() {
  return <FocusedRoute focus="maintainClearData" page={<AccessPage />} />;
}

export function MaintainWhitelistPage() {
  return <FocusedRoute focus="maintainWhitelist" page={<AccessPage />} />;
}

export function MaintainGeneralPage() {
  return <FocusedRoute focus="maintainGeneral" page={<AccessPage />} />;
}

export function MaintainUpgradePage() {
  return <FocusedRoute focus="maintainUpgrade" page={<AgentsPage />} />;
}

export function AlgorithmPage() {
  return <FocusedRoute focus="algorithm" page={<PoliciesPage />} />;
}

export function AlgorithmHardeningPage() {
  return <FocusedRoute focus="algorithmHardening" page={<AccessPage />} />;
}

export function AlgorithmAlarmPage() {
  return <FocusedRoute focus="algorithmAlarm" page={<AccessPage />} />;
}

export function LogExceptionsPage() {
  return <FocusedRoute focus="logExceptions" page={<EventsPage />} />;
}

export function LogCrashPage() {
  return <FocusedRoute focus="logCrash" page={<EventsPage />} />;
}

export function LogAuditPage() {
  return <FocusedRoute focus="logAudit" page={<AccessPage />} />;
}

export function PlatformPage() {
  return <FocusedRoute focus="platform" page={<AccessPage />} />;
}

export function PlatformUserPage() {
  return <FocusedRoute focus="platformUser" page={<AccessPage />} />;
}

export function SettingsPanelPage() {
  return <FocusedRoute focus="settingsPanel" page={<AccessPage />} />;
}

export function SettingsAlarmPage() {
  return <FocusedRoute focus="settingsAlarm" page={<AccessPage />} />;
}

export function SettingsSystemInfoPage() {
  return <FocusedRoute focus="settingsSystemInfo" page={<AccessPage />} />;
}

export function SettingsPoolVersionPage() {
  return <FocusedRoute focus="settingsPoolVersion" page={<AgentsPage />} />;
}

export function SettingsVersionPage() {
  return <FocusedRoute focus="settingsVersion" page={<AgentsPage />} />;
}

type FocusKey = keyof typeof focusCopy;

const focusCopy = {
  maintainHosts: ["Host Maintenance", "Agent inventory, ignore state, aliases, and heartbeat operations."],
  maintainClearData: ["Maintenance Cleanup", "Operational data retention, dry-run cleanup, and confirmed purge controls."],
  maintainWhitelist: ["Protection Allowlist", "Hardening settings and exception-oriented policy controls."],
  maintainGeneral: ["General Protection Settings", "System settings, edition status, and control-plane version information."],
  maintainUpgrade: ["Agent Upgrade", "Artifact catalog, daemon download metadata, and version drift checks."],
  algorithm: ["Algorithm Configuration", "Policy versions, rule validation, rollout, rollback, and default rule restoration."],
  algorithmHardening: ["Hardening Configuration", "Runtime hardening settings and system-level protection controls."],
  algorithmAlarm: ["Alarm Configuration", "Alert rules, delivery targets, delivery history, and alert status."],
  logExceptions: ["Error Events", "Agent-produced error events and exception attributes."],
  logCrash: ["Crash Events", "Agent-produced crash events and uncaught exception context."],
  logAudit: ["Audit Log", "Authenticated control-plane audit trail and operational write history."],
  platform: ["Platform Administration", "Users, RBAC, system settings, edition status, and audit trail."],
  platformUser: ["User Administration", "User lifecycle, role assignment, disabling, and filtered user search."],
  settingsPanel: ["Panel Settings", "Console settings, system version, edition state, and operator-facing configuration."],
  settingsAlarm: ["Alarm Settings", "Alert rules, alert deliveries, target status, and notification routing."],
  settingsSystemInfo: ["System Information", "Control-plane version, build metadata, and edition state."],
  settingsPoolVersion: ["Agent Package Versions", "Managed artifact catalog and daemon artifact lookup."],
  settingsVersion: ["Agent Version Status", "Agent inventory versions, drift checks, and upgrade state."]
} as const;

function FocusedRoute({ focus, page }: { focus: FocusKey; page: ReactNode }) {
  const { t } = useTranslation();
  const [label, detail] = focusCopy[focus];
  return (
    <div className="space-y-5" data-route-focus={label.toLowerCase().replaceAll(" ", "-")}>
      <Card>
        <CardContent>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h1 className="text-xl font-semibold tracking-normal text-slate-950">{t(`legacy.${focus}.label`, label)}</h1>
              <p className="mt-2 text-sm leading-6 text-slate-600">{t(`legacy.${focus}.detail`, detail)}</p>
            </div>
            <Badge tone="blue">{t("legacy.focusedRoute", "Focused legacy route")}</Badge>
          </div>
        </CardContent>
      </Card>
      {page}
    </div>
  );
}
