import { Link, Outlet, useNavigate } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AppWindow,
  ChartNoAxesColumnIncreasing,
  Download,
  Gauge,
  Globe2,
  KeyRound,
  LayoutDashboard,
  Link2,
  Link2Off,
  RadioTower,
  RefreshCcw,
  ScrollText,
  ShieldCheck,
  Trash2,
  Upload
} from "lucide-react";
import { type FormEvent, type ReactNode, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Badge } from "../components/ui/badge";
import type { BadgeTone } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Table } from "../components/ui/table";
import { eventPipelines, navigationSections, policyLifecycle } from "../domain/control-plane";
import appI18n, { setAppLanguage, supportedLanguages, type SupportedLanguage } from "../i18n";
import { UiText, UiValue, notice, translateNotice, translateUiCopy, useUiCopy } from "../i18n/copy";
import {
  bindDaemonWorkload,
  cleanupMaintenanceData,
  createAlertRule,
  createApplication,
  createEnvironment,
  createPolicy,
  createPolicyVersion,
  createUser,
  currentSession,
  deleteApplication,
  downloadAgentArtifact,
  exportApplications,
  exportDependencies,
  getAgentArtifactInfo,
  getDaemonApplicationCredential,
  getDaemonToken,
  heartbeatAgent,
  loginWithPassword,
  moveEventsToRecycleBin,
  purgeEventsFromRecycleBin,
  type Agent,
  type AgentArtifactCatalog,
  type AgentArtifactInfo,
  type AlertRule,
  type Application,
  type BaselineFindingQuery,
  type DaemonWorkload,
  type DependencyQuery,
  type EditionStatus,
  type PolicyRolloutScope,
  type PolicySet,
  type RuleInput,
  type SecurityEvent,
  type SecurityEventQuery,
  type SystemSetting,
  type User,
  type UserRole,
  pullAgentPolicy,
  registerAgent,
  resetDaemonToken,
  restoreEventsFromRecycleBin,
  rotateApplicationSecret,
  rollbackPolicy,
  rolloutPolicy,
  saveSession,
  testRule,
  updateAlertRule,
  uploadAgentArtifact,
  updatePolicyVersionRules,
  unbindDaemonWorkload,
  updateUser,
  updateSystemSetting,
  useAgents,
  useAgentArtifacts,
  useApplications,
  useDaemonWorkloads,
  useAlertDeliveries,
  useAlertRules,
  useAttackEvents,
  useAuditLogs,
  useBaselineFindings,
  useDependencies,
  useDependencySummary,
  useDeletedSecurityEvents,
  useEditionStatus,
  useObservability,
  useOverview,
  usePolicies,
  useSecurityEvents,
  useSystemSettings,
  useUsers,
  validateRules
} from "../lib/api";
import { cn } from "../lib/cn";

const iconMap = {
  layout: LayoutDashboard,
  app: AppWindow,
  agent: RadioTower,
  policy: ShieldCheck,
  event: ScrollText,
  chart: ChartNoAxesColumnIncreasing,
  shield: Gauge
};

const navigationKeyByPath = {
  "/": "overview",
  "/applications": "applications",
  "/agents": "agents",
  "/policies": "policies",
  "/events": "events",
  "/observability": "observability",
  "/access": "access"
} as const;

const lifecycleKeys = ["draft", "validate", "test", "version", "canary", "promote", "rollback"] as const;

export function RootLayout() {
  const { i18n, t } = useTranslation();
  const { copy } = useUiCopy();
  const [session, setSession] = useState(currentSession);

  useEffect(() => {
    const syncSession = () => setSession(currentSession());
    window.addEventListener("storage", syncSession);
    window.addEventListener("ohmyrasp.session.changed", syncSession);
    return () => {
      window.removeEventListener("storage", syncSession);
      window.removeEventListener("ohmyrasp.session.changed", syncSession);
    };
  }, []);

  return (
    <div className="min-h-screen bg-slate-100">
      <aside className="fixed inset-y-0 left-0 hidden w-72 border-r border-slate-200 bg-slate-950 text-white lg:block">
        <div className="border-b border-slate-800 px-5 py-5">
          <div className="text-lg font-semibold tracking-normal">{t("shell.product")}</div>
          <div className="mt-1 text-xs text-slate-400">{t("shell.subtitle")}</div>
        </div>
        <nav className="space-y-1 p-3">
          {navigationSections.map(section => {
            const Icon = iconMap[section.icon];
            const navigationKey = navigationKeyByPath[section.path];
            return (
              <Link
                key={section.path}
                to={section.path}
                className="flex items-center gap-3 rounded-md px-3 py-2 text-sm text-slate-300 hover:bg-slate-900 hover:text-white"
                activeProps={{ className: "bg-slate-800 text-white" }}
              >
                <Icon className="h-4 w-4" />
                <span>{t(`navigation.${navigationKey}.label`, section.label)}</span>
              </Link>
            );
          })}
        </nav>
      </aside>
      <main className="lg:pl-72">
        <header className="border-b border-slate-200 bg-white px-4 py-4 lg:px-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="text-xl font-semibold tracking-normal text-slate-950">{t("shell.title")}</div>
              <div className="text-sm text-slate-500">{t("shell.summary")}</div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <LanguageSwitcher language={i18n.resolvedLanguage ?? i18n.language} />
              <Link
                to="/policies"
                className="inline-flex h-9 items-center justify-center rounded-md border border-slate-200 bg-white px-3 text-sm font-medium text-slate-900 transition-colors hover:bg-slate-50"
              >
                {t("shell.validateRule")}
              </Link>
              <Link
                to="/agents"
                className="inline-flex h-9 items-center justify-center gap-2 rounded-md border border-slate-900 bg-slate-900 px-3 text-sm font-medium text-white transition-colors hover:bg-slate-800"
              >
                {t("shell.registerAgent")}
              </Link>
              {session.token ? (
                <div className="inline-flex h-9 items-center rounded-md border border-slate-200 bg-white px-3 text-sm font-medium text-slate-700">
                  {session.userEmail || session.userName || t("shell.signedIn")}
                </div>
              ) : (
                <Link
                  to="/login"
                  className="inline-flex h-9 items-center justify-center rounded-md border border-slate-200 bg-white px-3 text-sm font-medium text-slate-900 hover:bg-slate-50"
                >
                  {t("shell.signIn")}
                </Link>
              )}
            </div>
          </div>
        </header>
        <nav aria-label={copy("Primary mobile")} className="border-b border-slate-200 bg-white px-4 py-2 lg:hidden">
          <div className="flex gap-2 overflow-x-auto">
            {navigationSections.map(section => {
              const navigationKey = navigationKeyByPath[section.path];
              return (
                <Link
                  key={section.path}
                  to={section.path}
                  className="inline-flex h-9 shrink-0 items-center rounded-md px-3 text-sm font-medium text-slate-700 hover:bg-slate-100 hover:text-slate-950"
                  activeProps={{ className: "bg-slate-900 text-white hover:bg-slate-900 hover:text-white" }}
                >
                  {t(`navigation.${navigationKey}.label`, section.label)}
                </Link>
              );
            })}
          </div>
        </nav>
        <div className="p-4 lg:p-6">
          <Outlet />
        </div>
      </main>
    </div>
  );
}

function LanguageSwitcher({ language }: { language: string }) {
  const { t } = useTranslation();
  const selectedLanguage = supportedLanguages.some(option => option.code === language) ? (language as SupportedLanguage) : "en";

  return (
    <label className="inline-flex h-9 items-center gap-2 rounded-md border border-slate-200 bg-white px-2 text-sm font-medium text-slate-700">
      <Globe2 className="h-4 w-4 text-slate-500" />
      <span className="sr-only">{t("language.label")}</span>
      <select
        aria-label={t("language.label")}
        className="h-7 bg-transparent text-sm outline-none"
        value={selectedLanguage}
        onChange={event => void setAppLanguage(event.target.value as SupportedLanguage)}
      >
        {supportedLanguages.map(option => (
          <option key={option.code} value={option.code}>
            {option.nativeLabel}
          </option>
        ))}
      </select>
    </label>
  );
}

export function LoginPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setIsSubmitting(true);
    try {
      const result = await loginWithPassword(email, password);
      saveSession(result);
      await navigate({ to: "/" });
    } catch {
      setError(t("login.error"));
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div className="mx-auto flex min-h-[calc(100vh-9rem)] max-w-md items-center">
      <Card className="w-full">
        <CardHeader>
          <CardTitle>{t("login.title")}</CardTitle>
        </CardHeader>
        <CardContent>
          <form className="space-y-4" onSubmit={handleSubmit}>
            <div className="space-y-2">
              <label className="text-sm font-medium text-slate-700" htmlFor="email">
                {t("login.email")}
              </label>
              <input
                id="email"
                name="email"
                autoComplete="username"
                type="email"
                value={email}
                onChange={event => setEmail(event.target.value)}
                className="h-10 w-full rounded-md border border-slate-300 bg-white px-3 text-sm text-slate-950 outline-none focus:border-slate-900"
                required
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium text-slate-700" htmlFor="password">
                {t("login.password")}
              </label>
              <input
                id="password"
                name="password"
                autoComplete="current-password"
                type="password"
                value={password}
                onChange={event => setPassword(event.target.value)}
                className="h-10 w-full rounded-md border border-slate-300 bg-white px-3 text-sm text-slate-950 outline-none focus:border-slate-900"
                required
              />
            </div>
            {error ? (
              <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700" role="alert">
                {error}
              </div>
            ) : null}
            <Button className="w-full" disabled={isSubmitting} type="submit">
              {isSubmitting ? t("login.submitting") : t("login.submit")}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

export function NoAccessPage() {
  return (
    <EmptyStatePage
      title={<UiText k="No access" />}
      summary={<UiText k="Your account does not have permission to open this page." />}
      action={<UiText k="Back to overview" />}
      to="/"
    />
  );
}

export function NotFoundPage() {
  const session = currentSession();
  return (
    <EmptyStatePage
      title={<UiText k="Page not found" />}
      summary={<UiText k="The page you requested does not exist." />}
      action={<UiText k={session.token ? "Back to overview" : "Go to login"} />}
      to={session.token ? "/" : "/login"}
    />
  );
}

function EmptyStatePage({ action, summary, title, to }: { action: ReactNode; summary: ReactNode; title: ReactNode; to: string }) {
  return (
    <div className="mx-auto flex min-h-[calc(100vh-9rem)] max-w-lg items-center">
      <Card className="w-full">
        <CardContent className="space-y-4">
          <div>
            <h1 className="text-xl font-semibold tracking-normal text-slate-950">{title}</h1>
            <p className="mt-2 text-sm leading-6 text-slate-600">{summary}</p>
          </div>
          <Link
            to={to}
            className="inline-flex h-9 items-center justify-center rounded-md border border-slate-900 bg-slate-900 px-3 text-sm font-medium text-white transition-colors hover:bg-slate-800"
          >
            {action}
          </Link>
        </CardContent>
      </Card>
    </div>
  );
}

export function OverviewPage() {
  const { t } = useTranslation();
  const overviewQuery = useOverview();
  const overview = overviewQuery.data ?? {
    application_count: 0,
    agent_count: 0,
    online_agents: 0,
    event_count: 0,
    events_by_type: {},
    events_by_severity: {},
    attack_trend: [],
    attacks_by_hook: {},
    attacks_by_algorithm: {},
    attacks_by_user_agent: {},
    crash_count: 0
  };
  const onlineRate = Math.round((overview.online_agents / Math.max(overview.agent_count, 1)) * 100);
  const attackCount = overview.events_by_type.attack ?? 0;
  const criticalCount = overview.events_by_severity.critical ?? 0;
  return (
    <div className="space-y-5">
      <QueryStateNotice
        isLoading={overviewQuery.isLoading}
        isError={overviewQuery.isError}
        loading={<UiText k="Loading overview metrics." />}
        error={<UiText k="Overview metrics are unavailable." />}
      />
      <section className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Metric label={t("overview.metrics.applications")} value={overview.application_count} detail={t("overview.metrics.applicationsDetail")} />
        <Metric label={t("overview.metrics.onlineAgents")} value={`${overview.online_agents}/${overview.agent_count}`} detail={t("overview.metrics.onlineAgentsDetail", { rate: onlineRate })} />
        <Metric label={t("overview.metrics.events")} value={overview.event_count} detail={t("overview.metrics.eventsDetail")} />
        <Metric label={t("overview.metrics.attacks")} value={attackCount} detail={t("overview.metrics.attacksDetail")} />
        <Metric label={t("overview.metrics.crashes")} value={overview.crash_count} detail={t("overview.metrics.crashesDetail")} />
        <Metric label={t("overview.metrics.critical")} value={criticalCount} detail={t("overview.metrics.criticalDetail")} />
      </section>
      <section className="grid gap-5 xl:grid-cols-[1.2fr_.8fr]">
        <AttackTrendPanel points={overview.attack_trend} />
        <DashboardBreakdown
          title={t("overview.eventDistribution")}
          groups={[
            { label: t("overview.eventTypes"), entries: topEntries(overview.events_by_type) },
            { label: t("overview.severities"), entries: topEntries(overview.events_by_severity) }
          ]}
        />
      </section>
      <section className="grid gap-5 xl:grid-cols-3">
        <DashboardBreakdown
          title={t("overview.attackHooks")}
          groups={[{ label: t("overview.topHooks"), entries: topEntries(overview.attacks_by_hook) }]}
        />
        <DashboardBreakdown
          title={t("overview.vulnerabilitySignals")}
          groups={[{ label: t("overview.topAlgorithms"), entries: topEntries(overview.attacks_by_algorithm) }]}
        />
        <DashboardBreakdown
          title={t("overview.userAgents")}
          groups={[{ label: t("overview.topUserAgents"), entries: topEntries(overview.attacks_by_user_agent) }]}
        />
      </section>
      <section className="grid gap-5 xl:grid-cols-[1.15fr_.85fr]">
        <Card>
          <CardHeader>
            <CardTitle>{t("overview.controlDomains")}</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-3 md:grid-cols-2">
            {navigationSections.slice(1).map(section => {
              const navigationKey = navigationKeyByPath[section.path];
              return (
                <div key={section.path} className="rounded-md border border-slate-200 p-3">
                  <div className="font-medium text-slate-950">{t(`navigation.${navigationKey}.label`, section.label)}</div>
                  <p className="mt-1 text-sm leading-6 text-slate-600">{t(`navigation.${navigationKey}.description`, section.description)}</p>
                </div>
              );
            })}
          </CardContent>
        </Card>
        <PolicyLifecycle />
      </section>
    </div>
  );
}

export function ApplicationsPage() {
  const { t } = useTranslation();
  const applicationsQuery = useApplications();
  const applications = applicationsQuery.data?.items ?? [];
  const environmentCount = applications.reduce((count, app) => count + app.environment_ids.length, 0);

  return (
    <SectionPage
      title={t("pages.applications.title")}
      summary={t("pages.applications.summary")}
    >
      <QueryStateNotice
        isLoading={applicationsQuery.isLoading}
        isError={applicationsQuery.isError}
        loading={<UiText k="Loading applications." />}
        error={<UiText k="Applications are unavailable." />}
      />
      <div className="grid gap-3 md:grid-cols-3">
        <Metric label={<UiText k="Applications" />} value={applications.length} detail={<UiText k="managed services" />} />
        <Metric label={<UiText k="Environments" />} value={environmentCount} detail={<UiText k="deployment scopes" />} />
        <Metric label={<UiText k="Average Scope" />} value={applications.length > 0 ? (environmentCount / applications.length).toFixed(1) : "0.0"} detail={<UiText k="environments per app" />} />
      </div>
      <ApplicationsWritePanel applications={applications} />
      <Table>
        <thead>
          <tr className="bg-slate-50">
            <th className="p-3 text-left"><UiText k="Application" /></th>
            <th className="p-3 text-left"><UiText k="Environments" /></th>
            <th className="p-3 text-left"><UiText k="Description" /></th>
            <th className="p-3 text-left"><UiText k="Created" /></th>
          </tr>
        </thead>
        <tbody>
          {applications.length > 0 ? (
            applications.map(app => (
              <tr key={app.id} className="border-t border-slate-200">
                <td className="p-3 font-medium">{app.name}</td>
                <td className="p-3 text-slate-600">{app.environment_ids.length}</td>
                <td className="p-3 text-slate-600">{app.description || <UiText k="No description" />}</td>
                <td className="p-3 text-slate-600"><FormattedDate value={app.created_at} /></td>
              </tr>
            ))
          ) : (
            <tr className="border-t border-slate-200">
              <td className="p-3 text-slate-500" colSpan={4}>
                <UiText k="No applications" /></td>
            </tr>
          )}
        </tbody>
      </Table>
    </SectionPage>
  );
}

function ApplicationsWritePanel({ applications }: { applications: Application[] }) {
  const queryClient = useQueryClient();
  const [applicationName, setApplicationName] = useState("");
  const [applicationDescription, setApplicationDescription] = useState("");
  const [applicationMessage, setApplicationMessage] = useState({ status: "", error: "" });
  const [isApplicationSubmitting, setIsApplicationSubmitting] = useState(false);
  const [applicationID, setApplicationID] = useState(applications[0]?.id ?? "");
  const [environmentName, setEnvironmentName] = useState("production");
  const [environmentKind, setEnvironmentKind] = useState("production");
  const [environmentMessage, setEnvironmentMessage] = useState({ status: "", error: "" });
  const [isEnvironmentSubmitting, setIsEnvironmentSubmitting] = useState(false);
  const [secretMessage, setSecretMessage] = useState({ status: "", error: "" });
  const [isSecretSubmitting, setIsSecretSubmitting] = useState(false);
  const [exportMessage, setExportMessage] = useState({ status: "", error: "" });
  const [isExportSubmitting, setIsExportSubmitting] = useState(false);
  const [deleteMessage, setDeleteMessage] = useState({ status: "", error: "" });
  const [isDeleteSubmitting, setIsDeleteSubmitting] = useState(false);

  const selectedApplication = applications.find(application => application.id === applicationID) ?? applications[0];

  useEffect(() => {
    if (!applicationID && applications[0]?.id) {
      setApplicationID(applications[0].id);
    }
  }, [applications, applicationID]);

  async function handleApplicationSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setApplicationMessage({ status: "", error: "" });
    const trimmedName = applicationName.trim();
    if (!trimmedName) {
      setApplicationMessage({ status: "", error: notice("Application name is required.") });
      return;
    }
    setIsApplicationSubmitting(true);
    try {
      const created = await createApplication({
        name: trimmedName,
        description: applicationDescription.trim() || undefined
      });
      await queryClient.invalidateQueries({ queryKey: ["applications"] });
      setApplicationMessage({
        status: created.secret
          ? notice("Created application {{name}}. Secret: {{secret}}.", { name: created.name, secret: created.secret })
          : notice("Created application {{name}}.", { name: created.name }),
        error: ""
      });
      setApplicationName("");
      setApplicationDescription("");
    } catch {
      setApplicationMessage({ status: "", error: notice("Unable to create application.") });
    } finally {
      setIsApplicationSubmitting(false);
    }
  }

  async function handleEnvironmentSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setEnvironmentMessage({ status: "", error: "" });
    if (!selectedApplication) {
      setEnvironmentMessage({ status: "", error: notice("Choose an application first.") });
      return;
    }
    const trimmedName = environmentName.trim();
    if (!trimmedName) {
      setEnvironmentMessage({ status: "", error: notice("Environment name is required.") });
      return;
    }
    setIsEnvironmentSubmitting(true);
    try {
      const created = await createEnvironment(selectedApplication.id, {
        name: trimmedName,
        kind: environmentKind.trim() || undefined
      });
      await queryClient.invalidateQueries({ queryKey: ["applications"] });
      setEnvironmentMessage({ status: notice("Created environment {{name}} for {{application}}.", { name: created.name, application: selectedApplication.name }), error: "" });
      setEnvironmentName("");
    } catch {
      setEnvironmentMessage({ status: "", error: notice("Unable to create environment.") });
    } finally {
      setIsEnvironmentSubmitting(false);
    }
  }

  async function handleSecretRotation() {
    setSecretMessage({ status: "", error: "" });
    if (!selectedApplication) {
      setSecretMessage({ status: "", error: notice("Choose an application first.") });
      return;
    }
    setIsSecretSubmitting(true);
    try {
      const rotated = await rotateApplicationSecret(selectedApplication.id);
      await queryClient.invalidateQueries({ queryKey: ["applications"] });
      setSecretMessage({
        status: rotated.secret
          ? notice("Rotated secret for {{name}}. Secret: {{secret}}.", { name: rotated.name, secret: rotated.secret })
          : notice("Rotated secret for {{name}}.", { name: rotated.name }),
        error: ""
      });
    } catch {
      setSecretMessage({ status: "", error: notice("Unable to rotate application secret.") });
    } finally {
      setIsSecretSubmitting(false);
    }
  }

  async function handleExportApplications() {
    setExportMessage({ status: "", error: "" });
    setIsExportSubmitting(true);
    try {
      const exported = await exportApplications();
      downloadApplicationExport(exported.items);
      setExportMessage({ status: notice("Exported {{count}} applications.", { count: exported.items.length }), error: "" });
    } catch {
      setExportMessage({ status: "", error: notice("Unable to export applications.") });
    } finally {
      setIsExportSubmitting(false);
    }
  }

  async function handleApplicationDelete() {
    setDeleteMessage({ status: "", error: "" });
    if (!selectedApplication) {
      setDeleteMessage({ status: "", error: notice("Choose an application first.") });
      return;
    }
    setIsDeleteSubmitting(true);
    try {
      const deletedName = selectedApplication.name;
      await deleteApplication(selectedApplication.id);
      setApplicationID("");
      await queryClient.invalidateQueries({ queryKey: ["applications"] });
      await queryClient.invalidateQueries({ queryKey: ["agents"] });
      await queryClient.invalidateQueries({ queryKey: ["daemon-workloads"] });
      await queryClient.invalidateQueries({ queryKey: ["overview"] });
      setDeleteMessage({ status: notice("Deleted application {{name}}.", { name: deletedName }), error: "" });
    } catch {
      setDeleteMessage({ status: "", error: notice("Unable to delete application.") });
    } finally {
      setIsDeleteSubmitting(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle><UiText k="Application Scope" /></CardTitle>
      </CardHeader>
      <CardContent className="grid gap-5 xl:grid-cols-2">
        <form className="grid content-start gap-3" onSubmit={handleApplicationSubmit}>
          <label className={fieldGroupClass} htmlFor="application-name">
            <span className={fieldLabelClass}><UiText k="Application Name" /></span>
            <input id="application-name" className={fieldControlClass} value={applicationName} onChange={event => setApplicationName(event.target.value)} required />
          </label>
          <label className={fieldGroupClass} htmlFor="application-description">
            <span className={fieldLabelClass}><UiText k="Description" /></span>
            <input
              id="application-description"
              className={fieldControlClass}
              value={applicationDescription}
              onChange={event => setApplicationDescription(event.target.value)}
            />
          </label>
          <Button disabled={isApplicationSubmitting} type="submit">
            <UiText k={isApplicationSubmitting ? "Creating Application" : "Create Application"} />
          </Button>
          <FormMessage error={applicationMessage.error} status={applicationMessage.status} />
        </form>
        <form className="grid content-start gap-3" onSubmit={handleEnvironmentSubmit}>
          <label className={fieldGroupClass} htmlFor="environment-application">
            <span className={fieldLabelClass}><UiText k="Application" /></span>
            <select
              id="environment-application"
              className={fieldControlClass}
              disabled={applications.length === 0}
              value={selectedApplication?.id ?? ""}
              onChange={event => setApplicationID(event.target.value)}
            >
              {applications.length > 0 ? (
                applications.map(application => (
                  <option key={application.id} value={application.id}>
                    {application.name}
                  </option>
                ))
              ) : (
                <option value=""><UiText k="No applications" /></option>
              )}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="environment-name">
            <span className={fieldLabelClass}><UiText k="Environment Name" /></span>
            <input id="environment-name" className={fieldControlClass} value={environmentName} onChange={event => setEnvironmentName(event.target.value)} required />
          </label>
          <label className={fieldGroupClass} htmlFor="environment-kind">
            <span className={fieldLabelClass}><UiText k="Kind" /></span>
            <select id="environment-kind" className={fieldControlClass} value={environmentKind} onChange={event => setEnvironmentKind(event.target.value)}>
              <option value="production"><UiText k="production" /></option>
              <option value="staging"><UiText k="staging" /></option>
              <option value="qa"><UiText k="qa" /></option>
              <option value="development"><UiText k="development" /></option>
            </select>
          </label>
          <Button disabled={isEnvironmentSubmitting || !selectedApplication} type="submit">
            <UiText k={isEnvironmentSubmitting ? "Creating Environment" : "Create Environment"} />
          </Button>
          <FormMessage error={environmentMessage.error} status={environmentMessage.status} />
          <Button disabled={isSecretSubmitting || !selectedApplication} type="button" variant="secondary" onClick={handleSecretRotation}>
            <UiText k={isSecretSubmitting ? "Rotating Secret" : "Rotate Secret"} />
          </Button>
          <FormMessage error={secretMessage.error} status={secretMessage.status} />
          <div className="grid gap-2 md:grid-cols-2">
            <Button disabled={isExportSubmitting} type="button" variant="secondary" onClick={() => void handleExportApplications()}>
              <Download className="h-4 w-4" />
              <UiText k={isExportSubmitting ? "Exporting Applications" : "Export Applications"} />
            </Button>
            <Button disabled={isDeleteSubmitting || !selectedApplication} type="button" variant="danger" onClick={() => void handleApplicationDelete()}>
              <Trash2 className="h-4 w-4" />
              <UiText k={isDeleteSubmitting ? "Deleting Application" : "Delete Application"} />
            </Button>
          </div>
          <FormMessage error={exportMessage.error} status={exportMessage.status} />
          <FormMessage error={deleteMessage.error} status={deleteMessage.status} />
        </form>
      </CardContent>
    </Card>
  );
}

function downloadApplicationExport(applications: Application[]) {
  if (typeof document === "undefined") {
    return;
  }
  const blob = new Blob([JSON.stringify({ items: applications }, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `ohmyrasp-applications-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export function AgentsPage() {
  const { t } = useTranslation();
  const agentsQuery = useAgents();
  const agents = agentsQuery.data?.items ?? [];
  const applicationsQuery = useApplications();
  const applications = applicationsQuery.data?.items ?? [];
  const daemonWorkloadsQuery = useDaemonWorkloads();
  const daemonWorkloads = daemonWorkloadsQuery.data?.items ?? [];
  const agentArtifactsQuery = useAgentArtifacts();
  const agentArtifactCatalog = agentArtifactsQuery.data ?? emptyAgentArtifactCatalog();
  const [applicationSecrets, setApplicationSecrets] = useState<Record<string, string>>({});
  const [daemonToken, setDaemonToken] = useState("");
  const onlineAgents = agents.filter(agent => agent.status === "online").length;
  const latestVersion = latestAgentVersion(agents.map(agent => agent.version));
  const driftedAgents = agents.filter(agent => latestVersion && agent.version !== latestVersion).length;
  const rememberApplicationSecret = (applicationID: string, secret: string) => {
    setApplicationSecrets(current => ({ ...current, [applicationID]: secret }));
  };

  return (
    <SectionPage
      title={t("pages.agents.title")}
      summary={t("pages.agents.summary")}
    >
      <QueryStateNotice
        isLoading={agentsQuery.isLoading || applicationsQuery.isLoading || daemonWorkloadsQuery.isLoading || agentArtifactsQuery.isLoading}
        isError={agentsQuery.isError || applicationsQuery.isError || daemonWorkloadsQuery.isError || agentArtifactsQuery.isError}
        loading={<UiText k="Loading agent operations data." />}
        error={<UiText k="Some agent operations data is unavailable." />}
      />
      <div className="grid gap-3 md:grid-cols-3">
        <Metric label={<UiText k="Online" />} value={`${onlineAgents}/${agents.length}`} detail={<UiText k="healthy heartbeat" />} />
        <Metric
          label={<UiText k="Drifted" />}
          value={driftedAgents}
          detail={latestVersion ? <UiText k="latest {{version}}" values={{ version: latestVersion }} /> : <UiText k="no version baseline" />}
        />
        <Metric label={<UiText k="Assigned" />} value={agents.filter(agent => agent.policy_id).length} detail={<UiText k="policy-bound Agents" />} />
      </div>
      <AgentsWritePanel applications={applications} onSecretUsed={rememberApplicationSecret} />
      <AgentOperationsPanel agents={agents} applications={applications} applicationSecrets={applicationSecrets} onSecretUsed={rememberApplicationSecret} />
      <DaemonWorkloadPanel applications={applications} workloads={daemonWorkloads} onTokenReceived={setDaemonToken} />
      <AgentArtifactUploadPanel catalog={agentArtifactCatalog} />
      <AgentArtifactCatalogPanel catalog={agentArtifactCatalog} />
      <DaemonArtifactPanel applications={applications} daemonToken={daemonToken} />
      <Table>
        <thead>
          <tr className="bg-slate-50">
            <th className="p-3 text-left"><UiText k="Host" /></th>
            <th className="p-3 text-left"><UiText k="Runtime" /></th>
            <th className="p-3 text-left"><UiText k="Version" /></th>
            <th className="p-3 text-left"><UiText k="Policy" /></th>
            <th className="p-3 text-left"><UiText k="Status" /></th>
            <th className="p-3 text-left"><UiText k="Last Seen" /></th>
          </tr>
        </thead>
        <tbody>
          {agents.length > 0 ? (
            agents.map(agent => (
              <tr key={agent.id} className="border-t border-slate-200">
                <td className="p-3 font-medium">{agent.hostname}</td>
                <td className="p-3 text-slate-600">{agent.runtime}</td>
                <td className="p-3 text-slate-600">{agent.version}</td>
                <td className="p-3 text-slate-600">{agent.policy_id ? `${agent.policy_id} v${agent.policy_version ?? 0}` : <UiText k="unassigned" />}</td>
                <td className="p-3">
                  <Badge tone={agent.status === "online" ? "green" : "amber"}>{agent.status}</Badge>
                </td>
                <td className="p-3 text-slate-600"><FormattedDate value={agent.last_seen_at} /></td>
              </tr>
            ))
          ) : (
            <tr className="border-t border-slate-200">
              <td className="p-3 text-slate-500" colSpan={6}>
                <UiText k="No Agents" /></td>
            </tr>
          )}
        </tbody>
      </Table>
    </SectionPage>
  );
}

function AgentOperationsPanel({
  agents,
  applications,
  applicationSecrets,
  onSecretUsed
}: {
  agents: Agent[];
  applications: Application[];
  applicationSecrets: Record<string, string>;
  onSecretUsed: (applicationID: string, secret: string) => void;
}) {
  const queryClient = useQueryClient();
  const [agentID, setAgentID] = useState(agents[0]?.id ?? "");
  const [applicationSecret, setApplicationSecret] = useState("");
  const [heartbeatStatus, setHeartbeatStatus] = useState("online");
  const [message, setMessage] = useState({ status: "", error: "" });
  const [isSubmitting, setIsSubmitting] = useState(false);

  const selectedAgent = agents.find(agent => agent.id === agentID) ?? agents[0];
  const selectedApplication = applications.find(application => application.id === selectedAgent?.application_id);

  useEffect(() => {
    if (!selectedAgent && agentID) {
      setAgentID("");
      return;
    }
    if (!agentID && selectedAgent) {
      setAgentID(selectedAgent.id);
    }
  }, [agentID, selectedAgent]);

  useEffect(() => {
    if (!selectedAgent) {
      setApplicationSecret("");
      return;
    }
    setApplicationSecret(applicationSecrets[selectedAgent.application_id] ?? selectedApplication?.secret ?? "");
  }, [applicationSecrets, selectedAgent, selectedApplication?.secret]);

  async function handleHeartbeat() {
    if (!selectedAgent) {
      setMessage({ status: "", error: notice("Choose an Agent first.") });
      return;
    }
    const trimmedSecret = applicationSecret.trim();
    if (!trimmedSecret) {
      setMessage({ status: "", error: notice("Application secret is required.") });
      return;
    }
    setIsSubmitting(true);
    setMessage({ status: "", error: "" });
    try {
      const updated = await heartbeatAgent(selectedAgent.id, heartbeatStatus, {
        application_id: selectedAgent.application_id,
        application_secret: trimmedSecret
      });
      onSecretUsed(selectedAgent.application_id, trimmedSecret);
      await queryClient.invalidateQueries({ queryKey: ["agents"] });
      setMessage({ status: notice("Heartbeat accepted for {{hostname}}: {{status}}.", { hostname: updated.hostname, status: updated.status }), error: "" });
    } catch {
      setMessage({ status: "", error: notice("Unable to send Agent heartbeat.") });
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handlePolicyPull() {
    if (!selectedAgent) {
      setMessage({ status: "", error: notice("Choose an Agent first.") });
      return;
    }
    const trimmedSecret = applicationSecret.trim();
    if (!trimmedSecret) {
      setMessage({ status: "", error: notice("Application secret is required.") });
      return;
    }
    setIsSubmitting(true);
    setMessage({ status: "", error: "" });
    try {
      const policy = await pullAgentPolicy(selectedAgent.id, {
        application_id: selectedAgent.application_id,
        application_secret: trimmedSecret
      });
      onSecretUsed(selectedAgent.application_id, trimmedSecret);
      setMessage({
        status: notice("Pulled policy version {{version}} ({{status}}) with {{rules}} rules for {{hostname}}.", {
          version: policy.version,
          status: policy.status,
          rules: policy.rules.length,
          hostname: selectedAgent.hostname
        }),
        error: ""
      });
    } catch {
      setMessage({ status: "", error: notice("Unable to pull Agent policy.") });
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle><UiText k="Agent Operations" /></CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid gap-3 md:grid-cols-[1.2fr_.9fr_.7fr_auto_auto] md:items-end">
          <label className={fieldGroupClass} htmlFor="agent-operation-agent">
            <span className={fieldLabelClass}><UiText k="Agent" /></span>
            <select
              id="agent-operation-agent"
              className={fieldControlClass}
              disabled={agents.length === 0}
              value={selectedAgent?.id ?? ""}
              onChange={event => setAgentID(event.target.value)}
            >
              {agents.length > 0 ? (
                agents.map(agent => (
                  <option key={agent.id} value={agent.id}>
                    {agent.hostname}
                  </option>
                ))
              ) : (
                <option value=""><UiText k="No Agents" /></option>
              )}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="agent-operation-secret">
            <span className={fieldLabelClass}><UiText k="Operation Secret" /></span>
            <input
              id="agent-operation-secret"
              autoComplete="off"
              className={fieldControlClass}
              type="password"
              value={applicationSecret}
              onChange={event => setApplicationSecret(event.target.value)}
            />
          </label>
          <label className={fieldGroupClass} htmlFor="heartbeat-status">
            <span className={fieldLabelClass}><UiText k="Heartbeat Status" /></span>
            <select id="heartbeat-status" className={fieldControlClass} value={heartbeatStatus} onChange={event => setHeartbeatStatus(event.target.value)}>
              <option value="online"><UiText k="online" /></option>
              <option value="offline"><UiText k="offline" /></option>
            </select>
          </label>
          <Button disabled={isSubmitting || !selectedAgent} type="button" variant="secondary" onClick={handleHeartbeat}>
            <UiText k="Send Heartbeat" /></Button>
          <Button disabled={isSubmitting || !selectedAgent} type="button" variant="secondary" onClick={handlePolicyPull}>
            <UiText k="Pull Policy" /></Button>
          <div className="md:col-span-5">
            <FormMessage error={message.error} status={message.status} />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function DaemonWorkloadPanel({
  applications,
  workloads,
  onTokenReceived
}: {
  applications: Application[];
  workloads: DaemonWorkload[];
  onTokenReceived: (token: string) => void;
}) {
  const queryClient = useQueryClient();
  const [bindingApplicationIDs, setBindingApplicationIDs] = useState<Record<string, string>>({});
  const [message, setMessage] = useState({ status: "", error: "" });
  const [isTokenSubmitting, setIsTokenSubmitting] = useState(false);
  const [activeWorkloadID, setActiveWorkloadID] = useState("");

  useEffect(() => {
    setBindingApplicationIDs(current => {
      let changed = false;
      const next = { ...current };
      for (const workload of workloads) {
        if (!next[workload.id]) {
          next[workload.id] = workload.application_id || applications[0]?.id || "";
          changed = true;
        }
      }
      return changed ? next : current;
    });
  }, [applications, workloads]);

  async function handleTokenReveal() {
    setMessage({ status: "", error: "" });
    setIsTokenSubmitting(true);
    try {
      const token = await getDaemonToken();
      onTokenReceived(token.access_token);
      setMessage({ status: notice("Daemon token: {{token}}", { token: token.access_token }), error: "" });
    } catch {
      setMessage({ status: "", error: notice("Unable to reveal daemon token.") });
    } finally {
      setIsTokenSubmitting(false);
    }
  }

  async function handleTokenReset() {
    setMessage({ status: "", error: "" });
    setIsTokenSubmitting(true);
    try {
      const token = await resetDaemonToken();
      onTokenReceived(token.access_token);
      await queryClient.invalidateQueries({ queryKey: ["audit-logs"] });
      setMessage({ status: notice("Rotated daemon token: {{token}}", { token: token.access_token }), error: "" });
    } catch {
      setMessage({ status: "", error: notice("Unable to rotate daemon token.") });
    } finally {
      setIsTokenSubmitting(false);
    }
  }

  async function handleBind(workload: DaemonWorkload) {
    const applicationID = bindingApplicationIDs[workload.id] || applications[0]?.id || "";
    if (!applicationID) {
      setMessage({ status: "", error: notice("Choose an application before binding.") });
      return;
    }
    setActiveWorkloadID(workload.id);
    setMessage({ status: "", error: "" });
    try {
      const bound = await bindDaemonWorkload(workload.id, applicationID);
      await queryClient.invalidateQueries({ queryKey: ["daemon-workloads"] });
      await queryClient.invalidateQueries({ queryKey: ["audit-logs"] });
      const app = applications.find(application => application.id === bound.application_id);
      setMessage({ status: notice("Bound {{workload}} to {{application}}.", { workload: workloadLabel(bound), application: app?.name ?? bound.application_id }), error: "" });
    } catch {
      setMessage({ status: "", error: notice("Unable to bind workload.") });
    } finally {
      setActiveWorkloadID("");
    }
  }

  async function handleUnbind(workload: DaemonWorkload) {
    setActiveWorkloadID(workload.id);
    setMessage({ status: "", error: "" });
    try {
      const unbound = await unbindDaemonWorkload(workload.id);
      await queryClient.invalidateQueries({ queryKey: ["daemon-workloads"] });
      await queryClient.invalidateQueries({ queryKey: ["audit-logs"] });
      setMessage({ status: notice("Unbound {{workload}}.", { workload: workloadLabel(unbound) }), error: "" });
    } catch {
      setMessage({ status: "", error: notice("Unable to unbind workload.") });
    } finally {
      setActiveWorkloadID("");
    }
  }

  return (
    <Card className="overflow-hidden">
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <CardTitle><UiText k="Daemon Workloads" /></CardTitle>
          <div className="flex flex-wrap gap-2">
            <Button disabled={isTokenSubmitting} type="button" variant="secondary" onClick={handleTokenReveal}>
              <KeyRound className="h-4 w-4" />
              <UiText k="Reveal Token" /></Button>
            <Button disabled={isTokenSubmitting} type="button" variant="secondary" onClick={handleTokenReset}>
              <RefreshCcw className="h-4 w-4" />
              <UiText k="Reset Token" /></Button>
          </div>
        </div>
        <FormMessage error={message.error} status={message.status} />
      </CardHeader>
      <CardContent className="p-0">
        <Table className="rounded-none border-0">
          <thead>
            <tr className="bg-slate-50">
              <th className="p-3 text-left"><UiText k="Node" /></th>
              <th className="p-3 text-left"><UiText k="Workload" /></th>
              <th className="p-3 text-left"><UiText k="Bound App" /></th>
              <th className="p-3 text-left"><UiText k="Injection" /></th>
              <th className="p-3 text-left"><UiText k="Seen" /></th>
              <th className="p-3 text-left"><UiText k="Bind" /></th>
              <th className="p-3 text-left"><UiText k="Actions" /></th>
            </tr>
          </thead>
          <tbody>
            {workloads.length > 0 ? (
              workloads.map(workload => {
                const boundApplication = applications.find(application => application.id === workload.application_id);
                return (
                  <tr key={workload.id} className="border-t border-slate-200 align-top">
                    <td className="p-3">
                      <div className="font-medium text-slate-950">{workload.node_name}</div>
                      <div className="mt-1 text-xs text-slate-500">{workload.id}</div>
                    </td>
                    <td className="p-3">
                      <Badge tone={workload.type === "process" ? "blue" : "amber"}>{workload.type}</Badge>
                      <div className="mt-2 text-sm text-slate-600">{workloadDetail(workload)}</div>
                    </td>
                    <td className="p-3 text-slate-600">{boundApplication?.name ?? workload.application_id ?? <UiText k="unbound" />}</td>
                    <td className="p-3">{injectionStatusCell(workload)}</td>
                    <td className="p-3 text-slate-600"><FormattedDate value={workload.updated_at} /></td>
                    <td className="p-3">
                      <select
                        className={fieldControlClass}
                        disabled={applications.length === 0}
                        value={bindingApplicationIDs[workload.id] ?? applications[0]?.id ?? ""}
                        onChange={event => setBindingApplicationIDs(current => ({ ...current, [workload.id]: event.target.value }))}
                      >
                        {applications.length > 0 ? (
                          applications.map(application => (
                            <option key={application.id} value={application.id}>
                              {application.name}
                            </option>
                          ))
                        ) : (
                          <option value=""><UiText k="No applications" /></option>
                        )}
                      </select>
                    </td>
                    <td className="p-3">
                      <div className="flex flex-wrap gap-2">
                        <Button disabled={activeWorkloadID === workload.id || applications.length === 0} type="button" variant="secondary" onClick={() => handleBind(workload)}>
                          <Link2 className="h-4 w-4" />
                          <UiText k="Bind" /></Button>
                        <Button disabled={activeWorkloadID === workload.id || !workload.application_id} type="button" variant="secondary" onClick={() => handleUnbind(workload)}>
                          <Link2Off className="h-4 w-4" />
                          <UiText k="Unbind" /></Button>
                      </div>
                    </td>
                  </tr>
                );
              })
            ) : (
              <tr className="border-t border-slate-200">
                <td className="p-3 text-slate-500" colSpan={7}>
                  <UiText k="No daemon workloads" /></td>
              </tr>
            )}
          </tbody>
        </Table>
      </CardContent>
    </Card>
  );
}

function AgentArtifactUploadPanel({ catalog }: { catalog: AgentArtifactCatalog }) {
  const queryClient = useQueryClient();
  const [file, setFile] = useState<File | undefined>();
  const [systemType, setSystemType] = useState("linux");
  const [languageVersion, setLanguageVersion] = useState("17");
  const [message, setMessage] = useState({ status: "", error: "" });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const uploadAvailable = catalog.artifact_dir_configured;

  async function handleUpload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage({ status: "", error: "" });
    const normalizedSystemType = systemType.trim();
    const normalizedLanguageVersion = languageVersion.trim();
    if (!uploadAvailable) {
      setMessage({ status: "", error: notice("Managed artifact directory is not configured.") });
      return;
    }
    if (!file) {
      setMessage({ status: "", error: notice("Choose an Agent ZIP package.") });
      return;
    }
    if (!file.name.toLowerCase().endsWith(".zip")) {
      setMessage({ status: "", error: notice("Agent artifact must be a ZIP package.") });
      return;
    }
    if (!normalizedSystemType || !normalizedLanguageVersion) {
      setMessage({ status: "", error: notice("System type and language version are required.") });
      return;
    }
    setIsSubmitting(true);
    try {
      const content = await fileToBase64(file);
      const uploaded = await uploadAgentArtifact({
        filename: file.name,
        language: "java",
        system_type: normalizedSystemType,
        language_version: normalizedLanguageVersion,
        content_base64: content
      });
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["agent-artifacts"] }),
        queryClient.invalidateQueries({ queryKey: ["audit-logs"] })
      ]);
      setMessage({ status: notice("Uploaded {{filename}} ({{size}}).", { filename: uploaded.filename, size: formatBytes(uploaded.size) }), error: "" });
    } catch {
      setMessage({ status: "", error: notice("Unable to upload Agent artifact.") });
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <CardTitle><UiText k="Agent Artifact Upload" /></CardTitle>
          <Badge tone={uploadAvailable ? "green" : "amber"}>
            <UiText k={uploadAvailable ? "Managed Storage" : "Storage Unavailable"} />
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        <form className="grid gap-3 md:grid-cols-2 xl:grid-cols-[1.4fr_.7fr_.8fr_auto] xl:items-end" onSubmit={handleUpload}>
          <label className={fieldGroupClass} htmlFor="artifact-upload-file">
            <span className={fieldLabelClass}><UiText k="Agent ZIP" /></span>
            <input
              id="artifact-upload-file"
              accept=".zip,application/zip,application/x-zip-compressed"
              className={`${fieldControlClass} py-2`}
              disabled={!uploadAvailable || isSubmitting}
              type="file"
              onChange={event => setFile(event.target.files?.[0])}
            />
          </label>
          <label className={fieldGroupClass} htmlFor="artifact-upload-system-type">
            <span className={fieldLabelClass}><UiText k="Upload System Type" /></span>
            <select
              id="artifact-upload-system-type"
              className={fieldControlClass}
              disabled={!uploadAvailable || isSubmitting}
              value={systemType}
              onChange={event => setSystemType(event.target.value)}
            >
              <option value="linux"><UiText k="linux" /></option>
              <option value="windows"><UiText k="windows" /></option>
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="artifact-upload-language-version">
            <span className={fieldLabelClass}><UiText k="Upload Language Version" /></span>
            <input
              id="artifact-upload-language-version"
              className={fieldControlClass}
              disabled={!uploadAvailable || isSubmitting}
              value={languageVersion}
              onChange={event => setLanguageVersion(event.target.value)}
            />
          </label>
          <Button className="gap-2" disabled={!uploadAvailable || isSubmitting} type="submit">
            <Upload className="h-4 w-4" />
            <UiText k={isSubmitting ? "Uploading Artifact" : "Upload Artifact"} />
          </Button>
          <div className="md:col-span-2 xl:col-span-4">
            <FormMessage error={message.error} status={message.status} />
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function AgentArtifactCatalogPanel({ catalog }: { catalog: AgentArtifactCatalog }) {
  return (
    <Card className="overflow-hidden">
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <CardTitle><UiText k="Agent Artifact Catalog" /></CardTitle>
          <div className="flex flex-wrap gap-2">
            <Badge tone={catalog.artifact_dir_configured ? "green" : "amber"}>
              <UiText k={catalog.artifact_dir_configured ? "Filesystem Pool" : "Generated Bootstrap"} />
            </Badge>
            <Badge tone={catalog.generated_bootstrap_enabled ? "blue" : "neutral"}>
              <UiText k={catalog.generated_bootstrap_enabled ? "Generated Bootstrap" : "Filesystem Only"} />
            </Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <Table className="rounded-none border-0">
          <thead>
            <tr className="bg-slate-50">
              <th className="p-3 text-left"><UiText k="Package" /></th>
              <th className="p-3 text-left"><UiText k="Runtime" /></th>
              <th className="p-3 text-left"><UiText k="Checksum" /></th>
              <th className="p-3 text-left"><UiText k="Size" /></th>
              <th className="p-3 text-left"><UiText k="Source" /></th>
              <th className="p-3 text-left"><UiText k="Updated" /></th>
            </tr>
          </thead>
          <tbody>
            {catalog.items.length > 0 ? (
              catalog.items.map(item => (
                <tr key={item.filename} className="border-t border-slate-200 align-top">
                  <td className="p-3 font-medium">{item.filename}</td>
                  <td className="p-3 text-slate-600">
                    {item.language} / {item.system_type} / {item.language_version}
                  </td>
                  <td className="p-3 font-mono text-xs text-slate-600">{item.md5}</td>
                  <td className="p-3 text-slate-600">{formatBytes(item.size)}</td>
                  <td className="p-3">
                    <Badge tone={item.source === "filesystem" ? "green" : "blue"}>{item.source}</Badge>
                  </td>
                  <td className="p-3 text-slate-600"><FormattedDate value={item.updated_at} /></td>
                </tr>
              ))
            ) : (
              <tr className="border-t border-slate-200">
                <td className="p-3 text-slate-500" colSpan={6}>
                  <UiText k={catalog.generated_bootstrap_enabled ? "Generated bootstrap artifacts are available per application." : "No Agent artifacts discovered."} />
                </td>
              </tr>
            )}
          </tbody>
        </Table>
      </CardContent>
    </Card>
  );
}

function DaemonArtifactPanel({ applications, daemonToken }: { applications: Application[]; daemonToken: string }) {
  const [applicationID, setApplicationID] = useState(applications[0]?.id ?? "");
  const [token, setToken] = useState(daemonToken);
  const [systemType, setSystemType] = useState("linux");
  const [languageVersion, setLanguageVersion] = useState("unknown");
  const [artifact, setArtifact] = useState<AgentArtifactInfo | undefined>();
  const [message, setMessage] = useState({ status: "", error: "" });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isDownloading, setIsDownloading] = useState(false);

  const selectedApplication = applications.find(application => application.id === applicationID) ?? applications[0];

  useEffect(() => {
    if (!applicationID && selectedApplication) {
      setApplicationID(selectedApplication.id);
    }
  }, [applicationID, selectedApplication]);

  useEffect(() => {
    if (daemonToken) {
      setToken(daemonToken);
    }
  }, [daemonToken]);

  async function handleArtifactCheck() {
    setMessage({ status: "", error: "" });
    setArtifact(undefined);
    const trimmedToken = token.trim();
    if (!selectedApplication || !trimmedToken) {
      setMessage({ status: "", error: artifactInputError(Boolean(selectedApplication), trimmedToken) });
      return;
    }
    setIsSubmitting(true);
    try {
      const app = await getDaemonApplicationCredential(trimmedToken, selectedApplication.id);
      const info = await getAgentArtifactInfo(trimmedToken, {
        applicationID: selectedApplication.id,
        language: app.language || "java",
        systemType: systemType.trim() || "linux",
        languageVersion: languageVersion.trim() || "unknown"
      });
      setArtifact(info);
      setMessage({ status: notice("Artifact {{filename}} ready for {{application}}.", { filename: info.filename, application: selectedApplication.name }), error: "" });
    } catch {
      setMessage({ status: "", error: notice("Unable to verify Agent artifact.") });
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleArtifactDownload() {
    setMessage({ status: "", error: "" });
    const trimmedToken = token.trim();
    if (!selectedApplication || !trimmedToken) {
      setMessage({ status: "", error: artifactInputError(Boolean(selectedApplication), trimmedToken) });
      return;
    }
    setIsDownloading(true);
    try {
      const app = await getDaemonApplicationCredential(trimmedToken, selectedApplication.id);
      const language = artifact?.language || app.language || "java";
      const download = await downloadAgentArtifact(trimmedToken, {
        applicationID: selectedApplication.id,
        language,
        systemType: systemType.trim() || artifact?.system_type || "linux",
        languageVersion: languageVersion.trim() || artifact?.language_version || "unknown"
      });
      triggerBrowserDownload(download.blob, download.filename);
      setMessage({
        status: download.md5
          ? notice("Downloaded {{filename}} ({{size}}). MD5: {{md5}}.", { filename: download.filename, size: formatBytes(download.blob.size), md5: download.md5 })
          : notice("Downloaded {{filename}} ({{size}}).", { filename: download.filename, size: formatBytes(download.blob.size) }),
        error: ""
      });
    } catch {
      setMessage({ status: "", error: notice("Unable to download Agent artifact.") });
    } finally {
      setIsDownloading(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle><UiText k="Agent Bootstrap Artifact" /></CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4">
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-[1.2fr_1.1fr_.7fr_.8fr_auto_auto] xl:items-end">
          <label className={fieldGroupClass} htmlFor="artifact-application">
            <span className={fieldLabelClass}><UiText k="Artifact Application" /></span>
            <select
              id="artifact-application"
              className={fieldControlClass}
              disabled={applications.length === 0}
              value={selectedApplication?.id ?? ""}
              onChange={event => setApplicationID(event.target.value)}
            >
              {applications.length > 0 ? (
                applications.map(application => (
                  <option key={application.id} value={application.id}>
                    {application.name}
                  </option>
                ))
              ) : (
                <option value=""><UiText k="No applications" /></option>
              )}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="artifact-daemon-token">
            <span className={fieldLabelClass}><UiText k="Artifact Daemon Token" /></span>
            <input id="artifact-daemon-token" autoComplete="off" className={fieldControlClass} type="password" value={token} onChange={event => setToken(event.target.value)} />
          </label>
          <label className={fieldGroupClass} htmlFor="artifact-system-type">
            <span className={fieldLabelClass}><UiText k="System Type" /></span>
            <select id="artifact-system-type" className={fieldControlClass} value={systemType} onChange={event => setSystemType(event.target.value)}>
              <option value="linux"><UiText k="linux" /></option>
              <option value="windows"><UiText k="windows" /></option>
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="artifact-language-version">
            <span className={fieldLabelClass}><UiText k="Language Version" /></span>
            <input id="artifact-language-version" className={fieldControlClass} value={languageVersion} onChange={event => setLanguageVersion(event.target.value)} />
          </label>
          <Button disabled={isSubmitting || !selectedApplication} type="button" variant="secondary" onClick={handleArtifactCheck}>
            <UiText k={isSubmitting ? "Checking Artifact" : "Check Agent Artifact"} />
          </Button>
          <Button disabled={isDownloading || !selectedApplication} type="button" onClick={handleArtifactDownload}>
            <UiText k={isDownloading ? "Downloading Artifact" : "Download Agent Artifact"} />
          </Button>
        </div>
        <FormMessage error={message.error} status={message.status} />
        {artifact ? (
          <div className="grid gap-2 rounded-md border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700 md:grid-cols-2 xl:grid-cols-4">
            <div>
              <span className="block text-xs font-medium text-slate-500"><UiText k="MD5" /></span>
              <span className="break-all font-mono text-xs">{artifact.md5}</span>
            </div>
            <div>
              <span className="block text-xs font-medium text-slate-500"><UiText k="Size" /></span>
              <span>{formatBytes(artifact.size)}</span>
            </div>
            <div>
              <span className="block text-xs font-medium text-slate-500"><UiText k="Language" /></span>
              <span>{artifact.language}</span>
            </div>
            <div>
              <span className="block text-xs font-medium text-slate-500"><UiText k="System" /></span>
              <span>{artifact.system_type}</span>
            </div>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

function artifactInputError(hasApplication: boolean, token: string) {
  if (!hasApplication) {
    return notice("Choose an application first.");
  }
  if (!token) {
    return notice("Daemon token is required.");
  }
  return notice("Artifact request is invalid.");
}

function triggerBrowserDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = "noopener";
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error ?? new Error("Unable to read file."));
    reader.onload = () => {
      const result = String(reader.result ?? "");
      resolve(result.includes(",") ? result.slice(result.indexOf(",") + 1) : result);
    };
    reader.readAsDataURL(file);
  });
}

function AgentsWritePanel({ applications, onSecretUsed }: { applications: Application[]; onSecretUsed: (applicationID: string, secret: string) => void }) {
  const queryClient = useQueryClient();
  const [applicationID, setApplicationID] = useState(applications.find(application => application.environment_ids.length > 0)?.id ?? applications[0]?.id ?? "");
  const [environmentID, setEnvironmentID] = useState("");
  const [applicationSecret, setApplicationSecret] = useState("");
  const [hostname, setHostname] = useState("");
  const [runtime, setRuntime] = useState("java");
  const [version, setVersion] = useState("1.0.0");
  const [message, setMessage] = useState({ status: "", error: "" });
  const [isSubmitting, setIsSubmitting] = useState(false);

  const selectedApplication = applications.find(application => application.id === applicationID) ?? applications.find(application => application.environment_ids.length > 0) ?? applications[0];

  useEffect(() => {
    if (!applicationID && selectedApplication) {
      setApplicationID(selectedApplication.id);
    }
  }, [applicationID, selectedApplication]);

  useEffect(() => {
    if (!selectedApplication) {
      setEnvironmentID("");
      return;
    }
    if (!selectedApplication.environment_ids.includes(environmentID)) {
      setEnvironmentID(selectedApplication.environment_ids[0] ?? "");
    }
  }, [environmentID, selectedApplication]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage({ status: "", error: "" });
    if (!selectedApplication || !environmentID) {
      setMessage({ status: "", error: notice("Choose an application environment first.") });
      return;
    }
    const trimmedSecret = applicationSecret.trim();
    const trimmedHostname = hostname.trim();
    const trimmedVersion = version.trim();
    if (!trimmedSecret || !trimmedHostname || !trimmedVersion) {
      setMessage({ status: "", error: notice("Application secret, hostname, and version are required.") });
      return;
    }
    setIsSubmitting(true);
    try {
      const agent = await registerAgent({
        application_id: selectedApplication.id,
        application_secret: trimmedSecret,
        environment_id: environmentID,
        hostname: trimmedHostname,
        runtime: runtime.trim() || undefined,
        version: trimmedVersion
      });
      onSecretUsed(selectedApplication.id, trimmedSecret);
      await queryClient.invalidateQueries({ queryKey: ["agents"] });
      setMessage({ status: notice("Registered Agent {{hostname}} as {{id}}.", { hostname: agent.hostname, id: agent.id }), error: "" });
      setApplicationSecret("");
      setHostname("");
    } catch {
      setMessage({ status: "", error: notice("Unable to register Agent.") });
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle><UiText k="Agent Registration" /></CardTitle>
      </CardHeader>
      <CardContent>
        <form className="grid gap-3 md:grid-cols-2 xl:grid-cols-3" onSubmit={handleSubmit}>
          <label className={fieldGroupClass} htmlFor="agent-application">
            <span className={fieldLabelClass}><UiText k="Application" /></span>
            <select
              id="agent-application"
              className={fieldControlClass}
              disabled={applications.length === 0}
              value={selectedApplication?.id ?? ""}
              onChange={event => setApplicationID(event.target.value)}
            >
              {applications.length > 0 ? (
                applications.map(application => (
                  <option key={application.id} value={application.id}>
                    {application.name}
                  </option>
                ))
              ) : (
                <option value=""><UiText k="No applications" /></option>
              )}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="agent-environment">
            <span className={fieldLabelClass}><UiText k="Environment" /></span>
            <select
              id="agent-environment"
              className={fieldControlClass}
              disabled={!selectedApplication || selectedApplication.environment_ids.length === 0}
              value={environmentID}
              onChange={event => setEnvironmentID(event.target.value)}
            >
              {selectedApplication?.environment_ids.length ? (
                selectedApplication.environment_ids.map(envID => (
                  <option key={envID} value={envID}>
                    {envID}
                  </option>
                ))
              ) : (
                <option value=""><UiText k="No environments" /></option>
              )}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="agent-application-secret">
            <span className={fieldLabelClass}><UiText k="Application Secret" /></span>
            <input
              id="agent-application-secret"
              autoComplete="off"
              className={fieldControlClass}
              type="password"
              value={applicationSecret}
              onChange={event => setApplicationSecret(event.target.value)}
              required
            />
          </label>
          <label className={fieldGroupClass} htmlFor="agent-hostname">
            <span className={fieldLabelClass}><UiText k="Agent Hostname" /></span>
            <input id="agent-hostname" className={fieldControlClass} value={hostname} onChange={event => setHostname(event.target.value)} required />
          </label>
          <label className={fieldGroupClass} htmlFor="agent-runtime">
            <span className={fieldLabelClass}><UiText k="Agent Runtime" /></span>
            <input id="agent-runtime" className={fieldControlClass} value={runtime} onChange={event => setRuntime(event.target.value)} />
          </label>
          <label className={fieldGroupClass} htmlFor="agent-version">
            <span className={fieldLabelClass}><UiText k="Agent Version" /></span>
            <input id="agent-version" className={fieldControlClass} value={version} onChange={event => setVersion(event.target.value)} required />
          </label>
          <div className="flex flex-wrap items-center gap-3 md:col-span-2 xl:col-span-3">
            <Button disabled={isSubmitting || !selectedApplication || !environmentID} type="submit">
              <UiText k={isSubmitting ? "Registering Agent" : "Register Agent"} />
            </Button>
            <div className="min-w-72 flex-1">
              <FormMessage error={message.error} status={message.status} />
            </div>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

export function PoliciesPage() {
  const { t } = useTranslation();
  const policiesQuery = usePolicies();
  const policies = policiesQuery.data?.items ?? [];
  const applicationsQuery = useApplications();
  const applications = applicationsQuery.data?.items ?? [];
  const sampleEventsQuery = useSecurityEvents("attack", { limit: 25 });
  const sampleEvents = sampleEventsQuery.data?.items ?? [];
  const activePolicies = policies.filter(policy => policy.active).length;
  const ruleCount = policies.reduce((count, policy) => count + (policy.active?.rules.length ?? 0), 0);

  return (
    <SectionPage
      title={t("pages.policies.title")}
      summary={t("pages.policies.summary")}
    >
      <QueryStateNotice
        isLoading={policiesQuery.isLoading || applicationsQuery.isLoading || sampleEventsQuery.isLoading}
        isError={policiesQuery.isError || applicationsQuery.isError || sampleEventsQuery.isError}
        loading={<UiText k="Loading policies." />}
        error={<UiText k="Policies are unavailable." />}
      />
      <div className="grid gap-3 md:grid-cols-3">
        <Metric label={<UiText k="Policy Sets" />} value={policies.length} detail={<UiText k="managed rule groups" />} />
        <Metric label={<UiText k="Active" />} value={activePolicies} detail={<UiText k="serving policy versions" />} />
        <Metric label={<UiText k="Active Rules" />} value={ruleCount} detail={<UiText k="rules in deployed versions" />} />
      </div>
      <PolicySetCreatePanel />
      <PolicyWritePanel applications={applications} policies={policies} sampleEvents={sampleEvents} />
      <section className="grid gap-5 xl:grid-cols-[.8fr_1.2fr]">
        <PolicyLifecycle />
        <Table>
          <thead>
            <tr className="bg-slate-50">
              <th className="p-3 text-left"><UiText k="Policy" /></th>
              <th className="p-3 text-left"><UiText k="Active" /></th>
              <th className="p-3 text-right"><UiText k="Versions" /></th>
              <th className="p-3 text-right"><UiText k="Rules" /></th>
              <th className="p-3 text-left"><UiText k="Created" /></th>
            </tr>
          </thead>
          <tbody>
            {policies.length > 0 ? (
              policies.map(policy => (
                <tr key={policy.id} className="border-t border-slate-200">
                  <td className="p-3">
                    <div className="font-medium text-slate-950">{policy.name}</div>
                    <div className="text-xs text-slate-500">{policy.description || policy.id}</div>
                  </td>
                  <td className="p-3">
                    {policy.active ? <Badge tone={statusTone(policy.active.status)}>{policy.active.status} <UiText k="v" />{policy.active.version}</Badge> : <Badge><UiText k="No active" /></Badge>}
                  </td>
                  <td className="p-3 text-right text-slate-600">{policy.versions.length}</td>
                  <td className="p-3 text-right text-slate-600">{policy.active?.rules.length ?? 0}</td>
                  <td className="p-3 text-slate-600"><FormattedDate value={policy.created_at} /></td>
                </tr>
              ))
            ) : (
              <tr className="border-t border-slate-200">
                <td className="p-3 text-slate-500" colSpan={5}>
                  <UiText k="No policies" /></td>
              </tr>
            )}
          </tbody>
        </Table>
      </section>
    </SectionPage>
  );
}

export function EventsPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const applicationsQuery = useApplications();
  const agentsQuery = useAgents();
  const policiesQuery = usePolicies();
  const applications = applicationsQuery.data?.items ?? [];
  const agents = agentsQuery.data?.items ?? [];
  const policies = policiesQuery.data?.items ?? [];
  const [eventApplicationID, setEventApplicationID] = useState("");
  const [eventEnvironmentID, setEventEnvironmentID] = useState("");
  const [eventAgentID, setEventAgentID] = useState("");
  const [eventPolicyID, setEventPolicyID] = useState("");
  const [eventSeverity, setEventSeverity] = useState("");
  const [eventHook, setEventHook] = useState("");
  const [eventOccurredAfter, setEventOccurredAfter] = useState("");
  const [eventOccurredBefore, setEventOccurredBefore] = useState("");
  const [eventLimit, setEventLimit] = useState("500");
  const [recycleEventID, setRecycleEventID] = useState("");
  const [recycleMessage, setRecycleMessage] = useState({ status: "", error: "" });
  const [isRecyclingEvent, setIsRecyclingEvent] = useState(false);
  const [dependencyApplicationID, setDependencyApplicationID] = useState("");
  const [dependencyAgentID, setDependencyAgentID] = useState("");
  const [dependencyName, setDependencyName] = useState("");
  const [dependencyEcosystem, setDependencyEcosystem] = useState("");
  const [dependencyVulnerabilitySeverity, setDependencyVulnerabilitySeverity] = useState("");
  const [dependencyObservedAfter, setDependencyObservedAfter] = useState("");
  const [dependencyObservedBefore, setDependencyObservedBefore] = useState("");
  const [dependencyLimit, setDependencyLimit] = useState("500");
  const [dependencyExportMessage, setDependencyExportMessage] = useState({ status: "", error: "" });
  const [isExportingDependencies, setIsExportingDependencies] = useState(false);
  const [baselineApplicationID, setBaselineApplicationID] = useState("");
  const [baselineEnvironmentID, setBaselineEnvironmentID] = useState("");
  const [baselineAgentID, setBaselineAgentID] = useState("");
  const [baselineSeverity, setBaselineSeverity] = useState("");
  const [baselineStatus, setBaselineStatus] = useState("");
  const [baselineCategory, setBaselineCategory] = useState("");
  const [baselineObservedAfter, setBaselineObservedAfter] = useState("");
  const [baselineObservedBefore, setBaselineObservedBefore] = useState("");
  const [baselineLimit, setBaselineLimit] = useState("500");
  const selectedEventApplication = applications.find(application => application.id === eventApplicationID);
  const eventAgents = eventApplicationID ? agents.filter(agent => agent.application_id === eventApplicationID) : agents;
  const eventEnvironmentOptions = Array.from(
    new Set([
      ...(selectedEventApplication ? selectedEventApplication.environment_ids : applications.flatMap(application => application.environment_ids)),
      ...eventAgents.map(agent => agent.environment_id)
    ])
  ).sort();
  const eventQuery: SecurityEventQuery = {
    application_id: eventApplicationID || undefined,
    environment_id: eventEnvironmentID || undefined,
    agent_id: eventAgentID || undefined,
    policy_id: eventPolicyID || undefined,
    severity: eventSeverity || undefined,
    hook: eventHook.trim() || undefined,
    occurred_after: eventDateTimeQueryValue(eventOccurredAfter),
    occurred_before: eventDateTimeQueryValue(eventOccurredBefore),
    limit: eventLimit ? Number(eventLimit) : undefined
  };
  const dependencyAgents = dependencyApplicationID ? agents.filter(agent => agent.application_id === dependencyApplicationID) : agents;
  const selectedBaselineApplication = applications.find(application => application.id === baselineApplicationID);
  const baselineAgents = baselineApplicationID ? agents.filter(agent => agent.application_id === baselineApplicationID) : agents;
  const baselineEnvironmentOptions = Array.from(
    new Set([
      ...(selectedBaselineApplication ? selectedBaselineApplication.environment_ids : applications.flatMap(application => application.environment_ids)),
      ...baselineAgents.map(agent => agent.environment_id)
    ])
  ).sort();
  const dependencyQuery: DependencyQuery = {
    application_id: dependencyApplicationID || undefined,
    agent_id: dependencyAgentID || undefined,
    name: dependencyName.trim() || undefined,
    ecosystem: dependencyEcosystem.trim() || undefined,
    vulnerability_severity: dependencyVulnerabilitySeverity || undefined,
    observed_after: eventDateTimeQueryValue(dependencyObservedAfter),
    observed_before: eventDateTimeQueryValue(dependencyObservedBefore),
    limit: dependencyLimit ? Number(dependencyLimit) : undefined
  };
  const baselineQuery: BaselineFindingQuery = {
    application_id: baselineApplicationID || undefined,
    environment_id: baselineEnvironmentID || undefined,
    agent_id: baselineAgentID || undefined,
    severity: baselineSeverity || undefined,
    status: baselineStatus || undefined,
    category: baselineCategory.trim() || undefined,
    observed_after: eventDateTimeQueryValue(baselineObservedAfter),
    observed_before: eventDateTimeQueryValue(baselineObservedBefore),
    limit: baselineLimit ? Number(baselineLimit) : undefined
  };
  const attackQuery = useAttackEvents(eventQuery);
  const hookQuery = useSecurityEvents("hook", eventQuery);
  const performanceQuery = useSecurityEvents("performance", eventQuery);
  const crashQuery = useSecurityEvents("crash", eventQuery);
  const deletedEventsQuery = useDeletedSecurityEvents(eventQuery);
  const dependenciesQuery = useDependencies(dependencyQuery);
  const dependencySummaryQuery = useDependencySummary();
  const baselineFindingsQuery = useBaselineFindings(baselineQuery);
  const attackEvents = attackQuery.data?.items ?? [];
  const hookEvents = hookQuery.data?.items ?? [];
  const performanceEvents = performanceQuery.data?.items ?? [];
  const crashEvents = crashQuery.data?.items ?? [];
  const deletedEvents = deletedEventsQuery.data?.items ?? [];
  const dependencies = dependenciesQuery.data?.items ?? [];
  const dependencySummary = dependencySummaryQuery.data ?? {
    dependency_count: 0,
    vulnerable_dependency_count: 0,
    known_exploited_count: 0,
    dependencies_by_ecosystem: {},
    vulnerabilities_by_severity: {}
  };
  const baselineFindings = baselineFindingsQuery.data?.items ?? [];
  const allEvents = [...attackEvents, ...hookEvents, ...performanceEvents, ...crashEvents].sort((a, b) => Date.parse(b.occurred_at) - Date.parse(a.occurred_at));
  const recycleEventOptions = uniqueEventsByID([...allEvents, ...deletedEvents]).sort((a, b) => Date.parse(b.occurred_at) - Date.parse(a.occurred_at));
  const recycleEventIDs = recycleEventOptions.map(event => event.id).join("|");
  const criticalEvents = allEvents.filter(event => event.severity === "critical").length;
  const highEvents = allEvents.filter(event => event.severity === "high").length;
  const failedBaselineFindings = baselineFindings.filter(finding => finding.status === "failed" || finding.status === "warning").length;

  useEffect(() => {
    if (recycleEventOptions.length === 0) {
      setRecycleEventID("");
      return;
    }
    if (!recycleEventID || !recycleEventOptions.some(event => event.id === recycleEventID)) {
      setRecycleEventID(recycleEventOptions[0].id);
    }
  }, [recycleEventID, recycleEventIDs]);

  async function handleRecycleAction(action: "delete" | "restore" | "purge") {
    setRecycleMessage({ status: "", error: "" });
    if (!recycleEventID) {
      setRecycleMessage({ status: "", error: notice("Choose an event first.") });
      return;
    }
    setIsRecyclingEvent(true);
    try {
      const report =
        action === "delete"
          ? await moveEventsToRecycleBin([recycleEventID])
          : action === "restore"
            ? await restoreEventsFromRecycleBin([recycleEventID])
            : await purgeEventsFromRecycleBin([recycleEventID]);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["events"] }),
        queryClient.invalidateQueries({ queryKey: ["overview"] }),
        queryClient.invalidateQueries({ queryKey: ["alert-deliveries"] }),
        queryClient.invalidateQueries({ queryKey: ["audit-logs"] })
      ]);
      const messageKey =
        action === "delete"
          ? report.count === 1
            ? "Moved {{count}} event."
            : "Moved {{count}} events."
          : action === "restore"
            ? report.count === 1
              ? "Restored {{count}} event."
              : "Restored {{count}} events."
            : report.count === 1
              ? "Purged {{count}} event."
              : "Purged {{count}} events.";
      setRecycleMessage({ status: notice(messageKey, { count: report.count }), error: "" });
    } catch {
      setRecycleMessage({ status: "", error: notice("Unable to update the event recycle bin.") });
    } finally {
      setIsRecyclingEvent(false);
    }
  }

  const clearEventFilters = () => {
    setEventApplicationID("");
    setEventEnvironmentID("");
    setEventAgentID("");
    setEventPolicyID("");
    setEventSeverity("");
    setEventHook("");
    setEventOccurredAfter("");
    setEventOccurredBefore("");
    setEventLimit("500");
  };
  const clearDependencyFilters = () => {
    setDependencyApplicationID("");
    setDependencyAgentID("");
    setDependencyName("");
    setDependencyEcosystem("");
    setDependencyVulnerabilitySeverity("");
    setDependencyObservedAfter("");
    setDependencyObservedBefore("");
    setDependencyLimit("500");
  };
  const clearBaselineFilters = () => {
    setBaselineApplicationID("");
    setBaselineEnvironmentID("");
    setBaselineAgentID("");
    setBaselineSeverity("");
    setBaselineStatus("");
    setBaselineCategory("");
    setBaselineObservedAfter("");
    setBaselineObservedBefore("");
    setBaselineLimit("500");
  };

  async function handleDependencyExport() {
    setDependencyExportMessage({ status: "", error: "" });
    setIsExportingDependencies(true);
    try {
      const exported = await exportDependencies();
      const blob = new Blob([JSON.stringify(exported, null, 2)], { type: "application/json" });
      triggerBrowserDownload(blob, `ohmyrasp-dependencies-${new Date().toISOString().slice(0, 10)}.json`);
      setDependencyExportMessage({ status: notice("Exported {{count}} dependencies.", { count: exported.items.length }), error: "" });
    } catch {
      setDependencyExportMessage({ status: "", error: notice("Unable to export dependencies.") });
    } finally {
      setIsExportingDependencies(false);
    }
  }

  return (
    <SectionPage
      title={t("pages.events.title")}
      summary={t("pages.events.summary")}
    >
      <QueryStateNotice
        isLoading={
          applicationsQuery.isLoading ||
          agentsQuery.isLoading ||
          policiesQuery.isLoading ||
          attackQuery.isLoading ||
          hookQuery.isLoading ||
          performanceQuery.isLoading ||
          crashQuery.isLoading ||
          dependenciesQuery.isLoading ||
          dependencySummaryQuery.isLoading ||
          baselineFindingsQuery.isLoading
        }
        isError={
          applicationsQuery.isError ||
          agentsQuery.isError ||
          policiesQuery.isError ||
          attackQuery.isError ||
          hookQuery.isError ||
          performanceQuery.isError ||
          crashQuery.isError ||
          dependenciesQuery.isError ||
          dependencySummaryQuery.isError ||
          baselineFindingsQuery.isError
        }
        loading={<UiText k="Loading event and inventory data." />}
        error={<UiText k="Some event or inventory data is unavailable." />}
      />
      <div className="grid gap-3 md:grid-cols-4">
        <Metric label={<UiText k="Security Events" />} value={allEvents.length} detail={<UiText k="attack, Hook, performance, crash" />} />
        <Metric label={<UiText k="Critical" />} value={criticalEvents} detail={<UiText k="requires immediate review" />} />
        <Metric label={<UiText k="Dependencies" />} value={dependencies.length} detail={<UiText k="{{count}} high event signals" values={{ count: highEvents }} />} />
        <Metric label={<UiText k="Baseline Findings" />} value={baselineFindings.length} detail={<UiText k="{{count}} open posture signals" values={{ count: failedBaselineFindings }} />} />
      </div>
      <Card>
        <CardHeader>
          <CardTitle><UiText k="Event Query" /></CardTitle>
        </CardHeader>
        <CardContent className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <label className={fieldGroupClass} htmlFor="event-application">
            <span className={fieldLabelClass}><UiText k="Event Application" /></span>
            <select
              id="event-application"
              className={fieldControlClass}
              value={eventApplicationID}
              onChange={event => {
                setEventApplicationID(event.target.value);
                setEventEnvironmentID("");
                setEventAgentID("");
              }}
            >
              <option value=""><UiText k="All Applications" /></option>
              {applications.map(application => (
                <option key={application.id} value={application.id}>
                  {application.name}
                </option>
              ))}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="event-environment">
            <span className={fieldLabelClass}><UiText k="Event Environment" /></span>
            <select id="event-environment" className={fieldControlClass} value={eventEnvironmentID} onChange={event => setEventEnvironmentID(event.target.value)}>
              <option value=""><UiText k="All Environments" /></option>
              {eventEnvironmentOptions.map(environmentID => (
                <option key={environmentID} value={environmentID}>
                  {environmentID}
                </option>
              ))}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="event-agent">
            <span className={fieldLabelClass}><UiText k="Event Agent" /></span>
            <select id="event-agent" className={fieldControlClass} value={eventAgentID} onChange={event => setEventAgentID(event.target.value)}>
              <option value=""><UiText k="All Agents" /></option>
              {eventAgents.map(agent => (
                <option key={agent.id} value={agent.id}>
                  {agent.hostname}
                </option>
              ))}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="event-policy">
            <span className={fieldLabelClass}><UiText k="Event Policy" /></span>
            <select id="event-policy" className={fieldControlClass} value={eventPolicyID} onChange={event => setEventPolicyID(event.target.value)}>
              <option value=""><UiText k="All Policies" /></option>
              {policies.map(policy => (
                <option key={policy.id} value={policy.id}>
                  {policy.name}
                </option>
              ))}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="event-severity">
            <span className={fieldLabelClass}><UiText k="Event Severity" /></span>
            <select id="event-severity" className={fieldControlClass} value={eventSeverity} onChange={event => setEventSeverity(event.target.value)}>
              <option value=""><UiText k="All Severities" /></option>
              <option value="critical"><UiText k="critical" /></option>
              <option value="high"><UiText k="high" /></option>
              <option value="medium"><UiText k="medium" /></option>
              <option value="low"><UiText k="low" /></option>
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="event-hook">
            <span className={fieldLabelClass}><UiText k="Event Hook" /></span>
            <input id="event-hook" className={fieldControlClass} value={eventHook} onChange={event => setEventHook(event.target.value)} />
          </label>
          <label className={fieldGroupClass} htmlFor="event-occurred-after">
            <span className={fieldLabelClass}><UiText k="Occurred After" /></span>
            <input
              id="event-occurred-after"
              className={fieldControlClass}
              type="datetime-local"
              value={eventOccurredAfter}
              onChange={event => setEventOccurredAfter(event.target.value)}
            />
          </label>
          <label className={fieldGroupClass} htmlFor="event-occurred-before">
            <span className={fieldLabelClass}><UiText k="Occurred Before" /></span>
            <input
              id="event-occurred-before"
              className={fieldControlClass}
              type="datetime-local"
              value={eventOccurredBefore}
              onChange={event => setEventOccurredBefore(event.target.value)}
            />
          </label>
          <label className={fieldGroupClass} htmlFor="event-limit">
            <span className={fieldLabelClass}><UiText k="Event Limit" /></span>
            <input
              id="event-limit"
              className={fieldControlClass}
              min="1"
              max="1000"
              type="number"
              value={eventLimit}
              onChange={event => setEventLimit(event.target.value)}
            />
          </label>
          <div className="flex items-end">
            <Button className="w-full" type="button" variant="secondary" onClick={clearEventFilters}>
              <UiText k="Clear Filters" /></Button>
          </div>
        </CardContent>
      </Card>
      <section className="grid gap-5 xl:grid-cols-[.8fr_1.2fr]">
        <Table>
          <thead>
            <tr className="bg-slate-50">
              <th className="p-3 text-left"><UiText k="Event" /></th>
              <th className="p-3 text-left"><UiText k="Storage" /></th>
              <th className="p-3 text-left"><UiText k="Use" /></th>
            </tr>
          </thead>
          <tbody>
            {eventPipelines.map(pipeline => (
              <tr key={pipeline.type} className="border-t border-slate-200">
                <td className="p-3 font-medium">{pipeline.type}</td>
                <td className="p-3 text-slate-600">{pipeline.target}</td>
                <td className="p-3 text-slate-600">{pipeline.retention}</td>
              </tr>
            ))}
          </tbody>
        </Table>
        <Table>
          <thead>
            <tr className="bg-slate-50">
              <th className="p-3 text-left"><UiText k="Type" /></th>
              <th className="p-3 text-left"><UiText k="Message" /></th>
              <th className="p-3 text-left"><UiText k="Hook" /></th>
              <th className="p-3 text-left"><UiText k="Severity" /></th>
              <th className="p-3 text-left"><UiText k="Occurred" /></th>
            </tr>
          </thead>
          <tbody>
            {allEvents.length > 0 ? (
              allEvents.map(event => (
                <tr key={event.id} className="border-t border-slate-200">
                  <td className="p-3">
                    <Badge tone={eventTypeTone(event.type)}>{event.type}</Badge>
                  </td>
                  <td className="p-3">
                    <div className="font-medium">{event.message}</div>
                    <div className="mt-1 max-w-xl text-xs text-slate-500">
                      {event.id} / <UiText k="Algorithm" />: {event.algorithm || translateUiCopy(appI18n.resolvedLanguage ?? appI18n.language, "unknown")}
                      {event.policy_id ? ` / policy: ${event.policy_id} v${event.policy_version ?? 0}` : ""}
                    </div>
                    <div className="mt-1 max-w-xl truncate text-xs text-slate-500" title={formatDetails(event.attributes)}>
                      <UiText k="Attack Parameters" />: {formatDetails(event.attributes)}
                    </div>
                  </td>
                  <td className="p-3 text-slate-600">{event.hook || <UiText k="unknown" />}</td>
                  <td className="p-3">
                    <Badge tone={severityTone(event.severity)}>{event.severity}</Badge>
                  </td>
                  <td className="p-3 text-slate-600"><FormattedDate value={event.occurred_at} /></td>
                </tr>
              ))
            ) : (
              <tr className="border-t border-slate-200">
                <td className="p-3 text-slate-500" colSpan={5}>
                  <UiText k="No security events" /></td>
              </tr>
            )}
          </tbody>
        </Table>
      </section>
      <Card className="overflow-hidden">
        <CardHeader>
          <CardTitle><UiText k="Event Recycle Bin" /></CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4">
          <div className="grid gap-3 md:grid-cols-[1fr_auto_auto_auto] md:items-end">
            <label className={fieldGroupClass} htmlFor="event-recycle-id">
              <span className={fieldLabelClass}><UiText k="Recycle Event ID" /></span>
              <select
                id="event-recycle-id"
                className={fieldControlClass}
                disabled={recycleEventOptions.length === 0}
                value={recycleEventID}
                onChange={event => setRecycleEventID(event.target.value)}
              >
                {recycleEventOptions.length > 0 ? (
                  recycleEventOptions.map(event => (
                    <option key={event.id} value={event.id}>
                      {event.id} / {event.type} / {event.deleted_at ? translateUiCopy(appI18n.resolvedLanguage ?? appI18n.language, "deleted") : translateUiCopy(appI18n.resolvedLanguage ?? appI18n.language, "active")}
                    </option>
                  ))
                ) : (
                  <option value=""><UiText k="No events" /></option>
                )}
              </select>
            </label>
            <Button disabled={isRecyclingEvent || !recycleEventID} type="button" variant="secondary" onClick={() => void handleRecycleAction("delete")}>
              <UiText k="Move Event To Recycle Bin" /></Button>
            <Button disabled={isRecyclingEvent || !recycleEventID} type="button" variant="secondary" onClick={() => void handleRecycleAction("restore")}>
              <UiText k="Restore Event" /></Button>
            <Button disabled={isRecyclingEvent || !recycleEventID} type="button" onClick={() => void handleRecycleAction("purge")}>
              <UiText k="Permanently Delete Event" /></Button>
          </div>
          <FormMessage error={recycleMessage.error} status={recycleMessage.status} />
          <Table className="rounded-none border-0">
            <thead>
              <tr className="bg-slate-50">
                <th className="p-3 text-left"><UiText k="Type" /></th>
                <th className="p-3 text-left"><UiText k="Message" /></th>
                <th className="p-3 text-left"><UiText k="Deleted" /></th>
                <th className="p-3 text-left"><UiText k="Deleted By" /></th>
              </tr>
            </thead>
            <tbody>
              {deletedEvents.length > 0 ? (
                deletedEvents.map(event => (
                  <tr key={event.id} className="border-t border-slate-200">
                    <td className="p-3">
                      <Badge tone={eventTypeTone(event.type)}>{event.type}</Badge>
                    </td>
                    <td className="p-3">
                      <div className="font-medium">{event.message}</div>
                      <div className="text-xs text-slate-500">{event.id}</div>
                      <div className="mt-1 max-w-xl truncate text-xs text-slate-500" title={formatDetails(event.attributes)}>
                        <UiText k="Attack Parameters" />: {formatDetails(event.attributes)}
                      </div>
                    </td>
                    <td className="p-3 text-slate-600"><FormattedDate value={event.deleted_at} /></td>
                    <td className="p-3 text-slate-600">{event.deleted_by || <UiText k="unknown" />}</td>
                  </tr>
                ))
              ) : (
                <tr className="border-t border-slate-200">
                  <td className="p-3 text-slate-500" colSpan={4}>
                    <UiText k="No deleted events" /></td>
                </tr>
              )}
            </tbody>
          </Table>
        </CardContent>
      </Card>
      <section className="grid gap-5">
        <Card className="overflow-hidden">
          <CardHeader className="flex flex-wrap items-center justify-between gap-3">
            <CardTitle><UiText k="Dependency Inventory" /></CardTitle>
            <Button disabled={isExportingDependencies} type="button" variant="secondary" onClick={() => void handleDependencyExport()}>
              <Download className="h-4 w-4" />
              <UiText k={isExportingDependencies ? "Exporting Dependencies" : "Export Dependencies"} />
            </Button>
          </CardHeader>
          <CardContent className="p-0">
            <div className="grid gap-3 border-b border-slate-200 p-4 md:grid-cols-3 xl:grid-cols-5">
              <div className="rounded-md border border-slate-200 px-3 py-2">
                <div className="text-xs text-slate-500"><UiText k="Dependencies" /></div>
                <div className="mt-1 text-lg font-semibold tabular-nums text-slate-950">{formatNumber(dependencySummary.dependency_count)}</div>
              </div>
              <div className="rounded-md border border-slate-200 px-3 py-2">
                <div className="text-xs text-slate-500"><UiText k="Vulnerable Dependencies" /></div>
                <div className="mt-1 text-lg font-semibold tabular-nums text-slate-950">{formatNumber(dependencySummary.vulnerable_dependency_count)}</div>
              </div>
              <div className="rounded-md border border-slate-200 px-3 py-2">
                <div className="text-xs text-slate-500"><UiText k="Known Exploited" /></div>
                <div className="mt-1 text-lg font-semibold tabular-nums text-slate-950">{formatNumber(dependencySummary.known_exploited_count)}</div>
              </div>
              <div className="rounded-md border border-slate-200 px-3 py-2 xl:col-span-2">
                <div className="text-xs text-slate-500"><UiText k="Top Ecosystems" /></div>
                <div className="mt-1 truncate text-sm font-medium text-slate-950">
                  {topEntries(dependencySummary.dependencies_by_ecosystem, 3).map(([name, count]) => `${name} ${formatNumber(count)}`).join(" / ") || <UiText k="No samples" />}
                </div>
              </div>
            </div>
            <div className="border-b border-slate-200 px-4 py-3">
              <FormMessage error={dependencyExportMessage.error} status={dependencyExportMessage.status} />
            </div>
            <div className="grid gap-3 border-b border-slate-200 p-4 md:grid-cols-2 xl:grid-cols-4">
              <label className={fieldGroupClass} htmlFor="dependency-application">
                <span className={fieldLabelClass}><UiText k="Dependency Application" /></span>
                <select
                  id="dependency-application"
                  className={fieldControlClass}
                  value={dependencyApplicationID}
                  onChange={event => {
                    setDependencyApplicationID(event.target.value);
                    setDependencyAgentID("");
                  }}
                >
                  <option value=""><UiText k="All Applications" /></option>
                  {applications.map(application => (
                    <option key={application.id} value={application.id}>
                      {application.name}
                    </option>
                  ))}
                </select>
              </label>
              <label className={fieldGroupClass} htmlFor="dependency-agent">
                <span className={fieldLabelClass}><UiText k="Dependency Agent" /></span>
                <select id="dependency-agent" className={fieldControlClass} value={dependencyAgentID} onChange={event => setDependencyAgentID(event.target.value)}>
                  <option value=""><UiText k="All Agents" /></option>
                  {dependencyAgents.map(agent => (
                    <option key={agent.id} value={agent.id}>
                      {agent.hostname}
                    </option>
                  ))}
                </select>
              </label>
              <label className={fieldGroupClass} htmlFor="dependency-name">
                <span className={fieldLabelClass}><UiText k="Dependency Name" /></span>
                <input id="dependency-name" className={fieldControlClass} value={dependencyName} onChange={event => setDependencyName(event.target.value)} />
              </label>
              <label className={fieldGroupClass} htmlFor="dependency-ecosystem">
                <span className={fieldLabelClass}><UiText k="Dependency Ecosystem" /></span>
                <input id="dependency-ecosystem" className={fieldControlClass} value={dependencyEcosystem} onChange={event => setDependencyEcosystem(event.target.value)} />
              </label>
              <label className={fieldGroupClass} htmlFor="dependency-vulnerability-severity">
                <span className={fieldLabelClass}><UiText k="Dependency Severity" /></span>
                <select
                  id="dependency-vulnerability-severity"
                  className={fieldControlClass}
                  value={dependencyVulnerabilitySeverity}
                  onChange={event => setDependencyVulnerabilitySeverity(event.target.value)}
                >
                  <option value=""><UiText k="All Severities" /></option>
                  <option value="critical"><UiText k="critical" /></option>
                  <option value="high"><UiText k="high" /></option>
                  <option value="medium"><UiText k="medium" /></option>
                  <option value="low"><UiText k="low" /></option>
                </select>
              </label>
              <label className={fieldGroupClass} htmlFor="dependency-observed-after">
                <span className={fieldLabelClass}><UiText k="Observed After" /></span>
                <input
                  id="dependency-observed-after"
                  className={fieldControlClass}
                  type="datetime-local"
                  value={dependencyObservedAfter}
                  onChange={event => setDependencyObservedAfter(event.target.value)}
                />
              </label>
              <label className={fieldGroupClass} htmlFor="dependency-observed-before">
                <span className={fieldLabelClass}><UiText k="Observed Before" /></span>
                <input
                  id="dependency-observed-before"
                  className={fieldControlClass}
                  type="datetime-local"
                  value={dependencyObservedBefore}
                  onChange={event => setDependencyObservedBefore(event.target.value)}
                />
              </label>
              <label className={fieldGroupClass} htmlFor="dependency-limit">
                <span className={fieldLabelClass}><UiText k="Dependency Limit" /></span>
                <input
                  id="dependency-limit"
                  className={fieldControlClass}
                  min="1"
                  max="1000"
                  type="number"
                  value={dependencyLimit}
                  onChange={event => setDependencyLimit(event.target.value)}
                />
              </label>
              <div className="flex items-end">
                <Button className="w-full" type="button" variant="secondary" onClick={clearDependencyFilters}>
                  <UiText k="Clear Dependency Filters" /></Button>
              </div>
            </div>
            <Table className="rounded-none border-0">
              <thead>
                <tr className="bg-slate-50">
                  <th className="p-3 text-left"><UiText k="Dependency" /></th>
                  <th className="p-3 text-left"><UiText k="Version" /></th>
                  <th className="p-3 text-left"><UiText k="Ecosystem" /></th>
                  <th className="p-3 text-left"><UiText k="Licenses" /></th>
                  <th className="p-3 text-left"><UiText k="Vulnerabilities" /></th>
                  <th className="p-3 text-left"><UiText k="Observed" /></th>
                </tr>
              </thead>
              <tbody>
                {dependencies.length > 0 ? (
                  dependencies.map(dep => (
                    <tr key={dep.id} className="border-t border-slate-200">
                      <td className="p-3">
                        <div className="font-medium">{dep.name}</div>
                        <div className="max-w-xs truncate text-xs text-slate-500">{dep.package_path || dep.agent_id || <UiText k="unattributed" />}</div>
                      </td>
                      <td className="p-3 text-slate-600">{dep.version || <UiText k="unknown" />}</td>
                      <td className="p-3 text-slate-600">{dep.ecosystem || <UiText k="unknown" />}</td>
                      <td className="p-3 text-slate-600">{dep.licenses?.length ? dep.licenses.join(", ") : <UiText k="unknown" />}</td>
                      <td className="p-3">
                        <div className="flex flex-wrap gap-1">
                          {dep.vulnerabilities?.length ? (
                            dep.vulnerabilities.slice(0, 3).map(vulnerability => (
                              <Badge key={`${dep.id}-${vulnerability.id}`} tone={severityTone(vulnerability.severity)}>
                                {vulnerability.id}
                              </Badge>
                            ))
                          ) : (
                            <span className="text-slate-500"><UiText k="none" /></span>
                          )}
                        </div>
                      </td>
                      <td className="p-3 text-slate-600"><FormattedDate value={dep.observed_at} /></td>
                    </tr>
                  ))
                ) : (
                  <tr className="border-t border-slate-200">
                    <td className="p-3 text-slate-500" colSpan={6}>
                      <UiText k="No dependency observations" /></td>
                  </tr>
                )}
              </tbody>
            </Table>
          </CardContent>
        </Card>
      </section>
      <section className="grid gap-5">
        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle><UiText k="Baseline Findings" /></CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="grid gap-3 border-b border-slate-200 p-4 md:grid-cols-2 xl:grid-cols-4">
              <label className={fieldGroupClass} htmlFor="baseline-application">
                <span className={fieldLabelClass}><UiText k="Baseline Application" /></span>
                <select
                  id="baseline-application"
                  className={fieldControlClass}
                  value={baselineApplicationID}
                  onChange={event => {
                    setBaselineApplicationID(event.target.value);
                    setBaselineEnvironmentID("");
                    setBaselineAgentID("");
                  }}
                >
                  <option value=""><UiText k="All Applications" /></option>
                  {applications.map(application => (
                    <option key={application.id} value={application.id}>
                      {application.name}
                    </option>
                  ))}
                </select>
              </label>
              <label className={fieldGroupClass} htmlFor="baseline-environment">
                <span className={fieldLabelClass}><UiText k="Baseline Environment" /></span>
                <select id="baseline-environment" className={fieldControlClass} value={baselineEnvironmentID} onChange={event => setBaselineEnvironmentID(event.target.value)}>
                  <option value=""><UiText k="All Environments" /></option>
                  {baselineEnvironmentOptions.map(environmentID => (
                    <option key={environmentID} value={environmentID}>
                      {environmentID}
                    </option>
                  ))}
                </select>
              </label>
              <label className={fieldGroupClass} htmlFor="baseline-agent">
                <span className={fieldLabelClass}><UiText k="Baseline Agent" /></span>
                <select id="baseline-agent" className={fieldControlClass} value={baselineAgentID} onChange={event => setBaselineAgentID(event.target.value)}>
                  <option value=""><UiText k="All Agents" /></option>
                  {baselineAgents.map(agent => (
                    <option key={agent.id} value={agent.id}>
                      {agent.hostname}
                    </option>
                  ))}
                </select>
              </label>
              <label className={fieldGroupClass} htmlFor="baseline-severity">
                <span className={fieldLabelClass}><UiText k="Baseline Severity" /></span>
                <select id="baseline-severity" className={fieldControlClass} value={baselineSeverity} onChange={event => setBaselineSeverity(event.target.value)}>
                  <option value=""><UiText k="All Severities" /></option>
                  <option value="critical"><UiText k="critical" /></option>
                  <option value="high"><UiText k="high" /></option>
                  <option value="medium"><UiText k="medium" /></option>
                  <option value="low"><UiText k="low" /></option>
                  <option value="info"><UiText k="info" /></option>
                </select>
              </label>
              <label className={fieldGroupClass} htmlFor="baseline-status">
                <span className={fieldLabelClass}><UiText k="Baseline Status" /></span>
                <select id="baseline-status" className={fieldControlClass} value={baselineStatus} onChange={event => setBaselineStatus(event.target.value)}>
                  <option value=""><UiText k="All Statuses" /></option>
                  <option value="failed"><UiText k="failed" /></option>
                  <option value="warning"><UiText k="warning" /></option>
                  <option value="passed"><UiText k="passed" /></option>
                  <option value="suppressed"><UiText k="suppressed" /></option>
                </select>
              </label>
              <label className={fieldGroupClass} htmlFor="baseline-category">
                <span className={fieldLabelClass}><UiText k="Baseline Category" /></span>
                <input id="baseline-category" className={fieldControlClass} value={baselineCategory} onChange={event => setBaselineCategory(event.target.value)} />
              </label>
              <label className={fieldGroupClass} htmlFor="baseline-observed-after">
                <span className={fieldLabelClass}><UiText k="Baseline Observed After" /></span>
                <input
                  id="baseline-observed-after"
                  className={fieldControlClass}
                  type="datetime-local"
                  value={baselineObservedAfter}
                  onChange={event => setBaselineObservedAfter(event.target.value)}
                />
              </label>
              <label className={fieldGroupClass} htmlFor="baseline-observed-before">
                <span className={fieldLabelClass}><UiText k="Baseline Observed Before" /></span>
                <input
                  id="baseline-observed-before"
                  className={fieldControlClass}
                  type="datetime-local"
                  value={baselineObservedBefore}
                  onChange={event => setBaselineObservedBefore(event.target.value)}
                />
              </label>
              <label className={fieldGroupClass} htmlFor="baseline-limit">
                <span className={fieldLabelClass}><UiText k="Baseline Limit" /></span>
                <input
                  id="baseline-limit"
                  className={fieldControlClass}
                  min="1"
                  max="1000"
                  type="number"
                  value={baselineLimit}
                  onChange={event => setBaselineLimit(event.target.value)}
                />
              </label>
              <div className="flex items-end">
                <Button className="w-full" type="button" variant="secondary" onClick={clearBaselineFilters}>
                  <UiText k="Clear Baseline Filters" /></Button>
              </div>
            </div>
            <Table className="rounded-none border-0">
              <thead>
                <tr className="bg-slate-50">
                  <th className="p-3 text-left"><UiText k="Finding" /></th>
                  <th className="p-3 text-left"><UiText k="Category" /></th>
                  <th className="p-3 text-left"><UiText k="Severity" /></th>
                  <th className="p-3 text-left"><UiText k="Status" /></th>
                  <th className="p-3 text-left"><UiText k="Resource" /></th>
                  <th className="p-3 text-left"><UiText k="Observed" /></th>
                </tr>
              </thead>
              <tbody>
                {baselineFindings.length > 0 ? (
                  baselineFindings.map(finding => (
                    <tr key={finding.id} className="border-t border-slate-200">
                      <td className="p-3">
                        <div className="font-medium">{finding.title}</div>
                        <div className="text-xs text-slate-500">{finding.check_id}</div>
                        <div className="mt-1 max-w-xl truncate text-xs text-slate-500" title={finding.remediation || formatDetails(finding.attributes)}>
                          <UiText k="Fix Solution" />: {finding.remediation || <UiText k="No remediation" />}
                        </div>
                        <div className="mt-1 max-w-xl truncate text-xs text-slate-500" title={formatDetails(finding.attributes)}>
                          <UiText k="Baseline Parameters" />: {formatDetails(finding.attributes)}
                        </div>
                      </td>
                      <td className="p-3 text-slate-600">{finding.category ? <UiValue value={finding.category} /> : <UiText k="runtime" />}</td>
                      <td className="p-3">
                        <Badge tone={severityTone(finding.severity)}>{finding.severity}</Badge>
                      </td>
                      <td className="p-3">
                        <Badge tone={baselineStatusTone(finding.status)}>{finding.status}</Badge>
                      </td>
                      <td className="p-3 text-slate-600">{finding.resource || finding.agent_id}</td>
                      <td className="p-3 text-slate-600"><FormattedDate value={finding.observed_at} /></td>
                    </tr>
                  ))
                ) : (
                  <tr className="border-t border-slate-200">
                    <td className="p-3 text-slate-500" colSpan={6}>
                      <UiText k="No baseline findings" /></td>
                  </tr>
                )}
              </tbody>
            </Table>
          </CardContent>
        </Card>
      </section>
    </SectionPage>
  );
}

export function ObservabilityPage() {
  const { t } = useTranslation();
  const applicationsQuery = useApplications();
  const policiesQuery = usePolicies();
  const applications = applicationsQuery.data?.items ?? [];
  const policies = policiesQuery.data?.items ?? [];
  const [observabilityApplicationID, setObservabilityApplicationID] = useState("");
  const [observabilityPolicyID, setObservabilityPolicyID] = useState("");
  const observabilityQuery = useObservability({
    applicationID: observabilityApplicationID || undefined,
    policyID: observabilityPolicyID || undefined
  });
  const report = observabilityQuery.data ?? emptyObservabilityReport();
  const topHook = report.hook_latency[0];
  const topRule = report.rule_overhead[0];
  const topAgent = report.agent_overhead[0];
  const topPolicy = report.policy_performance[0];
  const clearObservabilityFilters = () => {
    setObservabilityApplicationID("");
    setObservabilityPolicyID("");
  };

  return (
    <SectionPage
      title={t("pages.observability.title")}
      summary={t("pages.observability.summary")}
    >
      <QueryStateNotice
        isLoading={applicationsQuery.isLoading || policiesQuery.isLoading || observabilityQuery.isLoading}
        isError={applicationsQuery.isError || policiesQuery.isError || observabilityQuery.isError}
        loading={<UiText k="Loading observability data." />}
        error={<UiText k="Observability data is unavailable." />}
      />
      <div className="grid gap-3 md:grid-cols-4">
        <Metric label={<UiText k="Hook p95" />} value={formatLatency(topHook?.p95_latency_us)} detail={topHook ? <UiText k="{{hook}} hook" values={{ hook: topHook.hook }} /> : <UiText k="no samples" />} />
        <Metric
          label={<UiText k="Rule p95" />}
          value={formatLatency(topRule?.p95_latency_us)}
          detail={topRule ? <UiText k="{{rule}} on {{hook}}" values={{ rule: topRule.rule_id, hook: topRule.hook }} /> : <UiText k="no samples" />}
        />
        <Metric label={<UiText k="Agent CPU" />} value={formatPercent(topAgent?.cpu_overhead_pct)} detail={topAgent ? <UiText k="{{agent}} median" values={{ agent: topAgent.agent_id }} /> : <UiText k="no samples" />} />
        <Metric
          label={<UiText k="Rule Eval" />}
          value={formatLatency(topPolicy?.rule_eval_p95_us)}
          detail={topPolicy ? <UiText k="{{policy}} v{{version}}" values={{ policy: topPolicy.policy_id, version: topPolicy.policy_version }} /> : <UiText k="no samples" />}
        />
      </div>
      <Card>
        <CardHeader>
          <CardTitle><UiText k="Observability Filters" /></CardTitle>
        </CardHeader>
        <CardContent className="grid gap-3 md:grid-cols-3">
          <label className={fieldGroupClass} htmlFor="observability-application">
            <span className={fieldLabelClass}><UiText k="Observability Application" /></span>
            <select
              id="observability-application"
              className={fieldControlClass}
              value={observabilityApplicationID}
              onChange={event => setObservabilityApplicationID(event.target.value)}
            >
              <option value=""><UiText k="All Applications" /></option>
              {applications.map(application => (
                <option key={application.id} value={application.id}>
                  {application.name}
                </option>
              ))}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="observability-policy">
            <span className={fieldLabelClass}><UiText k="Observability Policy" /></span>
            <select id="observability-policy" className={fieldControlClass} value={observabilityPolicyID} onChange={event => setObservabilityPolicyID(event.target.value)}>
              <option value=""><UiText k="All Policies" /></option>
              {policies.map(policy => (
                <option key={policy.id} value={policy.id}>
                  {policy.name}
                </option>
              ))}
            </select>
          </label>
          <div className="flex items-end">
            <Button className="w-full" type="button" variant="secondary" onClick={clearObservabilityFilters}>
              <UiText k="Clear Observability Filters" /></Button>
          </div>
        </CardContent>
      </Card>
      <div className="grid gap-5 xl:grid-cols-2">
        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle><UiText k="Rule Overhead" /></CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table className="rounded-none border-0">
              <thead>
                <tr className="bg-slate-50">
                  <th className="p-3 text-left"><UiText k="Rule" /></th>
                  <th className="p-3 text-left"><UiText k="Hook" /></th>
                  <th className="p-3 text-right"><UiText k="Exec" /></th>
                  <th className="p-3 text-right"><UiText k="Blocked" /></th>
                  <th className="p-3 text-right"><UiText k="p95" /></th>
                </tr>
              </thead>
              <tbody>
                {report.rule_overhead.length > 0 ? (
                  report.rule_overhead.map(row => (
                    <tr key={`${row.policy_id}-${row.policy_version}-${row.rule_id}-${row.hook}`} className="border-t border-slate-200">
                      <td className="p-3 font-medium">{row.rule_id}</td>
                      <td className="p-3 text-slate-600">{row.hook}</td>
                      <td className="p-3 text-right text-slate-600">{formatNumber(row.executions)}</td>
                      <td className="p-3 text-right text-slate-600">{formatNumber(row.blocked)}</td>
                      <td className="p-3 text-right text-slate-600">{formatLatency(row.p95_latency_us)}</td>
                    </tr>
                  ))
                ) : (
                  <tr className="border-t border-slate-200">
                    <td className="p-3 text-slate-500" colSpan={5}>
                      <UiText k="No samples" /></td>
                  </tr>
                )}
              </tbody>
            </Table>
          </CardContent>
        </Card>

        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle><UiText k="Hook Latency" /></CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table className="rounded-none border-0">
              <thead>
                <tr className="bg-slate-50">
                  <th className="p-3 text-left"><UiText k="Hook" /></th>
                  <th className="p-3 text-right"><UiText k="Calls" /></th>
                  <th className="p-3 text-right"><UiText k="Avg" /></th>
                  <th className="p-3 text-right"><UiText k="p95" /></th>
                  <th className="p-3 text-right"><UiText k="Max" /></th>
                </tr>
              </thead>
              <tbody>
                {report.hook_latency.length > 0 ? (
                  report.hook_latency.map(row => (
                    <tr key={row.hook} className="border-t border-slate-200">
                      <td className="p-3 font-medium">{row.hook}</td>
                      <td className="p-3 text-right text-slate-600">{formatNumber(row.calls)}</td>
                      <td className="p-3 text-right text-slate-600">{formatLatency(row.average_latency_us)}</td>
                      <td className="p-3 text-right text-slate-600">{formatLatency(row.p95_latency_us)}</td>
                      <td className="p-3 text-right text-slate-600">{formatLatency(row.max_latency_us)}</td>
                    </tr>
                  ))
                ) : (
                  <tr className="border-t border-slate-200">
                    <td className="p-3 text-slate-500" colSpan={5}>
                      <UiText k="No samples" /></td>
                  </tr>
                )}
              </tbody>
            </Table>
          </CardContent>
        </Card>

        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle><UiText k="Agent Overhead" /></CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table className="rounded-none border-0">
              <thead>
                <tr className="bg-slate-50">
                  <th className="p-3 text-left"><UiText k="Agent" /></th>
                  <th className="p-3 text-right"><UiText k="Samples" /></th>
                  <th className="p-3 text-right"><UiText k="CPU" /></th>
                  <th className="p-3 text-right"><UiText k="Memory" /></th>
                  <th className="p-3 text-right"><UiText k="Rule p95" /></th>
                </tr>
              </thead>
              <tbody>
                {report.agent_overhead.length > 0 ? (
                  report.agent_overhead.map(row => (
                    <tr key={row.agent_id} className="border-t border-slate-200">
                      <td className="p-3 font-medium">{row.agent_id}</td>
                      <td className="p-3 text-right text-slate-600">{formatNumber(row.samples)}</td>
                      <td className="p-3 text-right text-slate-600">{formatPercent(row.cpu_overhead_pct)}</td>
                      <td className="p-3 text-right text-slate-600">{formatBytes(row.memory_overhead_bytes)}</td>
                      <td className="p-3 text-right text-slate-600">{formatLatency(row.rule_eval_p95_us)}</td>
                    </tr>
                  ))
                ) : (
                  <tr className="border-t border-slate-200">
                    <td className="p-3 text-slate-500" colSpan={5}>
                      <UiText k="No samples" /></td>
                  </tr>
                )}
              </tbody>
            </Table>
          </CardContent>
        </Card>

        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle><UiText k="Policy Impact" /></CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table className="rounded-none border-0">
              <thead>
                <tr className="bg-slate-50">
                  <th className="p-3 text-left"><UiText k="Policy" /></th>
                  <th className="p-3 text-right"><UiText k="Version" /></th>
                  <th className="p-3 text-right"><UiText k="Samples" /></th>
                  <th className="p-3 text-right"><UiText k="CPU" /></th>
                  <th className="p-3 text-right"><UiText k="Hook p95" /></th>
                </tr>
              </thead>
              <tbody>
                {report.policy_performance.length > 0 ? (
                  report.policy_performance.map(row => (
                    <tr key={`${row.policy_id}-${row.policy_version}`} className="border-t border-slate-200">
                      <td className="p-3 font-medium">{row.policy_id}</td>
                      <td className="p-3 text-right text-slate-600">{row.policy_version}</td>
                      <td className="p-3 text-right text-slate-600">{formatNumber(row.samples)}</td>
                      <td className="p-3 text-right text-slate-600">{formatPercent(row.cpu_overhead_pct)}</td>
                      <td className="p-3 text-right text-slate-600">{formatLatency(row.hook_latency_p95_us)}</td>
                    </tr>
                  ))
                ) : (
                  <tr className="border-t border-slate-200">
                    <td className="p-3 text-slate-500" colSpan={5}>
                      <UiText k="No samples" /></td>
                  </tr>
                )}
              </tbody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </SectionPage>
  );
}

export function AccessPage() {
  const { t } = useTranslation();
  const auditQuery = useAuditLogs();
  const auditLogs = auditQuery.data?.items ?? [];
  const settingsQuery = useSystemSettings();
  const settings = settingsQuery.data?.items ?? [];
  const editionQuery = useEditionStatus();
  const edition = editionQuery.data ?? emptyEditionStatus();
  const alertRulesQuery = useAlertRules();
  const alertRules = alertRulesQuery.data?.items ?? [];
  const alertDeliveriesQuery = useAlertDeliveries();
  const alertDeliveries = alertDeliveriesQuery.data?.items ?? [];
  const usersQuery = useUsers();
  const users = usersQuery.data?.items ?? [];

  return (
    <SectionPage
      title={t("pages.access.title")}
      summary={t("pages.access.summary")}
    >
      <QueryStateNotice
        isLoading={auditQuery.isLoading || settingsQuery.isLoading || editionQuery.isLoading || alertRulesQuery.isLoading || alertDeliveriesQuery.isLoading || usersQuery.isLoading}
        isError={auditQuery.isError || settingsQuery.isError || editionQuery.isError || alertRulesQuery.isError || alertDeliveriesQuery.isError || usersQuery.isError}
        loading={<UiText k="Loading access and audit data." />}
        error={<UiText k="Some access and audit data is unavailable." />}
      />
      <div className="grid gap-3 md:grid-cols-3">
        {[
          ["Admin", "full system and policy administration"],
          ["Security Engineer", "policy, event, and Agent operations"],
          ["Viewer", "read-only investigation and reporting"]
        ].map(([role, detail]) => (
          <Card key={role}>
            <CardContent>
              <Badge tone="blue">{role}</Badge>
              <p className="mt-3 text-sm leading-6 text-slate-600">{detail}</p>
            </CardContent>
          </Card>
        ))}
      </div>
      <EditionStatusPanel edition={edition} />
      <ProtectionConfigurationPanel settings={settings} />
      <MaintenanceCleanupPanel />
      <AccessWritePanel />
      <AlertRuleLifecyclePanel alertRules={alertRules} />
      <UserLifecyclePanel users={users} />
      <section className="grid gap-5">
        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle><UiText k="User Administration" /></CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table className="rounded-none border-0">
              <thead>
                <tr className="bg-slate-50">
                  <th className="p-3 text-left"><UiText k="User" /></th>
                  <th className="p-3 text-left"><UiText k="Roles" /></th>
                  <th className="p-3 text-left"><UiText k="Status" /></th>
                  <th className="p-3 text-left"><UiText k="Updated" /></th>
                </tr>
              </thead>
              <tbody>
                {users.length > 0 ? (
                  users.map(user => (
                    <tr key={user.id} className="border-t border-slate-200">
                      <td className="p-3">
                        <div className="font-medium text-slate-950">{user.name}</div>
                        <div className="mt-1 text-xs text-slate-500">{user.email}</div>
                      </td>
                      <td className="p-3">
                        <div className="flex flex-wrap gap-1">
                          {user.roles.map(role => (
                            <Badge key={role} tone={role === "admin" ? "blue" : "neutral"}>
                              {formatRole(role)}
                            </Badge>
                          ))}
                        </div>
                      </td>
                      <td className="p-3">
                        <Badge tone={user.disabled_at ? "neutral" : "green"}>
                          <UiText k={user.disabled_at ? "disabled" : "active"} />
                        </Badge>
                      </td>
                      <td className="p-3 text-slate-600"><FormattedDate value={user.updated_at} /></td>
                    </tr>
                  ))
                ) : (
                  <tr className="border-t border-slate-200">
                    <td className="p-3 text-slate-500" colSpan={4}>
                      <UiText k="No users" /></td>
                  </tr>
                )}
              </tbody>
            </Table>
          </CardContent>
        </Card>
      </section>
      <section className="grid gap-5 xl:grid-cols-[.9fr_1.1fr]">
        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle><UiText k="System Settings" /></CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table className="rounded-none border-0">
              <thead>
                <tr className="bg-slate-50">
                  <th className="p-3 text-left"><UiText k="Key" /></th>
                  <th className="p-3 text-left"><UiText k="Value" /></th>
                  <th className="p-3 text-left"><UiText k="Updated" /></th>
                </tr>
              </thead>
              <tbody>
                {settings.length > 0 ? (
                  settings.map(setting => (
                    <tr key={setting.key} className="border-t border-slate-200">
                      <td className="p-3 font-medium">{setting.key}</td>
                      <td className="p-3 text-slate-600">{formatDetails(setting.value)}</td>
                      <td className="p-3 text-slate-600"><FormattedDate value={setting.updated_at} /></td>
                    </tr>
                  ))
                ) : (
                  <tr className="border-t border-slate-200">
                    <td className="p-3 text-slate-500" colSpan={3}>
                      <UiText k="No settings" /></td>
                  </tr>
                )}
              </tbody>
            </Table>
          </CardContent>
        </Card>
        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle><UiText k="Alert Rules" /></CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table className="rounded-none border-0">
              <thead>
                <tr className="bg-slate-50">
                  <th className="p-3 text-left"><UiText k="Rule" /></th>
                  <th className="p-3 text-left"><UiText k="Event" /></th>
                  <th className="p-3 text-left"><UiText k="Severity" /></th>
                  <th className="p-3 text-left"><UiText k="Target" /></th>
                  <th className="p-3 text-left"><UiText k="Status" /></th>
                </tr>
              </thead>
              <tbody>
                {alertRules.length > 0 ? (
                  alertRules.map(rule => (
                    <tr key={rule.id} className="border-t border-slate-200">
                      <td className="p-3">
                        <div className="font-medium text-slate-950">{rule.name}</div>
                        <div className="mt-1 text-xs text-slate-500">{rule.condition}</div>
                      </td>
                      <td className="p-3 text-slate-600">{rule.event_type}</td>
                      <td className="p-3">
                        <Badge tone={severityTone(rule.severity)}>{rule.severity}</Badge>
                      </td>
                      <td className="p-3 text-slate-600">{rule.target}</td>
                      <td className="p-3">
                        <Badge tone={rule.enabled ? "green" : "neutral"}>
                          <UiText k={rule.enabled ? "enabled" : "disabled"} />
                        </Badge>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr className="border-t border-slate-200">
                    <td className="p-3 text-slate-500" colSpan={5}>
                      <UiText k="No alert rules" /></td>
                  </tr>
                )}
              </tbody>
            </Table>
          </CardContent>
        </Card>
      </section>
      <section className="grid gap-5">
        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle><UiText k="Alert Delivery History" /></CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table className="rounded-none border-0">
              <thead>
                <tr className="bg-slate-50">
                  <th className="p-3 text-left"><UiText k="Alert" /></th>
                  <th className="p-3 text-left"><UiText k="Event" /></th>
                  <th className="p-3 text-left"><UiText k="Severity" /></th>
                  <th className="p-3 text-left"><UiText k="Target" /></th>
                  <th className="p-3 text-left"><UiText k="Status" /></th>
                  <th className="p-3 text-left"><UiText k="Created" /></th>
                </tr>
              </thead>
              <tbody>
                {alertDeliveries.length > 0 ? (
                  alertDeliveries.map(delivery => (
                    <tr key={delivery.id} className="border-t border-slate-200">
                      <td className="p-3">
                        <div className="font-medium text-slate-950">{delivery.alert_rule_name}</div>
                        <div className="mt-1 text-xs text-slate-500">{delivery.event_id}</div>
                      </td>
                      <td className="p-3 text-slate-600">{delivery.event_type}</td>
                      <td className="p-3">
                        <Badge tone={severityTone(delivery.severity)}>{delivery.severity}</Badge>
                      </td>
                      <td className="p-3 text-slate-600">{delivery.target}</td>
                      <td className="p-3">
                        <Badge tone={deliveryStatusTone(delivery.status)}>{delivery.status}</Badge>
                      </td>
                      <td className="p-3 text-slate-600"><FormattedDate value={delivery.created_at} /></td>
                    </tr>
                  ))
                ) : (
                  <tr className="border-t border-slate-200">
                    <td className="p-3 text-slate-500" colSpan={6}>
                      <UiText k="No alert deliveries" /></td>
                  </tr>
                )}
              </tbody>
            </Table>
          </CardContent>
        </Card>
      </section>
      <section className="grid gap-5">
        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle><UiText k="Audit Log" /></CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table className="rounded-none border-0">
              <thead>
                <tr className="bg-slate-50">
                  <th className="p-3 text-left"><UiText k="Action" /></th>
                  <th className="p-3 text-left"><UiText k="Actor" /></th>
                  <th className="p-3 text-left"><UiText k="Resource" /></th>
                  <th className="p-3 text-left"><UiText k="Created" /></th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.length > 0 ? (
                  auditLogs.map(log => (
                    <tr key={log.id} className="border-t border-slate-200">
                      <td className="p-3 font-medium">{log.action}</td>
                      <td className="p-3 text-slate-600">{log.actor_id || <UiText k="system" />}</td>
                      <td className="p-3 text-slate-600">{log.resource}</td>
                      <td className="p-3 text-slate-600"><FormattedDate value={log.created_at} /></td>
                    </tr>
                  ))
                ) : (
                  <tr className="border-t border-slate-200">
                    <td className="p-3 text-slate-500" colSpan={4}>
                      <UiText k="No audit logs" /></td>
                  </tr>
                )}
              </tbody>
            </Table>
          </CardContent>
        </Card>
      </section>
    </SectionPage>
  );
}

function EditionStatusPanel({ edition }: { edition: EditionStatus }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle><UiText k="Edition Status" /></CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid gap-4 md:grid-cols-4">
          <div>
            <span className="block text-xs font-medium text-slate-500"><UiText k="Edition" /></span>
            <span className="mt-1 block font-medium text-slate-950">{edition.display_name || <UiText k="Unavailable" />}</span>
          </div>
          <div>
            <span className="block text-xs font-medium text-slate-500"><UiText k="Deployment" /></span>
            <span className="mt-1 block font-medium text-slate-950"><UiValue value={edition.deployment_model} /></span>
          </div>
          <div>
            <span className="block text-xs font-medium text-slate-500"><UiText k="License" /></span>
            <span className="mt-1 block font-medium text-slate-950">
              <UiText k={edition.license_required ? "Required" : "Not required"} />
            </span>
          </div>
          <div>
            <span className="block text-xs font-medium text-slate-500"><UiText k="Enforcement" /></span>
            <Badge className="mt-1" tone={edition.license_enforcement === "none" ? "green" : "amber"}>
              <UiValue value={edition.license_enforcement} />
            </Badge>
          </div>
        </div>
        {edition.note ? <p className="mt-4 text-sm leading-6 text-slate-600">{edition.note}</p> : null}
        {!edition.display_name ? <p className="mt-4 text-sm leading-6 text-slate-600"><UiText k="Edition status is unavailable." /></p> : null}
      </CardContent>
    </Card>
  );
}

function AlertRuleLifecyclePanel({ alertRules }: { alertRules: AlertRule[] }) {
  const queryClient = useQueryClient();
  const [alertRuleID, setAlertRuleID] = useState(alertRules[0]?.id ?? "");
  const selectedRule = alertRules.find(rule => rule.id === alertRuleID) ?? alertRules[0];
  const [name, setName] = useState(selectedRule?.name ?? "");
  const [description, setDescription] = useState(selectedRule?.description ?? "");
  const [eventType, setEventType] = useState(selectedRule?.event_type ?? "attack");
  const [severity, setSeverity] = useState(selectedRule?.severity ?? "critical");
  const [condition, setCondition] = useState(selectedRule?.condition ?? "severity == critical");
  const [target, setTarget] = useState(selectedRule?.target ?? "");
  const [enabled, setEnabled] = useState(selectedRule?.enabled ?? true);
  const [message, setMessage] = useState({ status: "", error: "" });
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!selectedRule && alertRuleID) {
      setAlertRuleID("");
      return;
    }
    if (!alertRuleID && selectedRule) {
      setAlertRuleID(selectedRule.id);
    }
  }, [alertRuleID, selectedRule]);

  useEffect(() => {
    if (!selectedRule) {
      setName("");
      setDescription("");
      setEventType("attack");
      setSeverity("critical");
      setCondition("severity == critical");
      setTarget("");
      setEnabled(true);
      return;
    }
    setName(selectedRule.name);
    setDescription(selectedRule.description);
    setEventType(selectedRule.event_type);
    setSeverity(selectedRule.severity);
    setCondition(selectedRule.condition);
    setTarget(selectedRule.target);
    setEnabled(selectedRule.enabled);
  }, [selectedRule?.id, selectedRule?.updated_at]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage({ status: "", error: "" });
    if (!selectedRule) {
      setMessage({ status: "", error: notice("Choose an alert rule first.") });
      return;
    }
    const trimmedName = name.trim();
    const trimmedTarget = target.trim();
    if (!trimmedName || !trimmedTarget) {
      setMessage({ status: "", error: notice("Alert name and target are required.") });
      return;
    }
    setIsSubmitting(true);
    try {
      const updated = await updateAlertRule(selectedRule.id, {
        name: trimmedName,
        description: description.trim() || undefined,
        enabled,
        event_type: eventType,
        severity,
        condition: condition.trim() || undefined,
        target: trimmedTarget
      });
      await queryClient.invalidateQueries({ queryKey: ["alert-rules"] });
      setMessage({ status: notice("Updated alert rule {{name}}.", { name: updated.name }), error: "" });
    } catch {
      setMessage({ status: "", error: notice("Unable to update alert rule.") });
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle><UiText k="Alert Lifecycle" /></CardTitle>
      </CardHeader>
      <CardContent>
        <form className="grid gap-3 md:grid-cols-2 xl:grid-cols-4" onSubmit={handleSubmit}>
          <label className={fieldGroupClass} htmlFor="alert-lifecycle-rule">
            <span className={fieldLabelClass}><UiText k="Alert Rule" /></span>
            <select
              id="alert-lifecycle-rule"
              className={fieldControlClass}
              disabled={alertRules.length === 0}
              value={selectedRule?.id ?? ""}
              onChange={event => setAlertRuleID(event.target.value)}
            >
              {alertRules.length > 0 ? (
                alertRules.map(rule => (
                  <option key={rule.id} value={rule.id}>
                    {rule.name}
                  </option>
                ))
              ) : (
                <option value=""><UiText k="No alert rules" /></option>
              )}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="alert-lifecycle-name">
            <span className={fieldLabelClass}><UiText k="Alert Name" /></span>
            <input id="alert-lifecycle-name" className={fieldControlClass} value={name} onChange={event => setName(event.target.value)} required />
          </label>
          <label className={fieldGroupClass} htmlFor="alert-lifecycle-event-type">
            <span className={fieldLabelClass}><UiText k="Alert Event Type" /></span>
            <select id="alert-lifecycle-event-type" className={fieldControlClass} value={eventType} onChange={event => setEventType(event.target.value)}>
              <option value="attack"><UiText k="attack" /></option>
              <option value="hook"><UiText k="hook" /></option>
              <option value="performance"><UiText k="performance" /></option>
              <option value="crash"><UiText k="crash" /></option>
              <option value="dependency"><UiText k="dependency" /></option>
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="alert-lifecycle-severity">
            <span className={fieldLabelClass}><UiText k="Alert Severity" /></span>
            <select id="alert-lifecycle-severity" className={fieldControlClass} value={severity} onChange={event => setSeverity(event.target.value)}>
              <option value="critical"><UiText k="critical" /></option>
              <option value="high"><UiText k="high" /></option>
              <option value="medium"><UiText k="medium" /></option>
              <option value="low"><UiText k="low" /></option>
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="alert-lifecycle-description">
            <span className={fieldLabelClass}><UiText k="Alert Description" /></span>
            <input id="alert-lifecycle-description" className={fieldControlClass} value={description} onChange={event => setDescription(event.target.value)} />
          </label>
          <label className={fieldGroupClass} htmlFor="alert-lifecycle-condition">
            <span className={fieldLabelClass}><UiText k="Alert Condition" /></span>
            <input id="alert-lifecycle-condition" className={fieldControlClass} value={condition} onChange={event => setCondition(event.target.value)} />
          </label>
          <label className={fieldGroupClass} htmlFor="alert-lifecycle-target">
            <span className={fieldLabelClass}><UiText k="Alert Target" /></span>
            <input id="alert-lifecycle-target" className={fieldControlClass} value={target} onChange={event => setTarget(event.target.value)} required />
          </label>
          <label className="flex min-h-10 items-center gap-2 text-sm font-medium text-slate-700 xl:mt-6" htmlFor="alert-lifecycle-enabled">
            <input
              id="alert-lifecycle-enabled"
              className="h-4 w-4 rounded border-slate-300 text-slate-900"
              type="checkbox"
              checked={enabled}
              onChange={event => setEnabled(event.target.checked)}
            />
            <UiText k="Enable Alert Rule" /></label>
          <div className="flex flex-wrap items-center gap-3 md:col-span-2 xl:col-span-4">
            <Button disabled={isSubmitting || !selectedRule} type="submit">
              <UiText k={isSubmitting ? "Updating Alert Rule" : "Update Alert Rule"} />
            </Button>
            <div className="min-w-72 flex-1">
              <FormMessage error={message.error} status={message.status} />
            </div>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function UserLifecyclePanel({ users }: { users: User[] }) {
  const queryClient = useQueryClient();
  const [userID, setUserID] = useState(users[0]?.id ?? "");
  const selectedUser = users.find(user => user.id === userID) ?? users[0];
  const [name, setName] = useState(selectedUser?.name ?? "");
  const [role, setRole] = useState<UserRole>((selectedUser?.roles[0] as UserRole | undefined) ?? "viewer");
  const [disabled, setDisabled] = useState(Boolean(selectedUser?.disabled_at));
  const [message, setMessage] = useState({ status: "", error: "" });
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!selectedUser && userID) {
      setUserID("");
      return;
    }
    if (!userID && selectedUser) {
      setUserID(selectedUser.id);
    }
  }, [selectedUser, userID]);

  useEffect(() => {
    if (!selectedUser) {
      setName("");
      setRole("viewer");
      setDisabled(false);
      return;
    }
    setName(selectedUser.name);
    setRole((selectedUser.roles[0] as UserRole | undefined) ?? "viewer");
    setDisabled(Boolean(selectedUser.disabled_at));
  }, [selectedUser?.id, selectedUser?.updated_at, selectedUser?.disabled_at]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage({ status: "", error: "" });
    if (!selectedUser) {
      setMessage({ status: "", error: notice("Choose a user first.") });
      return;
    }
    const trimmedName = name.trim();
    if (!trimmedName) {
      setMessage({ status: "", error: notice("User display name is required.") });
      return;
    }
    setIsSubmitting(true);
    try {
      const updated = await updateUser(selectedUser.id, {
        name: trimmedName,
        roles: [role],
        disabled
      });
      await queryClient.invalidateQueries({ queryKey: ["users"] });
      setMessage({ status: notice("Updated user {{email}}.", { email: updated.email }), error: "" });
    } catch {
      setMessage({ status: "", error: notice("Unable to update user.") });
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle><UiText k="User Lifecycle" /></CardTitle>
      </CardHeader>
      <CardContent>
        <form className="grid gap-3 md:grid-cols-[1.2fr_1fr_.8fr_auto] md:items-end" onSubmit={handleSubmit}>
          <label className={fieldGroupClass} htmlFor="user-lifecycle-user">
            <span className={fieldLabelClass}><UiText k="User Account" /></span>
            <select
              id="user-lifecycle-user"
              className={fieldControlClass}
              disabled={users.length === 0}
              value={selectedUser?.id ?? ""}
              onChange={event => setUserID(event.target.value)}
            >
              {users.length > 0 ? (
                users.map(user => (
                  <option key={user.id} value={user.id}>
                    {user.name}
                  </option>
                ))
              ) : (
                <option value=""><UiText k="No users" /></option>
              )}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="user-lifecycle-name">
            <span className={fieldLabelClass}><UiText k="User Display Name" /></span>
            <input id="user-lifecycle-name" className={fieldControlClass} value={name} onChange={event => setName(event.target.value)} required />
          </label>
          <label className={fieldGroupClass} htmlFor="user-lifecycle-role">
            <span className={fieldLabelClass}><UiText k="User Role" /></span>
            <select id="user-lifecycle-role" className={fieldControlClass} value={role} onChange={event => setRole(event.target.value as UserRole)}>
              <option value="admin"><UiText k="Admin" /></option>
              <option value="security_engineer"><UiText k="Security Engineer" /></option>
              <option value="viewer"><UiText k="Viewer" /></option>
            </select>
          </label>
          <label className="flex min-h-10 items-center gap-2 text-sm font-medium text-slate-700" htmlFor="user-lifecycle-disabled">
            <input
              id="user-lifecycle-disabled"
              className="h-4 w-4 rounded border-slate-300 text-slate-900"
              type="checkbox"
              checked={disabled}
              onChange={event => setDisabled(event.target.checked)}
            />
            <UiText k="Disable User" /></label>
          <div className="flex flex-wrap items-center gap-3 md:col-span-4">
            <Button disabled={isSubmitting || !selectedUser} type="submit">
              <UiText k={isSubmitting ? "Updating User" : "Update User"} />
            </Button>
            <div className="min-w-72 flex-1">
              <FormMessage error={message.error} status={message.status} />
            </div>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function PolicySetCreatePanel() {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [message, setMessage] = useState({ status: "", error: "" });
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage({ status: "", error: "" });
    const trimmedName = name.trim();
    if (!trimmedName) {
      setMessage({ status: "", error: notice("Policy set name is required.") });
      return;
    }
    setIsSubmitting(true);
    try {
      const policy = await createPolicy({
        name: trimmedName,
        description: description.trim() || undefined
      });
      await queryClient.invalidateQueries({ queryKey: ["policies"] });
      setMessage({ status: notice("Created policy set {{name}}.", { name: policy.name }), error: "" });
      setName("");
      setDescription("");
    } catch {
      setMessage({ status: "", error: notice("Unable to create policy set.") });
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle><UiText k="Policy Set" /></CardTitle>
      </CardHeader>
      <CardContent>
        <form className="grid gap-3 md:grid-cols-[1fr_1.4fr_auto] md:items-end" onSubmit={handleSubmit}>
          <label className={fieldGroupClass} htmlFor="policy-set-name">
            <span className={fieldLabelClass}><UiText k="Policy Set Name" /></span>
            <input id="policy-set-name" className={fieldControlClass} value={name} onChange={event => setName(event.target.value)} required />
          </label>
          <label className={fieldGroupClass} htmlFor="policy-set-description">
            <span className={fieldLabelClass}><UiText k="Policy Description" /></span>
            <input id="policy-set-description" className={fieldControlClass} value={description} onChange={event => setDescription(event.target.value)} />
          </label>
          <Button disabled={isSubmitting} type="submit">
            <UiText k={isSubmitting ? "Creating Policy Set" : "Create Policy Set"} />
          </Button>
          <div className="md:col-span-3">
            <FormMessage error={message.error} status={message.status} />
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function PolicyWritePanel({ applications, policies, sampleEvents }: { applications: Application[]; policies: PolicySet[]; sampleEvents: SecurityEvent[] }) {
  const queryClient = useQueryClient();
  const { copy } = useUiCopy();
  const [policyID, setPolicyID] = useState(policies[0]?.id ?? "");
  const [ruleName, setRuleName] = useState("");
  const [hook, setHook] = useState("process");
  const [expression, setExpression] = useState("");
  const [action, setAction] = useState("block");
  const [severity, setSeverity] = useState("high");
  const [tags, setTags] = useState("");
  const [targetVersion, setTargetVersion] = useState(1);
  const [canaryPercent, setCanaryPercent] = useState(25);
  const [rolloutScope, setRolloutScope] = useState("global");
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const selectedPolicy = policies.find(policy => policy.id === policyID) ?? policies[0];
  const rolloutScopeOptions = policyRolloutScopeOptions(applications, copy);
  const selectedVersion = selectedPolicy?.versions.find(version => version.version === targetVersion);

  useEffect(() => {
    if (!policyID && policies[0]?.id) {
      setPolicyID(policies[0].id);
    }
  }, [policies, policyID]);

  useEffect(() => {
    const latestVersion = latestPolicyVersion(selectedPolicy);
    if (latestVersion) {
      setTargetVersion(latestVersion.version);
    }
  }, [selectedPolicy]);

  useEffect(() => {
    if (!rolloutScopeOptions.some(option => option.value === rolloutScope)) {
      setRolloutScope("global");
    }
  }, [rolloutScope, rolloutScopeOptions]);

  useEffect(() => {
    if (selectedVersion?.status !== "draft") {
      return;
    }
    const rule = selectedVersion.rules[0];
    if (!rule) {
      return;
    }
    setRuleName(rule.name);
    setHook(rule.hook);
    setExpression(rule.expression);
    setAction(rule.action || "block");
    setSeverity(rule.severity || "high");
    setTags(Array.isArray(rule.tags) ? rule.tags.join(", ") : "");
  }, [selectedPolicy?.id, selectedVersion?.version]);

  async function handleCreateVersion(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedPolicy) {
      return;
    }
    setIsSubmitting(true);
    setStatus("");
    setError("");
    try {
      const updated = await createPolicyVersion(selectedPolicy.id, [draftRule()]);
      await queryClient.invalidateQueries({ queryKey: ["policies"] });
      const latestVersion = latestPolicyVersion(updated);
      if (latestVersion) {
        setTargetVersion(latestVersion.version);
        setStatus(notice("Created policy version {{version}}.", { version: latestVersion.version }));
      } else {
        setStatus(notice("Created policy version."));
      }
    } catch {
      setError(notice("Unable to create policy version."));
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleUpdateDraft() {
    if (!selectedPolicy) {
      return;
    }
    if (!Number.isInteger(targetVersion) || targetVersion <= 0) {
      setError(notice("Choose a draft policy version."));
      return;
    }
    setIsSubmitting(true);
    setStatus("");
    setError("");
    try {
      await updatePolicyVersionRules(selectedPolicy.id, targetVersion, [draftRule(selectedVersion?.status === "draft" ? selectedVersion.rules[0]?.id : undefined)]);
      await queryClient.invalidateQueries({ queryKey: ["policies"] });
      setStatus(notice("Updated policy version {{version}}.", { version: targetVersion }));
    } catch {
      setError(notice("Unable to update draft version."));
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleValidateDraft() {
    if (!selectedPolicy) {
      return;
    }
    setIsSubmitting(true);
    setStatus("");
    setError("");
    try {
      const validation = await validateRules([draftRule()]);
      if (validation.valid) {
        setStatus(notice("Rule validation passed."));
      } else {
        setError(notice("Rule validation failed: {{message}}", { message: validation.errors.join("; ") || "" }));
      }
    } catch {
      setError(notice("Unable to validate rule."));
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleTestDraft() {
    if (!selectedPolicy) {
      return;
    }
    const sampleEvent = sampleEvents.find(event => !event.hook || !hook || event.hook === hook) ?? sampleEvents[0];
    if (!sampleEvent) {
      setError(notice("Ingest at least one attack event before testing a rule."));
      return;
    }
    setIsSubmitting(true);
    setStatus("");
    setError("");
    try {
      const rule = draftRule();
      const result = await testRule(rule, {
        application_id: sampleEvent.application_id,
        environment_id: sampleEvent.environment_id,
        agent_id: sampleEvent.agent_id,
        policy_id: selectedPolicy.id,
        policy_version: targetVersion,
        hook: sampleEvent.hook,
        algorithm: sampleEvent.algorithm,
        severity: sampleEvent.severity,
        message: sampleEvent.message,
        occurred_at: sampleEvent.occurred_at,
        attributes: sampleEvent.attributes
      });
      setStatus(
        result.matched
          ? notice("Rule test matched: {{action}} at {{confidence}}% confidence.", { action: result.action || "no action", confidence: result.confidence })
          : notice("Rule test did not match the sample event.")
      );
    } catch {
      setError(notice("Unable to test rule."));
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleRollout(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedPolicy) {
      return;
    }
    setIsSubmitting(true);
    setStatus("");
    setError("");
    try {
      await rolloutPolicy(selectedPolicy.id, targetVersion, canaryPercent, policyRolloutScopePayload(rolloutScope));
      await queryClient.invalidateQueries({ queryKey: ["policies"] });
      await queryClient.invalidateQueries({ queryKey: ["agents"] });
      await queryClient.invalidateQueries({ queryKey: ["applications"] });
      setStatus(
        notice("Rolled out version {{version}} to {{percent}}% for {{scope}}.", {
          version: targetVersion,
          percent: canaryPercent,
          scope: policyRolloutScopeStatus(rolloutScope, rolloutScopeOptions)
        })
      );
    } catch {
      setError(notice("Unable to roll out policy version."));
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleRollback() {
    if (!selectedPolicy) {
      return;
    }
    setIsSubmitting(true);
    setStatus("");
    setError("");
    try {
      await rollbackPolicy(selectedPolicy.id);
      await queryClient.invalidateQueries({ queryKey: ["policies"] });
      setStatus(notice("Rollback requested."));
    } catch {
      setError(notice("Unable to roll back policy."));
    } finally {
      setIsSubmitting(false);
    }
  }

  function draftRule(ruleID?: string): RuleInput {
    return {
      id: ruleID,
      name: ruleName,
      hook,
      algorithm: `${hook}_match`,
      action,
      severity,
      expression,
      tags: tags.split(",").map(tag => tag.trim()).filter(Boolean),
      description: `${ruleName} managed from the control console`
    };
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle><UiText k="Policy Change" /></CardTitle>
      </CardHeader>
      <CardContent className="grid gap-5 xl:grid-cols-[1.1fr_.9fr]">
        <form className="grid gap-3 md:grid-cols-2" onSubmit={handleCreateVersion}>
          <label className={fieldGroupClass} htmlFor="policy-id">
            <span className={fieldLabelClass}><UiText k="Policy" /></span>
            <select id="policy-id" className={fieldControlClass} value={selectedPolicy?.id ?? ""} onChange={event => setPolicyID(event.target.value)}>
              {policies.map(policy => (
                <option key={policy.id} value={policy.id}>
                  {policy.name}
                </option>
              ))}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="rule-name">
            <span className={fieldLabelClass}><UiText k="Rule Name" /></span>
            <input id="rule-name" className={fieldControlClass} value={ruleName} onChange={event => setRuleName(event.target.value)} required />
          </label>
          <label className={fieldGroupClass} htmlFor="rule-hook">
            <span className={fieldLabelClass}><UiText k="Hook" /></span>
            <input id="rule-hook" className={fieldControlClass} value={hook} onChange={event => setHook(event.target.value)} required />
          </label>
          <label className={fieldGroupClass} htmlFor="rule-expression">
            <span className={fieldLabelClass}><UiText k="Expression" /></span>
            <input id="rule-expression" className={fieldControlClass} value={expression} onChange={event => setExpression(event.target.value)} required />
          </label>
          <label className={fieldGroupClass} htmlFor="rule-action">
            <span className={fieldLabelClass}><UiText k="Action" /></span>
            <select id="rule-action" className={fieldControlClass} value={action} onChange={event => setAction(event.target.value)}>
              <option value="block"><UiText k="block" /></option>
              <option value="log"><UiText k="log" /></option>
              <option value="ignore"><UiText k="ignore" /></option>
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="rule-severity">
            <span className={fieldLabelClass}><UiText k="Severity" /></span>
            <select id="rule-severity" className={fieldControlClass} value={severity} onChange={event => setSeverity(event.target.value)}>
              <option value="critical"><UiText k="critical" /></option>
              <option value="high"><UiText k="high" /></option>
              <option value="medium"><UiText k="medium" /></option>
              <option value="low"><UiText k="low" /></option>
            </select>
          </label>
          <label className={`${fieldGroupClass} md:col-span-2`} htmlFor="rule-tags">
            <span className={fieldLabelClass}><UiText k="Tags" /></span>
            <input id="rule-tags" className={fieldControlClass} value={tags} onChange={event => setTags(event.target.value)} />
          </label>
          <div className="md:col-span-2">
            <div className="flex flex-wrap gap-2">
              <Button disabled={isSubmitting || !selectedPolicy} type="button" variant="secondary" onClick={handleValidateDraft}>
                <UiText k="Validate Draft" /></Button>
              <Button disabled={isSubmitting || !selectedPolicy} type="button" variant="secondary" onClick={handleTestDraft}>
                <UiText k="Test Draft" /></Button>
              <Button disabled={isSubmitting || !selectedPolicy} type="button" variant="secondary" onClick={handleUpdateDraft}>
                <UiText k="Update Draft" /></Button>
              <Button disabled={isSubmitting || !selectedPolicy} type="submit">
                <UiText k="Create Version" /></Button>
            </div>
          </div>
        </form>
        <form className="grid content-start gap-3" onSubmit={handleRollout}>
          <label className={fieldGroupClass} htmlFor="rollout-scope">
            <span className={fieldLabelClass}><UiText k="Rollout Scope" /></span>
            <select id="rollout-scope" className={fieldControlClass} value={rolloutScope} onChange={event => setRolloutScope(event.target.value)}>
              {rolloutScopeOptions.map(option => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="rollout-version">
            <span className={fieldLabelClass}><UiText k="Version" /></span>
            <input
              id="rollout-version"
              className={fieldControlClass}
              min={1}
              type="number"
              value={targetVersion}
              onChange={event => setTargetVersion(Number(event.target.value))}
              required
            />
          </label>
          <label className={fieldGroupClass} htmlFor="canary-percent">
            <span className={fieldLabelClass}><UiText k="Canary Percent" /></span>
            <input
              id="canary-percent"
              className={fieldControlClass}
              max={100}
              min={0}
              type="number"
              value={canaryPercent}
              onChange={event => setCanaryPercent(Number(event.target.value))}
              required
            />
          </label>
          <div className="flex flex-wrap gap-2">
            <Button disabled={isSubmitting || !selectedPolicy} type="submit">
              <UiText k="Roll Out Version" /></Button>
            <Button disabled={isSubmitting || !selectedPolicy} type="button" variant="secondary" onClick={handleRollback}>
              <UiText k="Rollback" /></Button>
          </div>
          <FormMessage error={error} status={status} />
        </form>
      </CardContent>
    </Card>
  );
}

function ProtectionConfigurationPanel({ settings }: { settings: SystemSetting[] }) {
  const queryClient = useQueryClient();
  const [allowlistEnabled, setAllowlistEnabled] = useState(false);
  const [allowlistMode, setAllowlistMode] = useState("monitor");
  const [allowlistEntries, setAllowlistEntries] = useState("");
  const [hardeningMode, setHardeningMode] = useState("monitor");
  const [blockReflectionAbuse, setBlockReflectionAbuse] = useState(true);
  const [blockProcessExecution, setBlockProcessExecution] = useState(true);
  const [vulnerabilitySeverity, setVulnerabilitySeverity] = useState("critical");
  const [blockKnownExploited, setBlockKnownExploited] = useState(true);
  const [attackRetentionDays, setAttackRetentionDays] = useState(180);
  const [performanceRetentionDays, setPerformanceRetentionDays] = useState(30);
  const [dependencyRetentionDays, setDependencyRetentionDays] = useState(365);
  const [auditRetentionDays, setAuditRetentionDays] = useState(365);
  const [message, setMessage] = useState({ status: "", error: "" });
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    const allowlist = settingRecord(settings, "protection.allowlist");
    const hardening = settingRecord(settings, "protection.hardening");
    const vulnerability = settingRecord(settings, "dependency.vulnerability_policy");
    const retention = settingRecord(settings, "events.retention");

    setAllowlistEnabled(settingBool(allowlist, "enabled", false));
    setAllowlistMode(settingString(allowlist, "mode", "monitor"));
    setAllowlistEntries(settingStringArray(allowlist, "entries").join("\n"));
    setHardeningMode(settingString(hardening, "mode", "monitor"));
    setBlockReflectionAbuse(settingBool(hardening, "block_reflection_abuse", true));
    setBlockProcessExecution(settingBool(hardening, "block_process_execution", true));
    setVulnerabilitySeverity(settingString(vulnerability, "fail_on_severity", "critical"));
    setBlockKnownExploited(settingBool(vulnerability, "block_known_exploited", true));
    setAttackRetentionDays(settingNumber(retention, "attack_days", 180));
    setPerformanceRetentionDays(settingNumber(retention, "performance_days", 30));
    setDependencyRetentionDays(settingNumber(retention, "dependency_days", 365));
    setAuditRetentionDays(settingNumber(retention, "audit_days", 365));
  }, [settings]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage({ status: "", error: "" });
    setIsSubmitting(true);
    try {
      const entries = allowlistEntries
        .split(/\r?\n/)
        .map(entry => entry.trim())
        .filter(Boolean);
      await Promise.all([
        updateSystemSetting("protection.allowlist", {
          enabled: allowlistEnabled,
          mode: allowlistMode,
          entries
        }),
        updateSystemSetting("protection.hardening", {
          mode: hardeningMode,
          block_reflection_abuse: blockReflectionAbuse,
          block_process_execution: blockProcessExecution
        }),
        updateSystemSetting("dependency.vulnerability_policy", {
          fail_on_severity: vulnerabilitySeverity,
          block_known_exploited: blockKnownExploited
        }),
        updateSystemSetting("events.retention", {
          attack_days: positiveInteger(attackRetentionDays, 180),
          performance_days: positiveInteger(performanceRetentionDays, 30),
          dependency_days: positiveInteger(dependencyRetentionDays, 365),
          audit_days: positiveInteger(auditRetentionDays, 365)
        })
      ]);
      await queryClient.invalidateQueries({ queryKey: ["system-settings"] });
      await queryClient.invalidateQueries({ queryKey: ["audit-logs"] });
      setMessage({ status: notice("Protection configuration saved."), error: "" });
    } catch {
      setMessage({ status: "", error: notice("Unable to save protection configuration.") });
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle><UiText k="Protection Configuration" /></CardTitle>
      </CardHeader>
      <CardContent>
        <form className="grid gap-4" onSubmit={handleSubmit}>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <label className="flex min-h-10 items-center gap-2 text-sm font-medium text-slate-700" htmlFor="protection-allowlist-enabled">
              <input
                id="protection-allowlist-enabled"
                className="h-4 w-4 rounded border-slate-300 text-slate-900"
                type="checkbox"
                checked={allowlistEnabled}
                onChange={event => setAllowlistEnabled(event.target.checked)}
              />
              <UiText k="Allowlist Enabled" /></label>
            <label className={fieldGroupClass} htmlFor="protection-allowlist-mode">
              <span className={fieldLabelClass}><UiText k="Allowlist Mode" /></span>
              <select id="protection-allowlist-mode" className={fieldControlClass} value={allowlistMode} onChange={event => setAllowlistMode(event.target.value)}>
                <option value="monitor"><UiText k="monitor" /></option>
                <option value="enforce"><UiText k="enforce" /></option>
              </select>
            </label>
            <label className={fieldGroupClass} htmlFor="protection-hardening-mode">
              <span className={fieldLabelClass}><UiText k="Hardening Mode" /></span>
              <select id="protection-hardening-mode" className={fieldControlClass} value={hardeningMode} onChange={event => setHardeningMode(event.target.value)}>
                <option value="monitor"><UiText k="monitor" /></option>
                <option value="enforce"><UiText k="enforce" /></option>
              </select>
            </label>
            <label className={fieldGroupClass} htmlFor="protection-vulnerability-threshold">
              <span className={fieldLabelClass}><UiText k="Vulnerability Threshold" /></span>
              <select id="protection-vulnerability-threshold" className={fieldControlClass} value={vulnerabilitySeverity} onChange={event => setVulnerabilitySeverity(event.target.value)}>
                <option value="critical"><UiText k="critical" /></option>
                <option value="high"><UiText k="high" /></option>
                <option value="medium"><UiText k="medium" /></option>
                <option value="low"><UiText k="low" /></option>
              </select>
            </label>
          </div>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <label className="flex min-h-10 items-center gap-2 text-sm font-medium text-slate-700" htmlFor="protection-block-reflection">
              <input
                id="protection-block-reflection"
                className="h-4 w-4 rounded border-slate-300 text-slate-900"
                type="checkbox"
                checked={blockReflectionAbuse}
                onChange={event => setBlockReflectionAbuse(event.target.checked)}
              />
              <UiText k="Block Reflection Abuse" /></label>
            <label className="flex min-h-10 items-center gap-2 text-sm font-medium text-slate-700" htmlFor="protection-block-process">
              <input
                id="protection-block-process"
                className="h-4 w-4 rounded border-slate-300 text-slate-900"
                type="checkbox"
                checked={blockProcessExecution}
                onChange={event => setBlockProcessExecution(event.target.checked)}
              />
              <UiText k="Block Process Execution" /></label>
            <label className="flex min-h-10 items-center gap-2 text-sm font-medium text-slate-700" htmlFor="protection-block-known-exploited">
              <input
                id="protection-block-known-exploited"
                className="h-4 w-4 rounded border-slate-300 text-slate-900"
                type="checkbox"
                checked={blockKnownExploited}
                onChange={event => setBlockKnownExploited(event.target.checked)}
              />
              <UiText k="Block Known Exploited" /></label>
          </div>
          <label className={fieldGroupClass} htmlFor="protection-allowlist-entries">
            <span className={fieldLabelClass}><UiText k="Allowlist Entries" /></span>
            <textarea
              id="protection-allowlist-entries"
              className={`${fieldControlClass} min-h-24 py-2`}
              value={allowlistEntries}
              onChange={event => setAllowlistEntries(event.target.value)}
            />
          </label>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <label className={fieldGroupClass} htmlFor="retention-attack-days">
              <span className={fieldLabelClass}><UiText k="Attack Retention Days" /></span>
              <input id="retention-attack-days" className={fieldControlClass} min={1} type="number" value={attackRetentionDays} onChange={event => setAttackRetentionDays(Number(event.target.value))} />
            </label>
            <label className={fieldGroupClass} htmlFor="retention-performance-days">
              <span className={fieldLabelClass}><UiText k="Performance Retention Days" /></span>
              <input
                id="retention-performance-days"
                className={fieldControlClass}
                min={1}
                type="number"
                value={performanceRetentionDays}
                onChange={event => setPerformanceRetentionDays(Number(event.target.value))}
              />
            </label>
            <label className={fieldGroupClass} htmlFor="retention-dependency-days">
              <span className={fieldLabelClass}><UiText k="Dependency Retention Days" /></span>
              <input
                id="retention-dependency-days"
                className={fieldControlClass}
                min={1}
                type="number"
                value={dependencyRetentionDays}
                onChange={event => setDependencyRetentionDays(Number(event.target.value))}
              />
            </label>
            <label className={fieldGroupClass} htmlFor="retention-audit-days">
              <span className={fieldLabelClass}><UiText k="Audit Retention Days" /></span>
              <input id="retention-audit-days" className={fieldControlClass} min={1} type="number" value={auditRetentionDays} onChange={event => setAuditRetentionDays(Number(event.target.value))} />
            </label>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Button disabled={isSubmitting} type="submit">
              <UiText k={isSubmitting ? "Saving Protection Configuration" : "Save Protection Configuration"} />
            </Button>
            <div className="min-w-72 flex-1">
              <FormMessage error={message.error} status={message.status} />
            </div>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function MaintenanceCleanupPanel() {
  const queryClient = useQueryClient();
  const defaultCutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  const [beforeDate, setBeforeDate] = useState(defaultCutoff);
  const [applicationID, setApplicationID] = useState("");
  const [includeEvents, setIncludeEvents] = useState(true);
  const [includeDependencies, setIncludeDependencies] = useState(true);
  const [includeBaselineFindings, setIncludeBaselineFindings] = useState(true);
  const [includeAlertDeliveries, setIncludeAlertDeliveries] = useState(true);
  const [confirmation, setConfirmation] = useState("");
  const [message, setMessage] = useState({ status: "", error: "" });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [lastCounts, setLastCounts] = useState<Record<string, number>>({});

  const before = `${beforeDate}T00:00:00.000Z`;

  async function runCleanup(dryRun: boolean) {
    setMessage({ status: "", error: "" });
    if (!beforeDate) {
      setMessage({ status: "", error: notice("Cleanup cutoff date is required.") });
      return;
    }
    if (!dryRun && confirmation !== "CLEAR_OPERATIONAL_DATA") {
      setMessage({ status: "", error: notice("Type CLEAR_OPERATIONAL_DATA before applying cleanup.") });
      return;
    }
    setIsSubmitting(true);
    try {
      const report = await cleanupMaintenanceData({
        before,
        application_id: applicationID.trim() || undefined,
        dry_run: dryRun,
        include_events: includeEvents,
        include_dependencies: includeDependencies,
        include_baseline_findings: includeBaselineFindings,
        include_alert_deliveries: includeAlertDeliveries,
        confirmation: dryRun ? undefined : confirmation
      });
      setLastCounts(report.counts);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["events"] }),
        queryClient.invalidateQueries({ queryKey: ["dependencies"] }),
        queryClient.invalidateQueries({ queryKey: ["baseline-findings"] }),
        queryClient.invalidateQueries({ queryKey: ["overview"] }),
        queryClient.invalidateQueries({ queryKey: ["observability"] }),
        queryClient.invalidateQueries({ queryKey: ["alert-deliveries"] }),
        queryClient.invalidateQueries({ queryKey: ["audit-logs"] })
      ]);
      setMessage({
        status: notice(dryRun ? "Previewed cleanup for {{count}} records." : "Applied cleanup for {{count}} records.", {
          count: formatCleanupCount(report.counts)
        }),
        error: ""
      });
    } catch {
      setMessage({ status: "", error: notice("Unable to run maintenance cleanup.") });
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle><UiText k="Maintenance Cleanup" /></CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4">
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-[.8fr_1fr_1.2fr_auto_auto] xl:items-end">
          <label className={fieldGroupClass} htmlFor="maintenance-cleanup-before">
            <span className={fieldLabelClass}><UiText k="Cleanup Before" /></span>
            <input id="maintenance-cleanup-before" className={fieldControlClass} type="date" value={beforeDate} onChange={event => setBeforeDate(event.target.value)} />
          </label>
          <label className={fieldGroupClass} htmlFor="maintenance-cleanup-application">
            <span className={fieldLabelClass}><UiText k="Cleanup Application ID" /></span>
            <input id="maintenance-cleanup-application" className={fieldControlClass} value={applicationID} onChange={event => setApplicationID(event.target.value)} />
          </label>
          <label className={fieldGroupClass} htmlFor="maintenance-cleanup-confirmation">
            <span className={fieldLabelClass}><UiText k="Cleanup Confirmation" /></span>
            <input
              id="maintenance-cleanup-confirmation"
              className={fieldControlClass}
              value={confirmation}
              onChange={event => setConfirmation(event.target.value)}
            />
          </label>
          <Button disabled={isSubmitting} type="button" variant="secondary" onClick={() => void runCleanup(true)}>
            <UiText k="Preview Cleanup" /></Button>
          <Button disabled={isSubmitting} type="button" onClick={() => void runCleanup(false)}>
            <UiText k="Apply Cleanup" /></Button>
        </div>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <label className="flex min-h-10 items-center gap-2 text-sm font-medium text-slate-700" htmlFor="maintenance-cleanup-events">
            <input id="maintenance-cleanup-events" className="h-4 w-4 rounded border-slate-300 text-slate-900" type="checkbox" checked={includeEvents} onChange={event => setIncludeEvents(event.target.checked)} />
            <UiText k="Events" /></label>
          <label className="flex min-h-10 items-center gap-2 text-sm font-medium text-slate-700" htmlFor="maintenance-cleanup-dependencies">
            <input id="maintenance-cleanup-dependencies" className="h-4 w-4 rounded border-slate-300 text-slate-900" type="checkbox" checked={includeDependencies} onChange={event => setIncludeDependencies(event.target.checked)} />
            <UiText k="Dependencies" /></label>
          <label className="flex min-h-10 items-center gap-2 text-sm font-medium text-slate-700" htmlFor="maintenance-cleanup-baseline">
            <input id="maintenance-cleanup-baseline" className="h-4 w-4 rounded border-slate-300 text-slate-900" type="checkbox" checked={includeBaselineFindings} onChange={event => setIncludeBaselineFindings(event.target.checked)} />
            <UiText k="Baseline Findings" /></label>
          <label className="flex min-h-10 items-center gap-2 text-sm font-medium text-slate-700" htmlFor="maintenance-cleanup-alerts">
            <input id="maintenance-cleanup-alerts" className="h-4 w-4 rounded border-slate-300 text-slate-900" type="checkbox" checked={includeAlertDeliveries} onChange={event => setIncludeAlertDeliveries(event.target.checked)} />
            <UiText k="Alert Deliveries" /></label>
        </div>
        <FormMessage error={message.error} status={message.status} />
        {Object.keys(lastCounts).length > 0 ? (
          <div className="grid gap-2 rounded-md border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700 md:grid-cols-2 xl:grid-cols-4">
            {Object.entries(lastCounts).map(([key, value]) => (
              <div key={key}>
                <span className="block text-xs font-medium text-slate-500"><UiValue value={formatCleanupKey(key)} /></span>
                <span className="font-mono text-sm">{value}</span>
              </div>
            ))}
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

function AccessWritePanel() {
  const queryClient = useQueryClient();
  const [settingKey, setSettingKey] = useState("agent.minimum_version");
  const [settingValue, setSettingValue] = useState('{"version":"1.1.0"}');
  const [settingMessage, setSettingMessage] = useState({ status: "", error: "" });
  const [alertName, setAlertName] = useState("");
  const [alertSeverity, setAlertSeverity] = useState("critical");
  const [alertTarget, setAlertTarget] = useState("");
  const [alertEnabled, setAlertEnabled] = useState(true);
  const [alertMessage, setAlertMessage] = useState({ status: "", error: "" });
  const [userEmail, setUserEmail] = useState("");
  const [userName, setUserName] = useState("");
  const [userPassword, setUserPassword] = useState("");
  const [userRole, setUserRole] = useState("security_engineer");
  const [userMessage, setUserMessage] = useState({ status: "", error: "" });

  async function handleSettingSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSettingMessage({ status: "", error: "" });
    try {
      const parsed = JSON.parse(settingValue) as unknown;
      if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") {
        throw new Error("setting value must be an object");
      }
      await updateSystemSetting(settingKey, parsed as Record<string, unknown>);
      await queryClient.invalidateQueries({ queryKey: ["system-settings"] });
      setSettingMessage({ status: notice("Setting saved."), error: "" });
    } catch {
      setSettingMessage({ status: "", error: notice("Unable to save setting.") });
    }
  }

  async function handleAlertSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAlertMessage({ status: "", error: "" });
    try {
      await createAlertRule({
        name: alertName,
        description: `${alertName} managed from the control console`,
        enabled: alertEnabled,
        event_type: "attack",
        severity: alertSeverity,
        condition: `severity == ${alertSeverity}`,
        target: alertTarget
      });
      await queryClient.invalidateQueries({ queryKey: ["alert-rules"] });
      setAlertMessage({ status: notice("Alert rule created."), error: "" });
    } catch {
      setAlertMessage({ status: "", error: notice("Unable to create alert rule.") });
    }
  }

  async function handleUserSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setUserMessage({ status: "", error: "" });
    try {
      await createUser({
        email: userEmail,
        name: userName,
        password: userPassword,
        roles: [userRole as "admin" | "security_engineer" | "viewer"]
      });
      await queryClient.invalidateQueries({ queryKey: ["users"] });
      setUserMessage({ status: notice("User created."), error: "" });
    } catch {
      setUserMessage({ status: "", error: notice("Unable to create user.") });
    }
  }

  return (
    <section className="grid gap-5 xl:grid-cols-3">
      <Card>
        <CardHeader>
          <CardTitle><UiText k="Setting Change" /></CardTitle>
        </CardHeader>
        <CardContent>
          <form className="grid gap-3" onSubmit={handleSettingSubmit}>
            <label className={fieldGroupClass} htmlFor="setting-key">
              <span className={fieldLabelClass}><UiText k="Key" /></span>
              <input id="setting-key" className={fieldControlClass} value={settingKey} onChange={event => setSettingKey(event.target.value)} required />
            </label>
            <label className={fieldGroupClass} htmlFor="setting-value">
              <span className={fieldLabelClass}><UiText k="Value JSON" /></span>
              <textarea
                id="setting-value"
                className={`${fieldControlClass} min-h-24 py-2`}
                value={settingValue}
                onChange={event => setSettingValue(event.target.value)}
                required
              />
            </label>
            <Button type="submit"><UiText k="Save Setting" /></Button>
            <FormMessage error={settingMessage.error} status={settingMessage.status} />
          </form>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle><UiText k="Alert Rule" /></CardTitle>
        </CardHeader>
        <CardContent>
          <form className="grid gap-3" onSubmit={handleAlertSubmit}>
            <label className={fieldGroupClass} htmlFor="alert-name">
              <span className={fieldLabelClass}><UiText k="Name" /></span>
              <input id="alert-name" className={fieldControlClass} value={alertName} onChange={event => setAlertName(event.target.value)} required />
            </label>
            <label className={fieldGroupClass} htmlFor="alert-severity">
              <span className={fieldLabelClass}><UiText k="Severity" /></span>
              <select id="alert-severity" className={fieldControlClass} value={alertSeverity} onChange={event => setAlertSeverity(event.target.value)}>
                <option value="critical"><UiText k="critical" /></option>
                <option value="high"><UiText k="high" /></option>
                <option value="medium"><UiText k="medium" /></option>
                <option value="low"><UiText k="low" /></option>
              </select>
            </label>
            <label className={fieldGroupClass} htmlFor="alert-target">
              <span className={fieldLabelClass}><UiText k="Target" /></span>
              <input id="alert-target" className={fieldControlClass} value={alertTarget} onChange={event => setAlertTarget(event.target.value)} required />
            </label>
            <label className="flex items-center gap-2 text-sm font-medium text-slate-700" htmlFor="alert-enabled">
              <input id="alert-enabled" checked={alertEnabled} type="checkbox" onChange={event => setAlertEnabled(event.target.checked)} />
              <UiText k="Enabled" /></label>
            <Button type="submit"><UiText k="Create Alert Rule" /></Button>
            <FormMessage error={alertMessage.error} status={alertMessage.status} />
          </form>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle><UiText k="User Invite" /></CardTitle>
        </CardHeader>
        <CardContent>
          <form className="grid gap-3" onSubmit={handleUserSubmit}>
            <label className={fieldGroupClass} htmlFor="user-email">
              <span className={fieldLabelClass}><UiText k="Email" /></span>
              <input id="user-email" className={fieldControlClass} type="email" value={userEmail} onChange={event => setUserEmail(event.target.value)} required />
            </label>
            <label className={fieldGroupClass} htmlFor="user-name">
              <span className={fieldLabelClass}><UiText k="Name" /></span>
              <input id="user-name" className={fieldControlClass} value={userName} onChange={event => setUserName(event.target.value)} required />
            </label>
            <label className={fieldGroupClass} htmlFor="user-password">
              <span className={fieldLabelClass}><UiText k="Password" /></span>
              <input id="user-password" className={fieldControlClass} type="password" value={userPassword} onChange={event => setUserPassword(event.target.value)} required />
            </label>
            <label className={fieldGroupClass} htmlFor="user-role">
              <span className={fieldLabelClass}><UiText k="Role" /></span>
              <select id="user-role" className={fieldControlClass} value={userRole} onChange={event => setUserRole(event.target.value)}>
                <option value="admin"><UiText k="Admin" /></option>
                <option value="security_engineer"><UiText k="Security Engineer" /></option>
                <option value="viewer"><UiText k="Viewer" /></option>
              </select>
            </label>
            <Button type="submit"><UiText k="Create User" /></Button>
            <FormMessage error={userMessage.error} status={userMessage.status} />
          </form>
        </CardContent>
      </Card>
    </section>
  );
}

function FormMessage({ error, status }: { error: string; status: string }) {
  const { i18n } = useTranslation();
  if (error) {
    return (
      <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700" role="alert">
        {translateNotice(i18n.resolvedLanguage ?? i18n.language, error)}
      </div>
    );
  }
  if (status) {
    return (
      <div className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-700" role="status">
        {translateNotice(i18n.resolvedLanguage ?? i18n.language, status)}
      </div>
    );
  }
  return null;
}

function QueryStateNotice({ isLoading, isError, loading, error }: { isLoading: boolean; isError: boolean; loading: ReactNode; error: ReactNode }) {
  if (isError) {
    return (
      <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700" role="alert">
        {error}
      </div>
    );
  }
  if (isLoading) {
    return (
      <div className="rounded-md border border-slate-200 bg-white px-3 py-2 text-sm text-slate-600" role="status">
        {loading}
      </div>
    );
  }
  return null;
}

function emptyAgentArtifactCatalog(): AgentArtifactCatalog {
  return {
    artifact_dir_configured: false,
    generated_bootstrap_enabled: false,
    items: []
  };
}

function emptyObservabilityReport() {
  return {
    rule_overhead: [],
    hook_latency: [],
    agent_overhead: [],
    policy_performance: []
  };
}

function emptyEditionStatus(): EditionStatus {
  return {
    edition: "",
    display_name: "",
    deployment_model: "",
    license_required: false,
    license_enforcement: "",
    license_status: "",
    note: ""
  };
}

function latestPolicyVersion(policy?: PolicySet) {
  if (!policy) {
    return undefined;
  }
  const versions = policy.versions.length > 0 ? policy.versions : policy.active ? [policy.active] : [];
  if (versions.length === 0) {
    return undefined;
  }
  return versions.slice(1).reduce((latest, candidate) => (candidate.version > latest.version ? candidate : latest), versions[0]);
}

type RolloutScopeOption = {
  label: string;
  value: string;
};

function policyRolloutScopeOptions(applications: Application[], copy: (key: "All Applications") => string): RolloutScopeOption[] {
  const options: RolloutScopeOption[] = [{ label: copy("All Applications"), value: "global" }];
  applications.forEach(application => {
    options.push({ label: application.name, value: `application:${application.id}` });
    application.environment_ids.forEach(environmentID => {
      options.push({ label: `${application.name} / ${environmentID}`, value: `environment:${environmentID}` });
    });
  });
  return options;
}

function policyRolloutScopePayload(scope: string): PolicyRolloutScope {
  const [kind, value] = scope.split(":");
  if (kind === "application" && value) {
    return { application_id: value };
  }
  if (kind === "environment" && value) {
    return { environment_id: value };
  }
  return {};
}

function policyRolloutScopeStatus(scope: string, options: RolloutScopeOption[]) {
  const option = options.find(candidate => candidate.value === scope);
  return option?.label ?? "All Applications";
}

const fieldGroupClass = "grid gap-1";
const fieldLabelClass = "text-sm font-medium text-slate-700";
const fieldControlClass = "min-h-10 w-full rounded-md border border-slate-300 bg-white px-3 text-sm text-slate-950 outline-none focus:border-slate-900";

function latestAgentVersion(versions: string[]) {
  return versions.filter(Boolean).sort((left, right) => right.localeCompare(left, undefined, { numeric: true, sensitivity: "base" }))[0] ?? "";
}

function statusTone(status: string): BadgeTone {
  if (status === "active") {
    return "green";
  }
  if (status === "canary") {
    return "amber";
  }
  if (status === "rolled_back") {
    return "neutral";
  }
  return "blue";
}

function severityTone(severity: string): BadgeTone {
	if (severity === "critical" || severity === "high") {
		return "red";
	}
  if (severity === "medium") {
    return "amber";
  }
	return "neutral";
}

function eventTypeTone(eventType: string): BadgeTone {
	if (eventType === "attack" || eventType === "crash") {
		return "red";
	}
	if (eventType === "performance") {
		return "amber";
	}
	if (eventType === "hook") {
		return "blue";
	}
	return "neutral";
}

function baselineStatusTone(status: string): BadgeTone {
  if (status === "failed") {
    return "red";
  }
  if (status === "warning") {
    return "amber";
  }
  if (status === "passed") {
    return "green";
  }
  return "neutral";
}

function deliveryStatusTone(status: string): BadgeTone {
  if (status === "delivered") {
    return "green";
  }
  if (status === "failed") {
    return "red";
  }
  if (status === "queued") {
    return "amber";
  }
  return "neutral";
}

function workloadLabel(workload: DaemonWorkload) {
  if (workload.type === "process") {
    return workload.pid ? `process ${workload.pid}` : workload.cmdline?.[0] ?? workload.id;
  }
  return workload.container_name || workload.container_id || workload.image_tag || workload.id;
}

function workloadDetail(workload: DaemonWorkload) {
  if (workload.type === "process") {
    const command = workload.cmdline?.join(" ");
    if (workload.pid && command) {
      return `pid ${workload.pid} - ${command}`;
    }
    if (workload.pid) {
      return `pid ${workload.pid}`;
    }
    return command || "process";
  }
  const parts = [workload.container_name, workload.container_id, workload.image_tag].filter(Boolean);
  return parts.length > 0 ? parts.join(" / ") : "container";
}

function injectionStatusCell(workload: DaemonWorkload) {
  if (!workload.injection_status) {
    return <span className="text-slate-500"><UiText k="pending" /></span>;
  }
  return (
    <div className="space-y-1">
      <Badge tone={injectionStatusTone(workload.injection_status)}>{workload.injection_status}</Badge>
      {workload.injection_error ? <div className="max-w-56 text-xs text-red-700">{workload.injection_error}</div> : null}
      {workload.injection_helper_id ? <div className="text-xs text-slate-500">{workload.injection_helper_id}</div> : null}
    </div>
  );
}

function injectionStatusTone(status: string): BadgeTone {
  if (status === "injected") {
    return "green";
  }
  if (status === "failed") {
    return "red";
  }
  if (status === "uninstalled") {
    return "neutral";
  }
  return "amber";
}

function FormattedDate({ value }: { value?: string }) {
  const { i18n } = useTranslation();
  return <>{formatDate(value, i18n.resolvedLanguage ?? i18n.language)}</>;
}

function formatDate(value?: string, language = "en") {
  if (!value) {
    return translateUiCopy(language, "unknown");
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat(language, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  }).format(parsed);
}

function uniqueEventsByID(events: SecurityEvent[]) {
  const byID = new Map<string, SecurityEvent>();
  events.forEach(event => {
    if (!byID.has(event.id)) {
      byID.set(event.id, event);
    }
  });
  return Array.from(byID.values());
}

function eventDateTimeQueryValue(value: string) {
  if (!value) {
    return undefined;
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return undefined;
  }
  return parsed.toISOString();
}

function formatDetails(details?: Record<string, unknown>) {
  if (!details || Object.keys(details).length === 0) {
    return "-";
  }
  return Object.entries(details)
    .map(([key, value]) => `${key}=${formatDetailValue(value)}`)
    .join(", ");
}

function formatDetailValue(value: unknown) {
  if (value === null || value === undefined) {
    return "";
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

function formatLabel(value?: string) {
  if (!value) {
    return "unknown";
  }
  return value
    .split("_")
    .filter(Boolean)
    .map(part => part[0].toUpperCase() + part.slice(1))
    .join(" ");
}

function settingRecord(settings: SystemSetting[], key: string) {
  const value = settings.find(setting => setting.key === key)?.value;
  if (!value || Array.isArray(value) || typeof value !== "object") {
    return {};
  }
  return value;
}

function settingString(value: Record<string, unknown>, key: string, fallback: string) {
  const raw = value[key];
  return typeof raw === "string" && raw ? raw : fallback;
}

function settingBool(value: Record<string, unknown>, key: string, fallback: boolean) {
  const raw = value[key];
  return typeof raw === "boolean" ? raw : fallback;
}

function settingNumber(value: Record<string, unknown>, key: string, fallback: number) {
  const raw = value[key];
  return typeof raw === "number" && Number.isFinite(raw) ? raw : fallback;
}

function settingStringArray(value: Record<string, unknown>, key: string) {
  const raw = value[key];
  if (!Array.isArray(raw)) {
    return [];
  }
  return raw.filter((entry): entry is string => typeof entry === "string");
}

function positiveInteger(value: number, fallback: number) {
  return Number.isInteger(value) && value > 0 ? value : fallback;
}

function formatCleanupCount(counts: Record<string, number>) {
  return formatNumber(Object.values(counts).reduce((total, value) => total + value, 0));
}

function formatCleanupKey(key: string) {
  return key
    .split("_")
    .map(part => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function formatRole(role: string) {
  return role
    .split("_")
    .map(part => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function formatLatency(value?: number) {
  if (typeof value !== "number" || Number.isNaN(value)) {
    return "0 us";
  }
  if (value >= 1000) {
    const ms = value / 1000;
    return `${ms >= 10 ? ms.toFixed(0) : ms.toFixed(1)} ms`;
  }
  return `${Math.round(value)} us`;
}

function formatPercent(value?: number) {
  if (typeof value !== "number" || Number.isNaN(value)) {
    return "0.0%";
  }
  return `${value.toFixed(1)}%`;
}

function formatBytes(value?: number) {
  if (typeof value !== "number" || Number.isNaN(value) || value <= 0) {
    return "0 B";
  }
  if (value >= 1024 * 1024) {
    return `${(value / 1024 / 1024).toFixed(1)} MiB`;
  }
  if (value >= 1024) {
    return `${(value / 1024).toFixed(1)} KiB`;
  }
  return `${value} B`;
}

function formatNumber(value: number) {
  return new Intl.NumberFormat(appI18n.resolvedLanguage ?? appI18n.language).format(value);
}

function Metric({ label, value, detail }: { label: ReactNode; value: string | number; detail: ReactNode }) {
  return (
    <Card>
      <CardContent>
        <div className="text-sm text-slate-500">{label}</div>
        <div className="mt-2 text-2xl font-semibold tracking-normal text-slate-950">{value}</div>
        <div className="mt-1 text-xs text-slate-500">{detail}</div>
      </CardContent>
    </Card>
  );
}

function AttackTrendPanel({ points }: { points: { bucket_start: string; count: number }[] }) {
  const { t } = useTranslation();
  const maxCount = Math.max(1, ...points.map(point => point.count));
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("overview.attackTrend")}</CardTitle>
      </CardHeader>
      <CardContent>
        {points.length > 0 ? (
          <div className="grid min-h-44 gap-3">
            {points.map(point => {
              const width = Math.max(8, Math.round((point.count / maxCount) * 100));
              return (
                <div key={point.bucket_start} className="grid grid-cols-[5.5rem_minmax(0,1fr)_3rem] items-center gap-3">
                  <div className="text-xs text-slate-500">{formatDateShort(point.bucket_start)}</div>
                  <div className="h-3 overflow-hidden rounded-sm bg-slate-100">
                    <div className="h-full rounded-sm bg-teal-600" style={{ width: `${width}%` }} />
                  </div>
                  <div className="text-right text-sm font-medium tabular-nums text-slate-900">{formatNumber(point.count)}</div>
                </div>
              );
            })}
          </div>
        ) : (
          <EmptyPanelLabel>{t("overview.noDashboardData")}</EmptyPanelLabel>
        )}
      </CardContent>
    </Card>
  );
}

function DashboardBreakdown({ title, groups }: { title: string; groups: { label: string; entries: [string, number][] }[] }) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid gap-4">
          {groups.map(group => (
            <div key={group.label}>
              <div className="mb-2 text-xs font-semibold uppercase tracking-normal text-slate-500">{group.label}</div>
              {group.entries.length > 0 ? (
                <div className="grid gap-2">
                  {group.entries.map(([label, count]) => (
                    <div key={label} className="flex min-h-9 items-center justify-between gap-3 rounded-md border border-slate-200 px-3 py-2">
                      <span className="min-w-0 truncate text-sm text-slate-700" title={label}>{label}</span>
                      <span className="shrink-0 text-sm font-medium tabular-nums text-slate-950">{formatNumber(count)}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyPanelLabel>{t("overview.noDashboardData")}</EmptyPanelLabel>
              )}
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function EmptyPanelLabel({ children }: { children: ReactNode }) {
  return <div className="flex min-h-24 items-center justify-center rounded-md border border-dashed border-slate-200 text-sm text-slate-500">{children}</div>;
}

function topEntries(values: Record<string, number> = {}, limit = 5): [string, number][] {
  return Object.entries(values)
    .filter(([, count]) => count > 0)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, limit);
}

function formatDateShort(value: string) {
  return new Intl.DateTimeFormat(appI18n.resolvedLanguage ?? appI18n.language, {
    month: "short",
    day: "numeric"
  }).format(new Date(value));
}

function PolicyLifecycle() {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("overview.policyLifecycle")}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid gap-2">
          {policyLifecycle.map((step, index) => (
            <div key={step} className={cn("flex items-center justify-between rounded-md border border-slate-200 p-3", index === 4 && "border-amber-300 bg-amber-50")}>
              <span className="font-medium text-slate-900">{t(`lifecycle.${lifecycleKeys[index]}`, step)}</span>
              <Badge tone={index < 4 ? "green" : index === 4 ? "amber" : "neutral"}>{index + 1}</Badge>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function SectionPage({ title, summary, children }: { title: string; summary: string; children: ReactNode }) {
  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-semibold tracking-normal text-slate-950">{title}</h1>
        <p className="mt-2 max-w-4xl text-sm leading-6 text-slate-600">{summary}</p>
      </div>
      {children}
    </div>
  );
}
