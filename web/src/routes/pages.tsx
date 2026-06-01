import { Link, Outlet, useNavigate } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AppWindow,
  ChartNoAxesColumnIncreasing,
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
import { setAppLanguage, supportedLanguages, type SupportedLanguage } from "../i18n";
import {
  agentsFallback,
  applicationsFallback,
  alertDeliveriesFallback,
  alertRulesFallback,
  bindDaemonWorkload,
  baselineFindingsFallback,
  cleanupMaintenanceData,
  createAlertRule,
  createApplication,
  createEnvironment,
  createPolicy,
  createPolicyVersion,
  createUser,
  agentArtifactsFallback,
  attackEventsFallback,
  auditLogsFallback,
  currentSession,
  daemonWorkloadsFallback,
  dependenciesFallback,
  downloadAgentArtifact,
  editionStatusFallback,
  eventFallbackByType,
  getAgentArtifactInfo,
  getDaemonApplicationCredential,
  getDaemonToken,
  heartbeatAgent,
  loginWithPassword,
  moveEventsToRecycleBin,
  observabilityFallback,
  overviewFallback,
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
  policiesFallback,
  pullAgentPolicy,
  registerAgent,
  resetDaemonToken,
  restoreEventsFromRecycleBin,
  rotateApplicationSecret,
  rollbackPolicy,
  rolloutPolicy,
  saveSession,
  systemSettingsFallback,
  testRule,
  updateAlertRule,
  uploadAgentArtifact,
  updatePolicyVersionRules,
  unbindDaemonWorkload,
  updateUser,
  updateSystemSetting,
  usersFallback,
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
        <nav aria-label="Primary mobile" className="border-b border-slate-200 bg-white px-4 py-2 lg:hidden">
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

export function OverviewPage() {
  const { t } = useTranslation();
  const overviewQuery = useOverview();
  const overview = overviewQuery.data ?? overviewFallback();
  const onlineRate = Math.round((overview.online_agents / Math.max(overview.agent_count, 1)) * 100);
  return (
    <div className="space-y-5">
      <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <Metric label={t("overview.metrics.applications")} value={overview.application_count} detail={t("overview.metrics.applicationsDetail")} />
        <Metric label={t("overview.metrics.onlineAgents")} value={`${overview.online_agents}/${overview.agent_count}`} detail={t("overview.metrics.onlineAgentsDetail", { rate: onlineRate })} />
        <Metric label={t("overview.metrics.events")} value={overview.event_count} detail={t("overview.metrics.eventsDetail")} />
        <Metric label={t("overview.metrics.hookP95")} value="1.8 ms" detail={t("overview.metrics.hookP95Detail")} />
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
  const applications = applicationsQuery.data?.items ?? applicationsFallback().items;
  const environmentCount = applications.reduce((count, app) => count + app.environment_ids.length, 0);

  return (
    <SectionPage
      title={t("pages.applications.title")}
      summary={t("pages.applications.summary")}
    >
      <div className="grid gap-3 md:grid-cols-3">
        <Metric label="Applications" value={applications.length} detail="managed services" />
        <Metric label="Environments" value={environmentCount} detail="deployment scopes" />
        <Metric label="Average Scope" value={applications.length > 0 ? (environmentCount / applications.length).toFixed(1) : "0.0"} detail="environments per app" />
      </div>
      <ApplicationsWritePanel applications={applications} />
      <Table>
        <thead>
          <tr className="bg-slate-50">
            <th className="p-3 text-left">Application</th>
            <th className="p-3 text-left">Environments</th>
            <th className="p-3 text-left">Description</th>
            <th className="p-3 text-left">Created</th>
          </tr>
        </thead>
        <tbody>
          {applications.length > 0 ? (
            applications.map(app => (
              <tr key={app.id} className="border-t border-slate-200">
                <td className="p-3 font-medium">{app.name}</td>
                <td className="p-3 text-slate-600">{app.environment_ids.length}</td>
                <td className="p-3 text-slate-600">{app.description || "No description"}</td>
                <td className="p-3 text-slate-600">{formatDate(app.created_at)}</td>
              </tr>
            ))
          ) : (
            <tr className="border-t border-slate-200">
              <td className="p-3 text-slate-500" colSpan={4}>
                No applications
              </td>
            </tr>
          )}
        </tbody>
      </Table>
    </SectionPage>
  );
}

function ApplicationsWritePanel({ applications }: { applications: Application[] }) {
  const queryClient = useQueryClient();
  const [applicationName, setApplicationName] = useState("Orders API");
  const [applicationDescription, setApplicationDescription] = useState("Order processing service");
  const [applicationMessage, setApplicationMessage] = useState({ status: "", error: "" });
  const [isApplicationSubmitting, setIsApplicationSubmitting] = useState(false);
  const [applicationID, setApplicationID] = useState(applications[0]?.id ?? "");
  const [environmentName, setEnvironmentName] = useState("production");
  const [environmentKind, setEnvironmentKind] = useState("production");
  const [environmentMessage, setEnvironmentMessage] = useState({ status: "", error: "" });
  const [isEnvironmentSubmitting, setIsEnvironmentSubmitting] = useState(false);
  const [secretMessage, setSecretMessage] = useState({ status: "", error: "" });
  const [isSecretSubmitting, setIsSecretSubmitting] = useState(false);

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
      setApplicationMessage({ status: "", error: "Application name is required." });
      return;
    }
    setIsApplicationSubmitting(true);
    try {
      const created = await createApplication({
        name: trimmedName,
        description: applicationDescription.trim() || undefined
      });
      await queryClient.invalidateQueries({ queryKey: ["applications"] });
      const secret = created.secret ? ` Secret: ${created.secret}.` : "";
      setApplicationMessage({ status: `Created application ${created.name}.${secret}`, error: "" });
      setApplicationName("");
      setApplicationDescription("");
    } catch {
      setApplicationMessage({ status: "", error: "Unable to create application." });
    } finally {
      setIsApplicationSubmitting(false);
    }
  }

  async function handleEnvironmentSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setEnvironmentMessage({ status: "", error: "" });
    if (!selectedApplication) {
      setEnvironmentMessage({ status: "", error: "Choose an application first." });
      return;
    }
    const trimmedName = environmentName.trim();
    if (!trimmedName) {
      setEnvironmentMessage({ status: "", error: "Environment name is required." });
      return;
    }
    setIsEnvironmentSubmitting(true);
    try {
      const created = await createEnvironment(selectedApplication.id, {
        name: trimmedName,
        kind: environmentKind.trim() || undefined
      });
      await queryClient.invalidateQueries({ queryKey: ["applications"] });
      setEnvironmentMessage({ status: `Created environment ${created.name} for ${selectedApplication.name}.`, error: "" });
      setEnvironmentName("");
    } catch {
      setEnvironmentMessage({ status: "", error: "Unable to create environment." });
    } finally {
      setIsEnvironmentSubmitting(false);
    }
  }

  async function handleSecretRotation() {
    setSecretMessage({ status: "", error: "" });
    if (!selectedApplication) {
      setSecretMessage({ status: "", error: "Choose an application first." });
      return;
    }
    setIsSecretSubmitting(true);
    try {
      const rotated = await rotateApplicationSecret(selectedApplication.id);
      await queryClient.invalidateQueries({ queryKey: ["applications"] });
      const secret = rotated.secret ? ` Secret: ${rotated.secret}.` : "";
      setSecretMessage({ status: `Rotated secret for ${rotated.name}.${secret}`, error: "" });
    } catch {
      setSecretMessage({ status: "", error: "Unable to rotate application secret." });
    } finally {
      setIsSecretSubmitting(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Application Scope</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-5 xl:grid-cols-2">
        <form className="grid content-start gap-3" onSubmit={handleApplicationSubmit}>
          <label className={fieldGroupClass} htmlFor="application-name">
            <span className={fieldLabelClass}>Application Name</span>
            <input id="application-name" className={fieldControlClass} value={applicationName} onChange={event => setApplicationName(event.target.value)} required />
          </label>
          <label className={fieldGroupClass} htmlFor="application-description">
            <span className={fieldLabelClass}>Description</span>
            <input
              id="application-description"
              className={fieldControlClass}
              value={applicationDescription}
              onChange={event => setApplicationDescription(event.target.value)}
            />
          </label>
          <Button disabled={isApplicationSubmitting} type="submit">
            {isApplicationSubmitting ? "Creating Application" : "Create Application"}
          </Button>
          <FormMessage error={applicationMessage.error} status={applicationMessage.status} />
        </form>
        <form className="grid content-start gap-3" onSubmit={handleEnvironmentSubmit}>
          <label className={fieldGroupClass} htmlFor="environment-application">
            <span className={fieldLabelClass}>Application</span>
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
                <option value="">No applications</option>
              )}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="environment-name">
            <span className={fieldLabelClass}>Environment Name</span>
            <input id="environment-name" className={fieldControlClass} value={environmentName} onChange={event => setEnvironmentName(event.target.value)} required />
          </label>
          <label className={fieldGroupClass} htmlFor="environment-kind">
            <span className={fieldLabelClass}>Kind</span>
            <select id="environment-kind" className={fieldControlClass} value={environmentKind} onChange={event => setEnvironmentKind(event.target.value)}>
              <option value="production">production</option>
              <option value="staging">staging</option>
              <option value="qa">qa</option>
              <option value="development">development</option>
            </select>
          </label>
          <Button disabled={isEnvironmentSubmitting || !selectedApplication} type="submit">
            {isEnvironmentSubmitting ? "Creating Environment" : "Create Environment"}
          </Button>
          <FormMessage error={environmentMessage.error} status={environmentMessage.status} />
          <Button disabled={isSecretSubmitting || !selectedApplication} type="button" variant="secondary" onClick={handleSecretRotation}>
            {isSecretSubmitting ? "Rotating Secret" : "Rotate Secret"}
          </Button>
          <FormMessage error={secretMessage.error} status={secretMessage.status} />
        </form>
      </CardContent>
    </Card>
  );
}

export function AgentsPage() {
  const { t } = useTranslation();
  const agentsQuery = useAgents();
  const agents = agentsQuery.data?.items ?? agentsFallback().items;
  const applicationsQuery = useApplications();
  const applications = applicationsQuery.data?.items ?? applicationsFallback().items;
  const daemonWorkloadsQuery = useDaemonWorkloads();
  const daemonWorkloads = daemonWorkloadsQuery.data?.items ?? daemonWorkloadsFallback().items;
  const agentArtifactsQuery = useAgentArtifacts();
  const agentArtifactCatalog = agentArtifactsQuery.data ?? agentArtifactsFallback();
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
      <div className="grid gap-3 md:grid-cols-3">
        <Metric label="Online" value={`${onlineAgents}/${agents.length}`} detail="healthy heartbeat" />
        <Metric label="Drifted" value={driftedAgents} detail={latestVersion ? `latest ${latestVersion}` : "no version baseline"} />
        <Metric label="Assigned" value={agents.filter(agent => agent.policy_id).length} detail="policy-bound Agents" />
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
            <th className="p-3 text-left">Host</th>
            <th className="p-3 text-left">Runtime</th>
            <th className="p-3 text-left">Version</th>
            <th className="p-3 text-left">Policy</th>
            <th className="p-3 text-left">Status</th>
            <th className="p-3 text-left">Last Seen</th>
          </tr>
        </thead>
        <tbody>
          {agents.length > 0 ? (
            agents.map(agent => (
              <tr key={agent.id} className="border-t border-slate-200">
                <td className="p-3 font-medium">{agent.hostname}</td>
                <td className="p-3 text-slate-600">{agent.runtime}</td>
                <td className="p-3 text-slate-600">{agent.version}</td>
                <td className="p-3 text-slate-600">{agent.policy_id ? `${agent.policy_id} v${agent.policy_version ?? 0}` : "unassigned"}</td>
                <td className="p-3">
                  <Badge tone={agent.status === "online" ? "green" : "amber"}>{agent.status}</Badge>
                </td>
                <td className="p-3 text-slate-600">{formatDate(agent.last_seen_at)}</td>
              </tr>
            ))
          ) : (
            <tr className="border-t border-slate-200">
              <td className="p-3 text-slate-500" colSpan={6}>
                No Agents
              </td>
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
      setMessage({ status: "", error: "Choose an Agent first." });
      return;
    }
    const trimmedSecret = applicationSecret.trim();
    if (!trimmedSecret) {
      setMessage({ status: "", error: "Application secret is required." });
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
      setMessage({ status: `Heartbeat accepted for ${updated.hostname}: ${updated.status}.`, error: "" });
    } catch {
      setMessage({ status: "", error: "Unable to send Agent heartbeat." });
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handlePolicyPull() {
    if (!selectedAgent) {
      setMessage({ status: "", error: "Choose an Agent first." });
      return;
    }
    const trimmedSecret = applicationSecret.trim();
    if (!trimmedSecret) {
      setMessage({ status: "", error: "Application secret is required." });
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
      setMessage({ status: `Pulled policy version ${policy.version} (${policy.status}) with ${policy.rules.length} rules for ${selectedAgent.hostname}.`, error: "" });
    } catch {
      setMessage({ status: "", error: "Unable to pull Agent policy." });
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Agent Operations</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid gap-3 md:grid-cols-[1.2fr_.9fr_.7fr_auto_auto] md:items-end">
          <label className={fieldGroupClass} htmlFor="agent-operation-agent">
            <span className={fieldLabelClass}>Agent</span>
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
                <option value="">No Agents</option>
              )}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="agent-operation-secret">
            <span className={fieldLabelClass}>Operation Secret</span>
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
            <span className={fieldLabelClass}>Heartbeat Status</span>
            <select id="heartbeat-status" className={fieldControlClass} value={heartbeatStatus} onChange={event => setHeartbeatStatus(event.target.value)}>
              <option value="online">online</option>
              <option value="offline">offline</option>
            </select>
          </label>
          <Button disabled={isSubmitting || !selectedAgent} type="button" variant="secondary" onClick={handleHeartbeat}>
            Send Heartbeat
          </Button>
          <Button disabled={isSubmitting || !selectedAgent} type="button" variant="secondary" onClick={handlePolicyPull}>
            Pull Policy
          </Button>
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
      setMessage({ status: `Daemon token: ${token.access_token}`, error: "" });
    } catch {
      setMessage({ status: "", error: "Unable to reveal daemon token." });
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
      setMessage({ status: `Rotated daemon token: ${token.access_token}`, error: "" });
    } catch {
      setMessage({ status: "", error: "Unable to rotate daemon token." });
    } finally {
      setIsTokenSubmitting(false);
    }
  }

  async function handleBind(workload: DaemonWorkload) {
    const applicationID = bindingApplicationIDs[workload.id] || applications[0]?.id || "";
    if (!applicationID) {
      setMessage({ status: "", error: "Choose an application before binding." });
      return;
    }
    setActiveWorkloadID(workload.id);
    setMessage({ status: "", error: "" });
    try {
      const bound = await bindDaemonWorkload(workload.id, applicationID);
      await queryClient.invalidateQueries({ queryKey: ["daemon-workloads"] });
      await queryClient.invalidateQueries({ queryKey: ["audit-logs"] });
      const app = applications.find(application => application.id === bound.application_id);
      setMessage({ status: `Bound ${workloadLabel(bound)} to ${app?.name ?? bound.application_id}.`, error: "" });
    } catch {
      setMessage({ status: "", error: "Unable to bind workload." });
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
      setMessage({ status: `Unbound ${workloadLabel(unbound)}.`, error: "" });
    } catch {
      setMessage({ status: "", error: "Unable to unbind workload." });
    } finally {
      setActiveWorkloadID("");
    }
  }

  return (
    <Card className="overflow-hidden">
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <CardTitle>Daemon Workloads</CardTitle>
          <div className="flex flex-wrap gap-2">
            <Button disabled={isTokenSubmitting} type="button" variant="secondary" onClick={handleTokenReveal}>
              <KeyRound className="h-4 w-4" />
              Reveal Token
            </Button>
            <Button disabled={isTokenSubmitting} type="button" variant="secondary" onClick={handleTokenReset}>
              <RefreshCcw className="h-4 w-4" />
              Reset Token
            </Button>
          </div>
        </div>
        <FormMessage error={message.error} status={message.status} />
      </CardHeader>
      <CardContent className="p-0">
        <Table className="rounded-none border-0">
          <thead>
            <tr className="bg-slate-50">
              <th className="p-3 text-left">Node</th>
              <th className="p-3 text-left">Workload</th>
              <th className="p-3 text-left">Bound App</th>
              <th className="p-3 text-left">Injection</th>
              <th className="p-3 text-left">Seen</th>
              <th className="p-3 text-left">Bind</th>
              <th className="p-3 text-left">Actions</th>
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
                    <td className="p-3 text-slate-600">{boundApplication?.name ?? workload.application_id ?? "unbound"}</td>
                    <td className="p-3">{injectionStatusCell(workload)}</td>
                    <td className="p-3 text-slate-600">{formatDate(workload.updated_at)}</td>
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
                          <option value="">No applications</option>
                        )}
                      </select>
                    </td>
                    <td className="p-3">
                      <div className="flex flex-wrap gap-2">
                        <Button disabled={activeWorkloadID === workload.id || applications.length === 0} type="button" variant="secondary" onClick={() => handleBind(workload)}>
                          <Link2 className="h-4 w-4" />
                          Bind
                        </Button>
                        <Button disabled={activeWorkloadID === workload.id || !workload.application_id} type="button" variant="secondary" onClick={() => handleUnbind(workload)}>
                          <Link2Off className="h-4 w-4" />
                          Unbind
                        </Button>
                      </div>
                    </td>
                  </tr>
                );
              })
            ) : (
              <tr className="border-t border-slate-200">
                <td className="p-3 text-slate-500" colSpan={7}>
                  No daemon workloads
                </td>
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
      setMessage({ status: "", error: "Managed artifact directory is not configured." });
      return;
    }
    if (!file) {
      setMessage({ status: "", error: "Choose an Agent ZIP package." });
      return;
    }
    if (!file.name.toLowerCase().endsWith(".zip")) {
      setMessage({ status: "", error: "Agent artifact must be a ZIP package." });
      return;
    }
    if (!normalizedSystemType || !normalizedLanguageVersion) {
      setMessage({ status: "", error: "System type and language version are required." });
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
      setMessage({ status: `Uploaded ${uploaded.filename} (${formatBytes(uploaded.size)}).`, error: "" });
    } catch {
      setMessage({ status: "", error: "Unable to upload Agent artifact." });
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <CardTitle>Agent Artifact Upload</CardTitle>
          <Badge tone={uploadAvailable ? "green" : "amber"}>{uploadAvailable ? "Managed Storage" : "Storage Unavailable"}</Badge>
        </div>
      </CardHeader>
      <CardContent>
        <form className="grid gap-3 md:grid-cols-2 xl:grid-cols-[1.4fr_.7fr_.8fr_auto] xl:items-end" onSubmit={handleUpload}>
          <label className={fieldGroupClass} htmlFor="artifact-upload-file">
            <span className={fieldLabelClass}>Agent ZIP</span>
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
            <span className={fieldLabelClass}>Upload System Type</span>
            <select
              id="artifact-upload-system-type"
              className={fieldControlClass}
              disabled={!uploadAvailable || isSubmitting}
              value={systemType}
              onChange={event => setSystemType(event.target.value)}
            >
              <option value="linux">linux</option>
              <option value="windows">windows</option>
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="artifact-upload-language-version">
            <span className={fieldLabelClass}>Upload Language Version</span>
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
            {isSubmitting ? "Uploading Artifact" : "Upload Artifact"}
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
          <CardTitle>Agent Artifact Catalog</CardTitle>
          <div className="flex flex-wrap gap-2">
            <Badge tone={catalog.artifact_dir_configured ? "green" : "amber"}>{catalog.artifact_dir_configured ? "Filesystem Pool" : "Generated Bootstrap"}</Badge>
            <Badge tone={catalog.generated_bootstrap_enabled ? "blue" : "neutral"}>{catalog.generated_bootstrap_enabled ? "Fallback Enabled" : "Filesystem Only"}</Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <Table className="rounded-none border-0">
          <thead>
            <tr className="bg-slate-50">
              <th className="p-3 text-left">Package</th>
              <th className="p-3 text-left">Runtime</th>
              <th className="p-3 text-left">Checksum</th>
              <th className="p-3 text-left">Size</th>
              <th className="p-3 text-left">Source</th>
              <th className="p-3 text-left">Updated</th>
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
                  <td className="p-3 text-slate-600">{formatDate(item.updated_at)}</td>
                </tr>
              ))
            ) : (
              <tr className="border-t border-slate-200">
                <td className="p-3 text-slate-500" colSpan={6}>
                  {catalog.generated_bootstrap_enabled ? "Generated bootstrap artifacts are available per application." : "No Agent artifacts discovered."}
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
      setMessage({ status: `Artifact ${info.filename} ready for ${selectedApplication.name}.`, error: "" });
    } catch {
      setMessage({ status: "", error: "Unable to verify Agent artifact." });
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
      const checksum = download.md5 ? ` MD5: ${download.md5}.` : "";
      setMessage({ status: `Downloaded ${download.filename} (${formatBytes(download.blob.size)}).${checksum}`, error: "" });
    } catch {
      setMessage({ status: "", error: "Unable to download Agent artifact." });
    } finally {
      setIsDownloading(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Agent Bootstrap Artifact</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4">
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-[1.2fr_1.1fr_.7fr_.8fr_auto_auto] xl:items-end">
          <label className={fieldGroupClass} htmlFor="artifact-application">
            <span className={fieldLabelClass}>Artifact Application</span>
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
                <option value="">No applications</option>
              )}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="artifact-daemon-token">
            <span className={fieldLabelClass}>Artifact Daemon Token</span>
            <input id="artifact-daemon-token" autoComplete="off" className={fieldControlClass} type="password" value={token} onChange={event => setToken(event.target.value)} />
          </label>
          <label className={fieldGroupClass} htmlFor="artifact-system-type">
            <span className={fieldLabelClass}>System Type</span>
            <select id="artifact-system-type" className={fieldControlClass} value={systemType} onChange={event => setSystemType(event.target.value)}>
              <option value="linux">linux</option>
              <option value="windows">windows</option>
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="artifact-language-version">
            <span className={fieldLabelClass}>Language Version</span>
            <input id="artifact-language-version" className={fieldControlClass} value={languageVersion} onChange={event => setLanguageVersion(event.target.value)} />
          </label>
          <Button disabled={isSubmitting || !selectedApplication} type="button" variant="secondary" onClick={handleArtifactCheck}>
            {isSubmitting ? "Checking Artifact" : "Check Agent Artifact"}
          </Button>
          <Button disabled={isDownloading || !selectedApplication} type="button" onClick={handleArtifactDownload}>
            {isDownloading ? "Downloading Artifact" : "Download Agent Artifact"}
          </Button>
        </div>
        <FormMessage error={message.error} status={message.status} />
        {artifact ? (
          <div className="grid gap-2 rounded-md border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700 md:grid-cols-2 xl:grid-cols-4">
            <div>
              <span className="block text-xs font-medium text-slate-500">MD5</span>
              <span className="break-all font-mono text-xs">{artifact.md5}</span>
            </div>
            <div>
              <span className="block text-xs font-medium text-slate-500">Size</span>
              <span>{formatBytes(artifact.size)}</span>
            </div>
            <div>
              <span className="block text-xs font-medium text-slate-500">Language</span>
              <span>{artifact.language}</span>
            </div>
            <div>
              <span className="block text-xs font-medium text-slate-500">System</span>
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
    return "Choose an application first.";
  }
  if (!token) {
    return "Daemon token is required.";
  }
  return "Artifact request is invalid.";
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
  const [hostname, setHostname] = useState("api-2");
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
      setMessage({ status: "", error: "Choose an application environment first." });
      return;
    }
    const trimmedSecret = applicationSecret.trim();
    const trimmedHostname = hostname.trim();
    const trimmedVersion = version.trim();
    if (!trimmedSecret || !trimmedHostname || !trimmedVersion) {
      setMessage({ status: "", error: "Application secret, hostname, and version are required." });
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
      setMessage({ status: `Registered Agent ${agent.hostname} as ${agent.id}.`, error: "" });
      setApplicationSecret("");
      setHostname("");
    } catch {
      setMessage({ status: "", error: "Unable to register Agent." });
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Agent Registration</CardTitle>
      </CardHeader>
      <CardContent>
        <form className="grid gap-3 md:grid-cols-2 xl:grid-cols-3" onSubmit={handleSubmit}>
          <label className={fieldGroupClass} htmlFor="agent-application">
            <span className={fieldLabelClass}>Application</span>
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
                <option value="">No applications</option>
              )}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="agent-environment">
            <span className={fieldLabelClass}>Environment</span>
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
                <option value="">No environments</option>
              )}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="agent-application-secret">
            <span className={fieldLabelClass}>Application Secret</span>
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
            <span className={fieldLabelClass}>Agent Hostname</span>
            <input id="agent-hostname" className={fieldControlClass} value={hostname} onChange={event => setHostname(event.target.value)} required />
          </label>
          <label className={fieldGroupClass} htmlFor="agent-runtime">
            <span className={fieldLabelClass}>Agent Runtime</span>
            <input id="agent-runtime" className={fieldControlClass} value={runtime} onChange={event => setRuntime(event.target.value)} />
          </label>
          <label className={fieldGroupClass} htmlFor="agent-version">
            <span className={fieldLabelClass}>Agent Version</span>
            <input id="agent-version" className={fieldControlClass} value={version} onChange={event => setVersion(event.target.value)} required />
          </label>
          <div className="flex flex-wrap items-center gap-3 md:col-span-2 xl:col-span-3">
            <Button disabled={isSubmitting || !selectedApplication || !environmentID} type="submit">
              {isSubmitting ? "Registering Agent" : "Register Agent"}
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
  const policies = policiesQuery.data?.items ?? policiesFallback().items;
  const applicationsQuery = useApplications();
  const applications = applicationsQuery.data?.items ?? applicationsFallback().items;
  const activePolicies = policies.filter(policy => policy.active).length;
  const ruleCount = policies.reduce((count, policy) => count + (policy.active?.rules.length ?? 0), 0);

  return (
    <SectionPage
      title={t("pages.policies.title")}
      summary={t("pages.policies.summary")}
    >
      <div className="grid gap-3 md:grid-cols-3">
        <Metric label="Policy Sets" value={policies.length} detail="managed rule groups" />
        <Metric label="Active" value={activePolicies} detail="serving policy versions" />
        <Metric label="Active Rules" value={ruleCount} detail="rules in deployed versions" />
      </div>
      <PolicySetCreatePanel />
      <PolicyWritePanel applications={applications} policies={policies} />
      <section className="grid gap-5 xl:grid-cols-[.8fr_1.2fr]">
        <PolicyLifecycle />
        <Table>
          <thead>
            <tr className="bg-slate-50">
              <th className="p-3 text-left">Policy</th>
              <th className="p-3 text-left">Active</th>
              <th className="p-3 text-right">Versions</th>
              <th className="p-3 text-right">Rules</th>
              <th className="p-3 text-left">Created</th>
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
                    {policy.active ? <Badge tone={statusTone(policy.active.status)}>{policy.active.status} v{policy.active.version}</Badge> : <Badge>No active</Badge>}
                  </td>
                  <td className="p-3 text-right text-slate-600">{policy.versions.length}</td>
                  <td className="p-3 text-right text-slate-600">{policy.active?.rules.length ?? 0}</td>
                  <td className="p-3 text-slate-600">{formatDate(policy.created_at)}</td>
                </tr>
              ))
            ) : (
              <tr className="border-t border-slate-200">
                <td className="p-3 text-slate-500" colSpan={5}>
                  No policies
                </td>
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
  const applications = applicationsQuery.data?.items ?? applicationsFallback().items;
  const agents = agentsQuery.data?.items ?? agentsFallback().items;
  const policies = policiesQuery.data?.items ?? policiesFallback().items;
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
  const baselineFindingsQuery = useBaselineFindings(baselineQuery);
  const attackEvents = attackQuery.data?.items ?? attackEventsFallback().items;
  const hookEvents = hookQuery.data?.items ?? eventFallbackByType("hook").items;
  const performanceEvents = performanceQuery.data?.items ?? eventFallbackByType("performance").items;
  const crashEvents = crashQuery.data?.items ?? eventFallbackByType("crash").items;
  const deletedEvents = deletedEventsQuery.data?.items ?? [];
  const dependencies = dependenciesQuery.data?.items ?? dependenciesFallback().items;
  const baselineFindings = baselineFindingsQuery.data?.items ?? baselineFindingsFallback().items;
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
      setRecycleMessage({ status: "", error: "Choose an event first." });
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
      const verb = action === "delete" ? "Moved" : action === "restore" ? "Restored" : "Purged";
      setRecycleMessage({ status: `${verb} ${report.count} event${report.count === 1 ? "" : "s"}.`, error: "" });
    } catch {
      setRecycleMessage({ status: "", error: "Unable to update the event recycle bin." });
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

  return (
    <SectionPage
      title={t("pages.events.title")}
      summary={t("pages.events.summary")}
    >
      <div className="grid gap-3 md:grid-cols-4">
        <Metric label="Security Events" value={allEvents.length} detail="attack, Hook, performance, crash" />
        <Metric label="Critical" value={criticalEvents} detail="requires immediate review" />
        <Metric label="Dependencies" value={dependencies.length} detail={`${highEvents} high event signals`} />
        <Metric label="Baseline Findings" value={baselineFindings.length} detail={`${failedBaselineFindings} open posture signals`} />
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Event Query</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <label className={fieldGroupClass} htmlFor="event-application">
            <span className={fieldLabelClass}>Event Application</span>
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
              <option value="">All Applications</option>
              {applications.map(application => (
                <option key={application.id} value={application.id}>
                  {application.name}
                </option>
              ))}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="event-environment">
            <span className={fieldLabelClass}>Event Environment</span>
            <select id="event-environment" className={fieldControlClass} value={eventEnvironmentID} onChange={event => setEventEnvironmentID(event.target.value)}>
              <option value="">All Environments</option>
              {eventEnvironmentOptions.map(environmentID => (
                <option key={environmentID} value={environmentID}>
                  {environmentID}
                </option>
              ))}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="event-agent">
            <span className={fieldLabelClass}>Event Agent</span>
            <select id="event-agent" className={fieldControlClass} value={eventAgentID} onChange={event => setEventAgentID(event.target.value)}>
              <option value="">All Agents</option>
              {eventAgents.map(agent => (
                <option key={agent.id} value={agent.id}>
                  {agent.hostname}
                </option>
              ))}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="event-policy">
            <span className={fieldLabelClass}>Event Policy</span>
            <select id="event-policy" className={fieldControlClass} value={eventPolicyID} onChange={event => setEventPolicyID(event.target.value)}>
              <option value="">All Policies</option>
              {policies.map(policy => (
                <option key={policy.id} value={policy.id}>
                  {policy.name}
                </option>
              ))}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="event-severity">
            <span className={fieldLabelClass}>Event Severity</span>
            <select id="event-severity" className={fieldControlClass} value={eventSeverity} onChange={event => setEventSeverity(event.target.value)}>
              <option value="">All Severities</option>
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="event-hook">
            <span className={fieldLabelClass}>Event Hook</span>
            <input id="event-hook" className={fieldControlClass} value={eventHook} onChange={event => setEventHook(event.target.value)} />
          </label>
          <label className={fieldGroupClass} htmlFor="event-occurred-after">
            <span className={fieldLabelClass}>Occurred After</span>
            <input
              id="event-occurred-after"
              className={fieldControlClass}
              type="datetime-local"
              value={eventOccurredAfter}
              onChange={event => setEventOccurredAfter(event.target.value)}
            />
          </label>
          <label className={fieldGroupClass} htmlFor="event-occurred-before">
            <span className={fieldLabelClass}>Occurred Before</span>
            <input
              id="event-occurred-before"
              className={fieldControlClass}
              type="datetime-local"
              value={eventOccurredBefore}
              onChange={event => setEventOccurredBefore(event.target.value)}
            />
          </label>
          <label className={fieldGroupClass} htmlFor="event-limit">
            <span className={fieldLabelClass}>Event Limit</span>
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
              Clear Filters
            </Button>
          </div>
        </CardContent>
      </Card>
      <section className="grid gap-5 xl:grid-cols-[.8fr_1.2fr]">
        <Table>
          <thead>
            <tr className="bg-slate-50">
              <th className="p-3 text-left">Event</th>
              <th className="p-3 text-left">Storage</th>
              <th className="p-3 text-left">Use</th>
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
              <th className="p-3 text-left">Type</th>
              <th className="p-3 text-left">Message</th>
              <th className="p-3 text-left">Hook</th>
              <th className="p-3 text-left">Severity</th>
              <th className="p-3 text-left">Occurred</th>
            </tr>
          </thead>
          <tbody>
            {allEvents.length > 0 ? (
              allEvents.map(event => (
                <tr key={event.id} className="border-t border-slate-200">
                  <td className="p-3">
                    <Badge tone={eventTypeTone(event.type)}>{event.type}</Badge>
                  </td>
                  <td className="p-3 font-medium">{event.message}</td>
                  <td className="p-3 text-slate-600">{event.hook || "unknown"}</td>
                  <td className="p-3">
                    <Badge tone={severityTone(event.severity)}>{event.severity}</Badge>
                  </td>
                  <td className="p-3 text-slate-600">{formatDate(event.occurred_at)}</td>
                </tr>
              ))
            ) : (
              <tr className="border-t border-slate-200">
                <td className="p-3 text-slate-500" colSpan={5}>
                  No security events
                </td>
              </tr>
            )}
          </tbody>
        </Table>
      </section>
      <Card className="overflow-hidden">
        <CardHeader>
          <CardTitle>Event Recycle Bin</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4">
          <div className="grid gap-3 md:grid-cols-[1fr_auto_auto_auto] md:items-end">
            <label className={fieldGroupClass} htmlFor="event-recycle-id">
              <span className={fieldLabelClass}>Recycle Event ID</span>
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
                      {event.id} / {event.type} / {event.deleted_at ? "deleted" : "active"}
                    </option>
                  ))
                ) : (
                  <option value="">No events</option>
                )}
              </select>
            </label>
            <Button disabled={isRecyclingEvent || !recycleEventID} type="button" variant="secondary" onClick={() => void handleRecycleAction("delete")}>
              Move Event To Recycle Bin
            </Button>
            <Button disabled={isRecyclingEvent || !recycleEventID} type="button" variant="secondary" onClick={() => void handleRecycleAction("restore")}>
              Restore Event
            </Button>
            <Button disabled={isRecyclingEvent || !recycleEventID} type="button" onClick={() => void handleRecycleAction("purge")}>
              Permanently Delete Event
            </Button>
          </div>
          <FormMessage error={recycleMessage.error} status={recycleMessage.status} />
          <Table className="rounded-none border-0">
            <thead>
              <tr className="bg-slate-50">
                <th className="p-3 text-left">Type</th>
                <th className="p-3 text-left">Message</th>
                <th className="p-3 text-left">Deleted</th>
                <th className="p-3 text-left">Deleted By</th>
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
                    </td>
                    <td className="p-3 text-slate-600">{formatDate(event.deleted_at)}</td>
                    <td className="p-3 text-slate-600">{event.deleted_by || "unknown"}</td>
                  </tr>
                ))
              ) : (
                <tr className="border-t border-slate-200">
                  <td className="p-3 text-slate-500" colSpan={4}>
                    No deleted events
                  </td>
                </tr>
              )}
            </tbody>
          </Table>
        </CardContent>
      </Card>
      <section className="grid gap-5">
        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle>Dependency Inventory</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="grid gap-3 border-b border-slate-200 p-4 md:grid-cols-2 xl:grid-cols-4">
              <label className={fieldGroupClass} htmlFor="dependency-application">
                <span className={fieldLabelClass}>Dependency Application</span>
                <select
                  id="dependency-application"
                  className={fieldControlClass}
                  value={dependencyApplicationID}
                  onChange={event => {
                    setDependencyApplicationID(event.target.value);
                    setDependencyAgentID("");
                  }}
                >
                  <option value="">All Applications</option>
                  {applications.map(application => (
                    <option key={application.id} value={application.id}>
                      {application.name}
                    </option>
                  ))}
                </select>
              </label>
              <label className={fieldGroupClass} htmlFor="dependency-agent">
                <span className={fieldLabelClass}>Dependency Agent</span>
                <select id="dependency-agent" className={fieldControlClass} value={dependencyAgentID} onChange={event => setDependencyAgentID(event.target.value)}>
                  <option value="">All Agents</option>
                  {dependencyAgents.map(agent => (
                    <option key={agent.id} value={agent.id}>
                      {agent.hostname}
                    </option>
                  ))}
                </select>
              </label>
              <label className={fieldGroupClass} htmlFor="dependency-name">
                <span className={fieldLabelClass}>Dependency Name</span>
                <input id="dependency-name" className={fieldControlClass} value={dependencyName} onChange={event => setDependencyName(event.target.value)} />
              </label>
              <label className={fieldGroupClass} htmlFor="dependency-ecosystem">
                <span className={fieldLabelClass}>Dependency Ecosystem</span>
                <input id="dependency-ecosystem" className={fieldControlClass} value={dependencyEcosystem} onChange={event => setDependencyEcosystem(event.target.value)} />
              </label>
              <label className={fieldGroupClass} htmlFor="dependency-vulnerability-severity">
                <span className={fieldLabelClass}>Dependency Severity</span>
                <select
                  id="dependency-vulnerability-severity"
                  className={fieldControlClass}
                  value={dependencyVulnerabilitySeverity}
                  onChange={event => setDependencyVulnerabilitySeverity(event.target.value)}
                >
                  <option value="">All Severities</option>
                  <option value="critical">critical</option>
                  <option value="high">high</option>
                  <option value="medium">medium</option>
                  <option value="low">low</option>
                </select>
              </label>
              <label className={fieldGroupClass} htmlFor="dependency-observed-after">
                <span className={fieldLabelClass}>Observed After</span>
                <input
                  id="dependency-observed-after"
                  className={fieldControlClass}
                  type="datetime-local"
                  value={dependencyObservedAfter}
                  onChange={event => setDependencyObservedAfter(event.target.value)}
                />
              </label>
              <label className={fieldGroupClass} htmlFor="dependency-observed-before">
                <span className={fieldLabelClass}>Observed Before</span>
                <input
                  id="dependency-observed-before"
                  className={fieldControlClass}
                  type="datetime-local"
                  value={dependencyObservedBefore}
                  onChange={event => setDependencyObservedBefore(event.target.value)}
                />
              </label>
              <label className={fieldGroupClass} htmlFor="dependency-limit">
                <span className={fieldLabelClass}>Dependency Limit</span>
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
                  Clear Dependency Filters
                </Button>
              </div>
            </div>
            <Table className="rounded-none border-0">
              <thead>
                <tr className="bg-slate-50">
                  <th className="p-3 text-left">Dependency</th>
                  <th className="p-3 text-left">Version</th>
                  <th className="p-3 text-left">Ecosystem</th>
                  <th className="p-3 text-left">Licenses</th>
                  <th className="p-3 text-left">Vulnerabilities</th>
                  <th className="p-3 text-left">Observed</th>
                </tr>
              </thead>
              <tbody>
                {dependencies.length > 0 ? (
                  dependencies.map(dep => (
                    <tr key={dep.id} className="border-t border-slate-200">
                      <td className="p-3">
                        <div className="font-medium">{dep.name}</div>
                        <div className="max-w-xs truncate text-xs text-slate-500">{dep.package_path || dep.agent_id || "unattributed"}</div>
                      </td>
                      <td className="p-3 text-slate-600">{dep.version || "unknown"}</td>
                      <td className="p-3 text-slate-600">{dep.ecosystem || "unknown"}</td>
                      <td className="p-3 text-slate-600">{dep.licenses?.length ? dep.licenses.join(", ") : "unknown"}</td>
                      <td className="p-3">
                        <div className="flex flex-wrap gap-1">
                          {dep.vulnerabilities?.length ? (
                            dep.vulnerabilities.slice(0, 3).map(vulnerability => (
                              <Badge key={`${dep.id}-${vulnerability.id}`} tone={severityTone(vulnerability.severity)}>
                                {vulnerability.id}
                              </Badge>
                            ))
                          ) : (
                            <span className="text-slate-500">none</span>
                          )}
                        </div>
                      </td>
                      <td className="p-3 text-slate-600">{formatDate(dep.observed_at)}</td>
                    </tr>
                  ))
                ) : (
                  <tr className="border-t border-slate-200">
                    <td className="p-3 text-slate-500" colSpan={6}>
                      No dependency observations
                    </td>
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
            <CardTitle>Baseline Findings</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="grid gap-3 border-b border-slate-200 p-4 md:grid-cols-2 xl:grid-cols-4">
              <label className={fieldGroupClass} htmlFor="baseline-application">
                <span className={fieldLabelClass}>Baseline Application</span>
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
                  <option value="">All Applications</option>
                  {applications.map(application => (
                    <option key={application.id} value={application.id}>
                      {application.name}
                    </option>
                  ))}
                </select>
              </label>
              <label className={fieldGroupClass} htmlFor="baseline-environment">
                <span className={fieldLabelClass}>Baseline Environment</span>
                <select id="baseline-environment" className={fieldControlClass} value={baselineEnvironmentID} onChange={event => setBaselineEnvironmentID(event.target.value)}>
                  <option value="">All Environments</option>
                  {baselineEnvironmentOptions.map(environmentID => (
                    <option key={environmentID} value={environmentID}>
                      {environmentID}
                    </option>
                  ))}
                </select>
              </label>
              <label className={fieldGroupClass} htmlFor="baseline-agent">
                <span className={fieldLabelClass}>Baseline Agent</span>
                <select id="baseline-agent" className={fieldControlClass} value={baselineAgentID} onChange={event => setBaselineAgentID(event.target.value)}>
                  <option value="">All Agents</option>
                  {baselineAgents.map(agent => (
                    <option key={agent.id} value={agent.id}>
                      {agent.hostname}
                    </option>
                  ))}
                </select>
              </label>
              <label className={fieldGroupClass} htmlFor="baseline-severity">
                <span className={fieldLabelClass}>Baseline Severity</span>
                <select id="baseline-severity" className={fieldControlClass} value={baselineSeverity} onChange={event => setBaselineSeverity(event.target.value)}>
                  <option value="">All Severities</option>
                  <option value="critical">critical</option>
                  <option value="high">high</option>
                  <option value="medium">medium</option>
                  <option value="low">low</option>
                  <option value="info">info</option>
                </select>
              </label>
              <label className={fieldGroupClass} htmlFor="baseline-status">
                <span className={fieldLabelClass}>Baseline Status</span>
                <select id="baseline-status" className={fieldControlClass} value={baselineStatus} onChange={event => setBaselineStatus(event.target.value)}>
                  <option value="">All Statuses</option>
                  <option value="failed">failed</option>
                  <option value="warning">warning</option>
                  <option value="passed">passed</option>
                  <option value="suppressed">suppressed</option>
                </select>
              </label>
              <label className={fieldGroupClass} htmlFor="baseline-category">
                <span className={fieldLabelClass}>Baseline Category</span>
                <input id="baseline-category" className={fieldControlClass} value={baselineCategory} onChange={event => setBaselineCategory(event.target.value)} />
              </label>
              <label className={fieldGroupClass} htmlFor="baseline-observed-after">
                <span className={fieldLabelClass}>Baseline Observed After</span>
                <input
                  id="baseline-observed-after"
                  className={fieldControlClass}
                  type="datetime-local"
                  value={baselineObservedAfter}
                  onChange={event => setBaselineObservedAfter(event.target.value)}
                />
              </label>
              <label className={fieldGroupClass} htmlFor="baseline-observed-before">
                <span className={fieldLabelClass}>Baseline Observed Before</span>
                <input
                  id="baseline-observed-before"
                  className={fieldControlClass}
                  type="datetime-local"
                  value={baselineObservedBefore}
                  onChange={event => setBaselineObservedBefore(event.target.value)}
                />
              </label>
              <label className={fieldGroupClass} htmlFor="baseline-limit">
                <span className={fieldLabelClass}>Baseline Limit</span>
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
                  Clear Baseline Filters
                </Button>
              </div>
            </div>
            <Table className="rounded-none border-0">
              <thead>
                <tr className="bg-slate-50">
                  <th className="p-3 text-left">Finding</th>
                  <th className="p-3 text-left">Category</th>
                  <th className="p-3 text-left">Severity</th>
                  <th className="p-3 text-left">Status</th>
                  <th className="p-3 text-left">Resource</th>
                  <th className="p-3 text-left">Observed</th>
                </tr>
              </thead>
              <tbody>
                {baselineFindings.length > 0 ? (
                  baselineFindings.map(finding => (
                    <tr key={finding.id} className="border-t border-slate-200">
                      <td className="p-3">
                        <div className="font-medium">{finding.title}</div>
                        <div className="text-xs text-slate-500">{finding.check_id}</div>
                      </td>
                      <td className="p-3 text-slate-600">{finding.category || "runtime"}</td>
                      <td className="p-3">
                        <Badge tone={severityTone(finding.severity)}>{finding.severity}</Badge>
                      </td>
                      <td className="p-3">
                        <Badge tone={baselineStatusTone(finding.status)}>{finding.status}</Badge>
                      </td>
                      <td className="p-3 text-slate-600">{finding.resource || finding.agent_id}</td>
                      <td className="p-3 text-slate-600">{formatDate(finding.observed_at)}</td>
                    </tr>
                  ))
                ) : (
                  <tr className="border-t border-slate-200">
                    <td className="p-3 text-slate-500" colSpan={6}>
                      No baseline findings
                    </td>
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
  const applications = applicationsQuery.data?.items ?? applicationsFallback().items;
  const policies = policiesQuery.data?.items ?? policiesFallback().items;
  const [observabilityApplicationID, setObservabilityApplicationID] = useState("");
  const [observabilityPolicyID, setObservabilityPolicyID] = useState("");
  const observabilityQuery = useObservability({
    applicationID: observabilityApplicationID || undefined,
    policyID: observabilityPolicyID || undefined
  });
  const report = observabilityQuery.data ?? observabilityFallback();
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
      <div className="grid gap-3 md:grid-cols-4">
        <Metric label="Hook p95" value={formatLatency(topHook?.p95_latency_us)} detail={topHook ? `${topHook.hook} hook` : "no samples"} />
        <Metric label="Rule p95" value={formatLatency(topRule?.p95_latency_us)} detail={topRule ? `${topRule.rule_id} on ${topRule.hook}` : "no samples"} />
        <Metric label="Agent CPU" value={formatPercent(topAgent?.cpu_overhead_pct)} detail={topAgent ? `${topAgent.agent_id} median` : "no samples"} />
        <Metric label="Rule Eval" value={formatLatency(topPolicy?.rule_eval_p95_us)} detail={topPolicy ? `${topPolicy.policy_id} v${topPolicy.policy_version}` : "no samples"} />
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Observability Filters</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-3 md:grid-cols-3">
          <label className={fieldGroupClass} htmlFor="observability-application">
            <span className={fieldLabelClass}>Observability Application</span>
            <select
              id="observability-application"
              className={fieldControlClass}
              value={observabilityApplicationID}
              onChange={event => setObservabilityApplicationID(event.target.value)}
            >
              <option value="">All Applications</option>
              {applications.map(application => (
                <option key={application.id} value={application.id}>
                  {application.name}
                </option>
              ))}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="observability-policy">
            <span className={fieldLabelClass}>Observability Policy</span>
            <select id="observability-policy" className={fieldControlClass} value={observabilityPolicyID} onChange={event => setObservabilityPolicyID(event.target.value)}>
              <option value="">All Policies</option>
              {policies.map(policy => (
                <option key={policy.id} value={policy.id}>
                  {policy.name}
                </option>
              ))}
            </select>
          </label>
          <div className="flex items-end">
            <Button className="w-full" type="button" variant="secondary" onClick={clearObservabilityFilters}>
              Clear Observability Filters
            </Button>
          </div>
        </CardContent>
      </Card>
      <div className="grid gap-5 xl:grid-cols-2">
        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle>Rule Overhead</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table className="rounded-none border-0">
              <thead>
                <tr className="bg-slate-50">
                  <th className="p-3 text-left">Rule</th>
                  <th className="p-3 text-left">Hook</th>
                  <th className="p-3 text-right">Exec</th>
                  <th className="p-3 text-right">Blocked</th>
                  <th className="p-3 text-right">p95</th>
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
                      No samples
                    </td>
                  </tr>
                )}
              </tbody>
            </Table>
          </CardContent>
        </Card>

        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle>Hook Latency</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table className="rounded-none border-0">
              <thead>
                <tr className="bg-slate-50">
                  <th className="p-3 text-left">Hook</th>
                  <th className="p-3 text-right">Calls</th>
                  <th className="p-3 text-right">Avg</th>
                  <th className="p-3 text-right">p95</th>
                  <th className="p-3 text-right">Max</th>
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
                      No samples
                    </td>
                  </tr>
                )}
              </tbody>
            </Table>
          </CardContent>
        </Card>

        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle>Agent Overhead</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table className="rounded-none border-0">
              <thead>
                <tr className="bg-slate-50">
                  <th className="p-3 text-left">Agent</th>
                  <th className="p-3 text-right">Samples</th>
                  <th className="p-3 text-right">CPU</th>
                  <th className="p-3 text-right">Memory</th>
                  <th className="p-3 text-right">Rule p95</th>
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
                      No samples
                    </td>
                  </tr>
                )}
              </tbody>
            </Table>
          </CardContent>
        </Card>

        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle>Policy Impact</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table className="rounded-none border-0">
              <thead>
                <tr className="bg-slate-50">
                  <th className="p-3 text-left">Policy</th>
                  <th className="p-3 text-right">Version</th>
                  <th className="p-3 text-right">Samples</th>
                  <th className="p-3 text-right">CPU</th>
                  <th className="p-3 text-right">Hook p95</th>
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
                      No samples
                    </td>
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
  const auditLogs = auditQuery.data?.items ?? auditLogsFallback().items;
  const settingsQuery = useSystemSettings();
  const settings = settingsQuery.data?.items ?? systemSettingsFallback().items;
  const editionQuery = useEditionStatus();
  const edition = editionQuery.data ?? editionStatusFallback();
  const alertRulesQuery = useAlertRules();
  const alertRules = alertRulesQuery.data?.items ?? alertRulesFallback().items;
  const alertDeliveriesQuery = useAlertDeliveries();
  const alertDeliveries = alertDeliveriesQuery.data?.items ?? alertDeliveriesFallback().items;
  const usersQuery = useUsers();
  const users = usersQuery.data?.items ?? usersFallback().items;

  return (
    <SectionPage
      title={t("pages.access.title")}
      summary={t("pages.access.summary")}
    >
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
            <CardTitle>User Administration</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table className="rounded-none border-0">
              <thead>
                <tr className="bg-slate-50">
                  <th className="p-3 text-left">User</th>
                  <th className="p-3 text-left">Roles</th>
                  <th className="p-3 text-left">Status</th>
                  <th className="p-3 text-left">Updated</th>
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
                        <Badge tone={user.disabled_at ? "neutral" : "green"}>{user.disabled_at ? "disabled" : "active"}</Badge>
                      </td>
                      <td className="p-3 text-slate-600">{formatDate(user.updated_at)}</td>
                    </tr>
                  ))
                ) : (
                  <tr className="border-t border-slate-200">
                    <td className="p-3 text-slate-500" colSpan={4}>
                      No users
                    </td>
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
            <CardTitle>System Settings</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table className="rounded-none border-0">
              <thead>
                <tr className="bg-slate-50">
                  <th className="p-3 text-left">Key</th>
                  <th className="p-3 text-left">Value</th>
                  <th className="p-3 text-left">Updated</th>
                </tr>
              </thead>
              <tbody>
                {settings.length > 0 ? (
                  settings.map(setting => (
                    <tr key={setting.key} className="border-t border-slate-200">
                      <td className="p-3 font-medium">{setting.key}</td>
                      <td className="p-3 text-slate-600">{formatDetails(setting.value)}</td>
                      <td className="p-3 text-slate-600">{formatDate(setting.updated_at)}</td>
                    </tr>
                  ))
                ) : (
                  <tr className="border-t border-slate-200">
                    <td className="p-3 text-slate-500" colSpan={3}>
                      No settings
                    </td>
                  </tr>
                )}
              </tbody>
            </Table>
          </CardContent>
        </Card>
        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle>Alert Rules</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table className="rounded-none border-0">
              <thead>
                <tr className="bg-slate-50">
                  <th className="p-3 text-left">Rule</th>
                  <th className="p-3 text-left">Event</th>
                  <th className="p-3 text-left">Severity</th>
                  <th className="p-3 text-left">Target</th>
                  <th className="p-3 text-left">Status</th>
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
                        <Badge tone={rule.enabled ? "green" : "neutral"}>{rule.enabled ? "enabled" : "disabled"}</Badge>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr className="border-t border-slate-200">
                    <td className="p-3 text-slate-500" colSpan={5}>
                      No alert rules
                    </td>
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
            <CardTitle>Alert Delivery History</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table className="rounded-none border-0">
              <thead>
                <tr className="bg-slate-50">
                  <th className="p-3 text-left">Alert</th>
                  <th className="p-3 text-left">Event</th>
                  <th className="p-3 text-left">Severity</th>
                  <th className="p-3 text-left">Target</th>
                  <th className="p-3 text-left">Status</th>
                  <th className="p-3 text-left">Created</th>
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
                      <td className="p-3 text-slate-600">{formatDate(delivery.created_at)}</td>
                    </tr>
                  ))
                ) : (
                  <tr className="border-t border-slate-200">
                    <td className="p-3 text-slate-500" colSpan={6}>
                      No alert deliveries
                    </td>
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
            <CardTitle>Audit Log</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table className="rounded-none border-0">
              <thead>
                <tr className="bg-slate-50">
                  <th className="p-3 text-left">Action</th>
                  <th className="p-3 text-left">Actor</th>
                  <th className="p-3 text-left">Resource</th>
                  <th className="p-3 text-left">Created</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.length > 0 ? (
                  auditLogs.map(log => (
                    <tr key={log.id} className="border-t border-slate-200">
                      <td className="p-3 font-medium">{log.action}</td>
                      <td className="p-3 text-slate-600">{log.actor_id || "system"}</td>
                      <td className="p-3 text-slate-600">{log.resource}</td>
                      <td className="p-3 text-slate-600">{formatDate(log.created_at)}</td>
                    </tr>
                  ))
                ) : (
                  <tr className="border-t border-slate-200">
                    <td className="p-3 text-slate-500" colSpan={4}>
                      No audit logs
                    </td>
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
        <CardTitle>Edition Status</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid gap-4 md:grid-cols-4">
          <div>
            <span className="block text-xs font-medium text-slate-500">Edition</span>
            <span className="mt-1 block font-medium text-slate-950">{edition.display_name}</span>
          </div>
          <div>
            <span className="block text-xs font-medium text-slate-500">Deployment</span>
            <span className="mt-1 block font-medium text-slate-950">{formatLabel(edition.deployment_model)}</span>
          </div>
          <div>
            <span className="block text-xs font-medium text-slate-500">License</span>
            <span className="mt-1 block font-medium text-slate-950">{edition.license_required ? "Required" : "Not required"}</span>
          </div>
          <div>
            <span className="block text-xs font-medium text-slate-500">Enforcement</span>
            <Badge className="mt-1" tone={edition.license_enforcement === "none" ? "green" : "amber"}>
              {formatLabel(edition.license_enforcement)}
            </Badge>
          </div>
        </div>
        {edition.note ? <p className="mt-4 text-sm leading-6 text-slate-600">{edition.note}</p> : null}
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
      setMessage({ status: "", error: "Choose an alert rule first." });
      return;
    }
    const trimmedName = name.trim();
    const trimmedTarget = target.trim();
    if (!trimmedName || !trimmedTarget) {
      setMessage({ status: "", error: "Alert name and target are required." });
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
      setMessage({ status: `Updated alert rule ${updated.name}.`, error: "" });
    } catch {
      setMessage({ status: "", error: "Unable to update alert rule." });
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Alert Lifecycle</CardTitle>
      </CardHeader>
      <CardContent>
        <form className="grid gap-3 md:grid-cols-2 xl:grid-cols-4" onSubmit={handleSubmit}>
          <label className={fieldGroupClass} htmlFor="alert-lifecycle-rule">
            <span className={fieldLabelClass}>Alert Rule</span>
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
                <option value="">No alert rules</option>
              )}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="alert-lifecycle-name">
            <span className={fieldLabelClass}>Alert Name</span>
            <input id="alert-lifecycle-name" className={fieldControlClass} value={name} onChange={event => setName(event.target.value)} required />
          </label>
          <label className={fieldGroupClass} htmlFor="alert-lifecycle-event-type">
            <span className={fieldLabelClass}>Alert Event Type</span>
            <select id="alert-lifecycle-event-type" className={fieldControlClass} value={eventType} onChange={event => setEventType(event.target.value)}>
              <option value="attack">attack</option>
              <option value="hook">hook</option>
              <option value="performance">performance</option>
              <option value="crash">crash</option>
              <option value="dependency">dependency</option>
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="alert-lifecycle-severity">
            <span className={fieldLabelClass}>Alert Severity</span>
            <select id="alert-lifecycle-severity" className={fieldControlClass} value={severity} onChange={event => setSeverity(event.target.value)}>
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="alert-lifecycle-description">
            <span className={fieldLabelClass}>Alert Description</span>
            <input id="alert-lifecycle-description" className={fieldControlClass} value={description} onChange={event => setDescription(event.target.value)} />
          </label>
          <label className={fieldGroupClass} htmlFor="alert-lifecycle-condition">
            <span className={fieldLabelClass}>Alert Condition</span>
            <input id="alert-lifecycle-condition" className={fieldControlClass} value={condition} onChange={event => setCondition(event.target.value)} />
          </label>
          <label className={fieldGroupClass} htmlFor="alert-lifecycle-target">
            <span className={fieldLabelClass}>Alert Target</span>
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
            Enable Alert Rule
          </label>
          <div className="flex flex-wrap items-center gap-3 md:col-span-2 xl:col-span-4">
            <Button disabled={isSubmitting || !selectedRule} type="submit">
              {isSubmitting ? "Updating Alert Rule" : "Update Alert Rule"}
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
      setMessage({ status: "", error: "Choose a user first." });
      return;
    }
    const trimmedName = name.trim();
    if (!trimmedName) {
      setMessage({ status: "", error: "User display name is required." });
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
      setMessage({ status: `Updated user ${updated.email}.`, error: "" });
    } catch {
      setMessage({ status: "", error: "Unable to update user." });
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>User Lifecycle</CardTitle>
      </CardHeader>
      <CardContent>
        <form className="grid gap-3 md:grid-cols-[1.2fr_1fr_.8fr_auto] md:items-end" onSubmit={handleSubmit}>
          <label className={fieldGroupClass} htmlFor="user-lifecycle-user">
            <span className={fieldLabelClass}>User Account</span>
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
                <option value="">No users</option>
              )}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="user-lifecycle-name">
            <span className={fieldLabelClass}>User Display Name</span>
            <input id="user-lifecycle-name" className={fieldControlClass} value={name} onChange={event => setName(event.target.value)} required />
          </label>
          <label className={fieldGroupClass} htmlFor="user-lifecycle-role">
            <span className={fieldLabelClass}>User Role</span>
            <select id="user-lifecycle-role" className={fieldControlClass} value={role} onChange={event => setRole(event.target.value as UserRole)}>
              <option value="admin">Admin</option>
              <option value="security_engineer">Security Engineer</option>
              <option value="viewer">Viewer</option>
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
            Disable User
          </label>
          <div className="flex flex-wrap items-center gap-3 md:col-span-4">
            <Button disabled={isSubmitting || !selectedUser} type="submit">
              {isSubmitting ? "Updating User" : "Update User"}
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
  const [name, setName] = useState("Runtime Protection");
  const [description, setDescription] = useState("Application-specific Java RASP policy set");
  const [message, setMessage] = useState({ status: "", error: "" });
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage({ status: "", error: "" });
    const trimmedName = name.trim();
    if (!trimmedName) {
      setMessage({ status: "", error: "Policy set name is required." });
      return;
    }
    setIsSubmitting(true);
    try {
      const policy = await createPolicy({
        name: trimmedName,
        description: description.trim() || undefined
      });
      await queryClient.invalidateQueries({ queryKey: ["policies"] });
      setMessage({ status: `Created policy set ${policy.name}.`, error: "" });
      setName("");
      setDescription("");
    } catch {
      setMessage({ status: "", error: "Unable to create policy set." });
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Policy Set</CardTitle>
      </CardHeader>
      <CardContent>
        <form className="grid gap-3 md:grid-cols-[1fr_1.4fr_auto] md:items-end" onSubmit={handleSubmit}>
          <label className={fieldGroupClass} htmlFor="policy-set-name">
            <span className={fieldLabelClass}>Policy Set Name</span>
            <input id="policy-set-name" className={fieldControlClass} value={name} onChange={event => setName(event.target.value)} required />
          </label>
          <label className={fieldGroupClass} htmlFor="policy-set-description">
            <span className={fieldLabelClass}>Policy Description</span>
            <input id="policy-set-description" className={fieldControlClass} value={description} onChange={event => setDescription(event.target.value)} />
          </label>
          <Button disabled={isSubmitting} type="submit">
            {isSubmitting ? "Creating Policy Set" : "Create Policy Set"}
          </Button>
          <div className="md:col-span-3">
            <FormMessage error={message.error} status={message.status} />
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function PolicyWritePanel({ applications, policies }: { applications: Application[]; policies: PolicySet[] }) {
  const queryClient = useQueryClient();
  const [policyID, setPolicyID] = useState(policies[0]?.id ?? "");
  const [ruleName, setRuleName] = useState("Block suspicious command");
  const [hook, setHook] = useState("process");
  const [expression, setExpression] = useState("Runtime.exec");
  const [action, setAction] = useState("block");
  const [severity, setSeverity] = useState("high");
  const [tags, setTags] = useState("command, runtime");
  const [targetVersion, setTargetVersion] = useState(1);
  const [canaryPercent, setCanaryPercent] = useState(25);
  const [rolloutScope, setRolloutScope] = useState("global");
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const selectedPolicy = policies.find(policy => policy.id === policyID) ?? policies[0];
  const rolloutScopeOptions = policyRolloutScopeOptions(applications);
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
        setStatus(`Created policy version ${latestVersion.version}.`);
      } else {
        setStatus("Created policy version.");
      }
    } catch {
      setError("Unable to create policy version.");
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleUpdateDraft() {
    if (!selectedPolicy) {
      return;
    }
    if (!Number.isInteger(targetVersion) || targetVersion <= 0) {
      setError("Choose a draft policy version.");
      return;
    }
    setIsSubmitting(true);
    setStatus("");
    setError("");
    try {
      await updatePolicyVersionRules(selectedPolicy.id, targetVersion, [draftRule(selectedVersion?.status === "draft" ? selectedVersion.rules[0]?.id : undefined)]);
      await queryClient.invalidateQueries({ queryKey: ["policies"] });
      setStatus(`Updated policy version ${targetVersion}.`);
    } catch {
      setError("Unable to update draft version.");
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
        setStatus("Rule validation passed.");
      } else {
        setError(validation.errors.join("; ") || "Rule validation failed.");
      }
    } catch {
      setError("Unable to validate rule.");
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleTestDraft() {
    if (!selectedPolicy) {
      return;
    }
    setIsSubmitting(true);
    setStatus("");
    setError("");
    try {
      const rule = draftRule();
      const result = await testRule(rule, {
        application_id: "app_console_test",
        environment_id: "env_console_test",
        agent_id: "agt_console_test",
        policy_id: selectedPolicy.id,
        policy_version: targetVersion,
        hook: rule.hook,
        algorithm: rule.algorithm,
        severity,
        message: `Console simulation for ${rule.expression}`,
        attributes: { source: "policy-console" }
      });
      setStatus(result.matched ? `Rule test matched: ${result.action || "no action"} at ${result.confidence}% confidence.` : "Rule test did not match the sample event.");
    } catch {
      setError("Unable to test rule.");
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
      setStatus(`Rolled out version ${targetVersion} to ${canaryPercent}% ${policyRolloutScopeStatus(rolloutScope, rolloutScopeOptions)}.`);
    } catch {
      setError("Unable to roll out policy version.");
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
      setStatus("Rollback requested.");
    } catch {
      setError("Unable to roll back policy.");
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
        <CardTitle>Policy Change</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-5 xl:grid-cols-[1.1fr_.9fr]">
        <form className="grid gap-3 md:grid-cols-2" onSubmit={handleCreateVersion}>
          <label className={fieldGroupClass} htmlFor="policy-id">
            <span className={fieldLabelClass}>Policy</span>
            <select id="policy-id" className={fieldControlClass} value={selectedPolicy?.id ?? ""} onChange={event => setPolicyID(event.target.value)}>
              {policies.map(policy => (
                <option key={policy.id} value={policy.id}>
                  {policy.name}
                </option>
              ))}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="rule-name">
            <span className={fieldLabelClass}>Rule Name</span>
            <input id="rule-name" className={fieldControlClass} value={ruleName} onChange={event => setRuleName(event.target.value)} required />
          </label>
          <label className={fieldGroupClass} htmlFor="rule-hook">
            <span className={fieldLabelClass}>Hook</span>
            <input id="rule-hook" className={fieldControlClass} value={hook} onChange={event => setHook(event.target.value)} required />
          </label>
          <label className={fieldGroupClass} htmlFor="rule-expression">
            <span className={fieldLabelClass}>Expression</span>
            <input id="rule-expression" className={fieldControlClass} value={expression} onChange={event => setExpression(event.target.value)} required />
          </label>
          <label className={fieldGroupClass} htmlFor="rule-action">
            <span className={fieldLabelClass}>Action</span>
            <select id="rule-action" className={fieldControlClass} value={action} onChange={event => setAction(event.target.value)}>
              <option value="block">block</option>
              <option value="log">log</option>
              <option value="ignore">ignore</option>
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="rule-severity">
            <span className={fieldLabelClass}>Severity</span>
            <select id="rule-severity" className={fieldControlClass} value={severity} onChange={event => setSeverity(event.target.value)}>
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
            </select>
          </label>
          <label className={`${fieldGroupClass} md:col-span-2`} htmlFor="rule-tags">
            <span className={fieldLabelClass}>Tags</span>
            <input id="rule-tags" className={fieldControlClass} value={tags} onChange={event => setTags(event.target.value)} />
          </label>
          <div className="md:col-span-2">
            <div className="flex flex-wrap gap-2">
              <Button disabled={isSubmitting || !selectedPolicy} type="button" variant="secondary" onClick={handleValidateDraft}>
                Validate Draft
              </Button>
              <Button disabled={isSubmitting || !selectedPolicy} type="button" variant="secondary" onClick={handleTestDraft}>
                Test Draft
              </Button>
              <Button disabled={isSubmitting || !selectedPolicy} type="button" variant="secondary" onClick={handleUpdateDraft}>
                Update Draft
              </Button>
              <Button disabled={isSubmitting || !selectedPolicy} type="submit">
                Create Version
              </Button>
            </div>
          </div>
        </form>
        <form className="grid content-start gap-3" onSubmit={handleRollout}>
          <label className={fieldGroupClass} htmlFor="rollout-scope">
            <span className={fieldLabelClass}>Rollout Scope</span>
            <select id="rollout-scope" className={fieldControlClass} value={rolloutScope} onChange={event => setRolloutScope(event.target.value)}>
              {rolloutScopeOptions.map(option => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
          <label className={fieldGroupClass} htmlFor="rollout-version">
            <span className={fieldLabelClass}>Version</span>
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
            <span className={fieldLabelClass}>Canary Percent</span>
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
              Roll Out Version
            </Button>
            <Button disabled={isSubmitting || !selectedPolicy} type="button" variant="secondary" onClick={handleRollback}>
              Rollback
            </Button>
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
      setMessage({ status: "Protection configuration saved.", error: "" });
    } catch {
      setMessage({ status: "", error: "Unable to save protection configuration." });
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Protection Configuration</CardTitle>
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
              Allowlist Enabled
            </label>
            <label className={fieldGroupClass} htmlFor="protection-allowlist-mode">
              <span className={fieldLabelClass}>Allowlist Mode</span>
              <select id="protection-allowlist-mode" className={fieldControlClass} value={allowlistMode} onChange={event => setAllowlistMode(event.target.value)}>
                <option value="monitor">monitor</option>
                <option value="enforce">enforce</option>
              </select>
            </label>
            <label className={fieldGroupClass} htmlFor="protection-hardening-mode">
              <span className={fieldLabelClass}>Hardening Mode</span>
              <select id="protection-hardening-mode" className={fieldControlClass} value={hardeningMode} onChange={event => setHardeningMode(event.target.value)}>
                <option value="monitor">monitor</option>
                <option value="enforce">enforce</option>
              </select>
            </label>
            <label className={fieldGroupClass} htmlFor="protection-vulnerability-threshold">
              <span className={fieldLabelClass}>Vulnerability Threshold</span>
              <select id="protection-vulnerability-threshold" className={fieldControlClass} value={vulnerabilitySeverity} onChange={event => setVulnerabilitySeverity(event.target.value)}>
                <option value="critical">critical</option>
                <option value="high">high</option>
                <option value="medium">medium</option>
                <option value="low">low</option>
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
              Block Reflection Abuse
            </label>
            <label className="flex min-h-10 items-center gap-2 text-sm font-medium text-slate-700" htmlFor="protection-block-process">
              <input
                id="protection-block-process"
                className="h-4 w-4 rounded border-slate-300 text-slate-900"
                type="checkbox"
                checked={blockProcessExecution}
                onChange={event => setBlockProcessExecution(event.target.checked)}
              />
              Block Process Execution
            </label>
            <label className="flex min-h-10 items-center gap-2 text-sm font-medium text-slate-700" htmlFor="protection-block-known-exploited">
              <input
                id="protection-block-known-exploited"
                className="h-4 w-4 rounded border-slate-300 text-slate-900"
                type="checkbox"
                checked={blockKnownExploited}
                onChange={event => setBlockKnownExploited(event.target.checked)}
              />
              Block Known Exploited
            </label>
          </div>
          <label className={fieldGroupClass} htmlFor="protection-allowlist-entries">
            <span className={fieldLabelClass}>Allowlist Entries</span>
            <textarea
              id="protection-allowlist-entries"
              className={`${fieldControlClass} min-h-24 py-2`}
              value={allowlistEntries}
              onChange={event => setAllowlistEntries(event.target.value)}
            />
          </label>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <label className={fieldGroupClass} htmlFor="retention-attack-days">
              <span className={fieldLabelClass}>Attack Retention Days</span>
              <input id="retention-attack-days" className={fieldControlClass} min={1} type="number" value={attackRetentionDays} onChange={event => setAttackRetentionDays(Number(event.target.value))} />
            </label>
            <label className={fieldGroupClass} htmlFor="retention-performance-days">
              <span className={fieldLabelClass}>Performance Retention Days</span>
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
              <span className={fieldLabelClass}>Dependency Retention Days</span>
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
              <span className={fieldLabelClass}>Audit Retention Days</span>
              <input id="retention-audit-days" className={fieldControlClass} min={1} type="number" value={auditRetentionDays} onChange={event => setAuditRetentionDays(Number(event.target.value))} />
            </label>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Button disabled={isSubmitting} type="submit">
              {isSubmitting ? "Saving Protection Configuration" : "Save Protection Configuration"}
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
      setMessage({ status: "", error: "Cleanup cutoff date is required." });
      return;
    }
    if (!dryRun && confirmation !== "CLEAR_OPERATIONAL_DATA") {
      setMessage({ status: "", error: "Type CLEAR_OPERATIONAL_DATA before applying cleanup." });
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
      setMessage({ status: `${dryRun ? "Previewed" : "Applied"} cleanup for ${formatCleanupCount(report.counts)} records.`, error: "" });
    } catch {
      setMessage({ status: "", error: "Unable to run maintenance cleanup." });
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Maintenance Cleanup</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4">
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-[.8fr_1fr_1.2fr_auto_auto] xl:items-end">
          <label className={fieldGroupClass} htmlFor="maintenance-cleanup-before">
            <span className={fieldLabelClass}>Cleanup Before</span>
            <input id="maintenance-cleanup-before" className={fieldControlClass} type="date" value={beforeDate} onChange={event => setBeforeDate(event.target.value)} />
          </label>
          <label className={fieldGroupClass} htmlFor="maintenance-cleanup-application">
            <span className={fieldLabelClass}>Cleanup Application ID</span>
            <input id="maintenance-cleanup-application" className={fieldControlClass} value={applicationID} onChange={event => setApplicationID(event.target.value)} />
          </label>
          <label className={fieldGroupClass} htmlFor="maintenance-cleanup-confirmation">
            <span className={fieldLabelClass}>Cleanup Confirmation</span>
            <input
              id="maintenance-cleanup-confirmation"
              className={fieldControlClass}
              value={confirmation}
              onChange={event => setConfirmation(event.target.value)}
            />
          </label>
          <Button disabled={isSubmitting} type="button" variant="secondary" onClick={() => void runCleanup(true)}>
            Preview Cleanup
          </Button>
          <Button disabled={isSubmitting} type="button" onClick={() => void runCleanup(false)}>
            Apply Cleanup
          </Button>
        </div>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <label className="flex min-h-10 items-center gap-2 text-sm font-medium text-slate-700" htmlFor="maintenance-cleanup-events">
            <input id="maintenance-cleanup-events" className="h-4 w-4 rounded border-slate-300 text-slate-900" type="checkbox" checked={includeEvents} onChange={event => setIncludeEvents(event.target.checked)} />
            Events
          </label>
          <label className="flex min-h-10 items-center gap-2 text-sm font-medium text-slate-700" htmlFor="maintenance-cleanup-dependencies">
            <input id="maintenance-cleanup-dependencies" className="h-4 w-4 rounded border-slate-300 text-slate-900" type="checkbox" checked={includeDependencies} onChange={event => setIncludeDependencies(event.target.checked)} />
            Dependencies
          </label>
          <label className="flex min-h-10 items-center gap-2 text-sm font-medium text-slate-700" htmlFor="maintenance-cleanup-baseline">
            <input id="maintenance-cleanup-baseline" className="h-4 w-4 rounded border-slate-300 text-slate-900" type="checkbox" checked={includeBaselineFindings} onChange={event => setIncludeBaselineFindings(event.target.checked)} />
            Baseline Findings
          </label>
          <label className="flex min-h-10 items-center gap-2 text-sm font-medium text-slate-700" htmlFor="maintenance-cleanup-alerts">
            <input id="maintenance-cleanup-alerts" className="h-4 w-4 rounded border-slate-300 text-slate-900" type="checkbox" checked={includeAlertDeliveries} onChange={event => setIncludeAlertDeliveries(event.target.checked)} />
            Alert Deliveries
          </label>
        </div>
        <FormMessage error={message.error} status={message.status} />
        {Object.keys(lastCounts).length > 0 ? (
          <div className="grid gap-2 rounded-md border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700 md:grid-cols-2 xl:grid-cols-4">
            {Object.entries(lastCounts).map(([key, value]) => (
              <div key={key}>
                <span className="block text-xs font-medium text-slate-500">{formatCleanupKey(key)}</span>
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
  const [alertName, setAlertName] = useState("Repeated critical attacks");
  const [alertSeverity, setAlertSeverity] = useState("critical");
  const [alertTarget, setAlertTarget] = useState("security-operations");
  const [alertEnabled, setAlertEnabled] = useState(true);
  const [alertMessage, setAlertMessage] = useState({ status: "", error: "" });
  const [userEmail, setUserEmail] = useState("analyst@ohmyrasp.local");
  const [userName, setUserName] = useState("Security Analyst");
  const [userPassword, setUserPassword] = useState("change-me-123");
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
      setSettingMessage({ status: "Setting saved.", error: "" });
    } catch {
      setSettingMessage({ status: "", error: "Unable to save setting." });
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
      setAlertMessage({ status: "Alert rule created.", error: "" });
    } catch {
      setAlertMessage({ status: "", error: "Unable to create alert rule." });
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
      setUserMessage({ status: "User created.", error: "" });
    } catch {
      setUserMessage({ status: "", error: "Unable to create user." });
    }
  }

  return (
    <section className="grid gap-5 xl:grid-cols-3">
      <Card>
        <CardHeader>
          <CardTitle>Setting Change</CardTitle>
        </CardHeader>
        <CardContent>
          <form className="grid gap-3" onSubmit={handleSettingSubmit}>
            <label className={fieldGroupClass} htmlFor="setting-key">
              <span className={fieldLabelClass}>Key</span>
              <input id="setting-key" className={fieldControlClass} value={settingKey} onChange={event => setSettingKey(event.target.value)} required />
            </label>
            <label className={fieldGroupClass} htmlFor="setting-value">
              <span className={fieldLabelClass}>Value JSON</span>
              <textarea
                id="setting-value"
                className={`${fieldControlClass} min-h-24 py-2`}
                value={settingValue}
                onChange={event => setSettingValue(event.target.value)}
                required
              />
            </label>
            <Button type="submit">Save Setting</Button>
            <FormMessage error={settingMessage.error} status={settingMessage.status} />
          </form>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Alert Rule</CardTitle>
        </CardHeader>
        <CardContent>
          <form className="grid gap-3" onSubmit={handleAlertSubmit}>
            <label className={fieldGroupClass} htmlFor="alert-name">
              <span className={fieldLabelClass}>Name</span>
              <input id="alert-name" className={fieldControlClass} value={alertName} onChange={event => setAlertName(event.target.value)} required />
            </label>
            <label className={fieldGroupClass} htmlFor="alert-severity">
              <span className={fieldLabelClass}>Severity</span>
              <select id="alert-severity" className={fieldControlClass} value={alertSeverity} onChange={event => setAlertSeverity(event.target.value)}>
                <option value="critical">critical</option>
                <option value="high">high</option>
                <option value="medium">medium</option>
                <option value="low">low</option>
              </select>
            </label>
            <label className={fieldGroupClass} htmlFor="alert-target">
              <span className={fieldLabelClass}>Target</span>
              <input id="alert-target" className={fieldControlClass} value={alertTarget} onChange={event => setAlertTarget(event.target.value)} required />
            </label>
            <label className="flex items-center gap-2 text-sm font-medium text-slate-700" htmlFor="alert-enabled">
              <input id="alert-enabled" checked={alertEnabled} type="checkbox" onChange={event => setAlertEnabled(event.target.checked)} />
              Enabled
            </label>
            <Button type="submit">Create Alert Rule</Button>
            <FormMessage error={alertMessage.error} status={alertMessage.status} />
          </form>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>User Invite</CardTitle>
        </CardHeader>
        <CardContent>
          <form className="grid gap-3" onSubmit={handleUserSubmit}>
            <label className={fieldGroupClass} htmlFor="user-email">
              <span className={fieldLabelClass}>Email</span>
              <input id="user-email" className={fieldControlClass} type="email" value={userEmail} onChange={event => setUserEmail(event.target.value)} required />
            </label>
            <label className={fieldGroupClass} htmlFor="user-name">
              <span className={fieldLabelClass}>Name</span>
              <input id="user-name" className={fieldControlClass} value={userName} onChange={event => setUserName(event.target.value)} required />
            </label>
            <label className={fieldGroupClass} htmlFor="user-password">
              <span className={fieldLabelClass}>Password</span>
              <input id="user-password" className={fieldControlClass} type="password" value={userPassword} onChange={event => setUserPassword(event.target.value)} required />
            </label>
            <label className={fieldGroupClass} htmlFor="user-role">
              <span className={fieldLabelClass}>Role</span>
              <select id="user-role" className={fieldControlClass} value={userRole} onChange={event => setUserRole(event.target.value)}>
                <option value="admin">Admin</option>
                <option value="security_engineer">Security Engineer</option>
                <option value="viewer">Viewer</option>
              </select>
            </label>
            <Button type="submit">Create User</Button>
            <FormMessage error={userMessage.error} status={userMessage.status} />
          </form>
        </CardContent>
      </Card>
    </section>
  );
}

function FormMessage({ error, status }: { error: string; status: string }) {
  if (error) {
    return (
      <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700" role="alert">
        {error}
      </div>
    );
  }
  if (status) {
    return (
      <div className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-700" role="status">
        {status}
      </div>
    );
  }
  return null;
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

function policyRolloutScopeOptions(applications: Application[]): RolloutScopeOption[] {
  const options: RolloutScopeOption[] = [{ label: "All Applications", value: "global" }];
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
  if (!option || option.value === "global") {
    return "for all applications";
  }
  return `for ${option.label}`;
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
    return <span className="text-slate-500">pending</span>;
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

function formatDate(value?: string) {
  if (!value) {
    return "unknown";
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat("en-US", {
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
    .map(([key, value]) => `${key}=${String(value)}`)
    .join(", ");
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
  return new Intl.NumberFormat("en-US").format(value);
}

function Metric({ label, value, detail }: { label: string; value: string | number; detail: string }) {
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
