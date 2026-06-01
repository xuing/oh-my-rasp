import { Boxes, Container, Copy, Server, Terminal } from "lucide-react";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { type Application, useApplications } from "../lib/api";

const modes = [
  { id: "manual", label: "Manual", icon: Terminal },
  { id: "docker", label: "Docker", icon: Container },
  { id: "kubernetes", label: "Kubernetes", icon: Boxes },
  { id: "daemon", label: "Daemon", icon: Server }
] as const;

type Mode = (typeof modes)[number]["id"];

export function AgentOnboardingPage() {
  const { t } = useTranslation();
  const applicationsQuery = useApplications();
  const applications = applicationsQuery.data?.items ?? [];
  const [applicationID, setApplicationID] = useState("");
  const [environmentID, setEnvironmentID] = useState("");
  const [mode, setMode] = useState<Mode>("manual");

  const selectedApplication = useMemo(
    () => applications.find(application => application.id === applicationID) ?? applications[0],
    [applicationID, applications]
  );
  const selectedEnvironmentID = environmentID || selectedApplication?.environment_ids[0] || "env_default";
  const selectedApplicationID = selectedApplication?.id || "app_default";

  return (
    <div className="space-y-5" data-route-focus="add-instance-onboarding">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-normal text-slate-950">{t("onboarding.addInstance", "Add Instance")}</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
            {t("onboarding.summary", "Register a workload, install the Java agent, and verify that heartbeats plus runtime evidence arrive in the control plane.")}
          </p>
        </div>
        <Badge tone="blue">{t("onboarding.badge", "Agent onboarding")}</Badge>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{t("onboarding.targetScope", "Target Scope")}</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 md:grid-cols-2">
            <label className="space-y-2" htmlFor="onboarding-application">
              <span className="text-sm font-medium text-slate-700">{t("onboarding.application", "Application")}</span>
              <select
                id="onboarding-application"
                className="h-10 w-full rounded-md border border-slate-300 bg-white px-3 text-sm text-slate-950 outline-none focus:border-slate-900"
                value={selectedApplicationID}
                onChange={event => {
                  setApplicationID(event.target.value);
                  setEnvironmentID("");
                }}
              >
                {applications.length ? (
                  applications.map(application => (
                    <option key={application.id} value={application.id}>
                      {application.name}
                    </option>
                  ))
                ) : (
                  <option value="app_default">{t("onboarding.defaultApplication", "app_default")}</option>
                )}
              </select>
            </label>
            <label className="space-y-2" htmlFor="onboarding-environment">
              <span className="text-sm font-medium text-slate-700">{t("onboarding.environment", "Environment")}</span>
              <select
                id="onboarding-environment"
                className="h-10 w-full rounded-md border border-slate-300 bg-white px-3 text-sm text-slate-950 outline-none focus:border-slate-900"
                value={selectedEnvironmentID}
                onChange={event => setEnvironmentID(event.target.value)}
              >
                {environmentOptions(selectedApplication).map(id => (
                  <option key={id} value={id}>
                    {id}
                  </option>
                ))}
              </select>
            </label>
          </div>
          {applicationsQuery.isError ? <p className="mt-3 text-sm text-red-700">{t("onboarding.applicationUnavailable", "Application metadata is unavailable.")}</p> : null}
        </CardContent>
      </Card>

      <div className="flex flex-wrap gap-2">
        {modes.map(item => {
          const Icon = item.icon;
          return (
            <Button key={item.id} type="button" variant={mode === item.id ? "default" : "secondary"} onClick={() => setMode(item.id)}>
              <Icon className="h-4 w-4" />
              {item.label}
            </Button>
          );
        })}
      </div>

      <OnboardingCommand mode={mode} applicationID={selectedApplicationID} environmentID={selectedEnvironmentID} />
      <VerificationChecklist />
    </div>
  );
}

function OnboardingCommand({ applicationID, environmentID, mode }: { applicationID: string; environmentID: string; mode: Mode }) {
  const { t } = useTranslation();
  const command = commandForMode(mode, applicationID, environmentID);
  return (
    <Card>
      <CardHeader>
        <CardTitle>{modeTitle(mode)}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <pre className="overflow-x-auto rounded-md bg-slate-950 p-4 text-xs leading-6 text-slate-100">
          <code>{command}</code>
        </pre>
        <div className="flex flex-wrap gap-2 text-sm text-slate-600">
          <Badge tone="neutral">{t("onboarding.appBadge", "app:")} {applicationID}</Badge>
          <Badge tone="neutral">{t("onboarding.envBadge", "env:")} {environmentID}</Badge>
          <Button type="button" variant="secondary" onClick={() => void navigator.clipboard?.writeText(command)}>
            <Copy className="h-4 w-4" />
            {t("onboarding.copy", "Copy")}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function VerificationChecklist() {
  const { t } = useTranslation();
  return (
    <div className="grid gap-3 md:grid-cols-3">
      {[
        [t("onboarding.heartbeat", "Heartbeat"), t("onboarding.heartbeatDetail", "Agent status changes to online after registration.")],
        [t("onboarding.policyPull", "Policy pull"), t("onboarding.policyPullDetail", "Assigned policy version appears on the Agent row.")],
        [t("onboarding.runtimeEvidence", "Runtime evidence"), t("onboarding.runtimeEvidenceDetail", "Dependency, baseline, performance, error, and crash records are produced by the Agent.")]
      ].map(([title, detail]) => (
        <Card key={title}>
          <CardContent>
            <Badge tone="blue">{title}</Badge>
            <p className="mt-3 text-sm leading-6 text-slate-600">{detail}</p>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function environmentOptions(application: Application | undefined) {
  const options = application?.environment_ids ?? [];
  return options.length ? options : ["env_default"];
}

function modeTitle(mode: Mode) {
  switch (mode) {
    case "docker":
      return "Docker Runtime";
    case "kubernetes":
      return "Kubernetes Workload";
    case "daemon":
      return "Daemon Managed Injection";
    default:
      return "Manual Java Agent";
  }
}

function commandForMode(mode: Mode, applicationID: string, environmentID: string) {
  switch (mode) {
    case "docker":
      return [
        "docker run \\",
        "  -e OHMYRASP_BACKEND_URL=https://control-plane.example.com \\",
        `  -e OHMYRASP_APP_ID=${applicationID} \\`,
        "  -e OHMYRASP_APP_SECRET=<application-secret> \\",
        `  -e OHMYRASP_ENVIRONMENT_ID=${environmentID} \\`,
        "  -e JAVA_TOOL_OPTIONS='-javaagent:/opt/ohmyrasp/ohmyrasp-agent.jar' \\",
        "  your-java-service:latest"
      ].join("\n");
    case "kubernetes":
      return [
        "env:",
        `  - name: OHMYRASP_APP_ID\n    value: ${applicationID}`,
        "  - name: OHMYRASP_APP_SECRET\n    valueFrom:\n      secretKeyRef:\n        name: ohmyrasp-agent\n        key: app-secret",
        `  - name: OHMYRASP_ENVIRONMENT_ID\n    value: ${environmentID}`,
        "  - name: JAVA_TOOL_OPTIONS\n    value: -javaagent:/opt/ohmyrasp/ohmyrasp-agent.jar"
      ].join("\n");
    case "daemon":
      return [
        "1. Upload the Java agent artifact from Agents.",
        "2. Bind the daemon workload to this application.",
        "3. Confirm the injection report changes to injected.",
        `4. Verify Agent registration for ${applicationID}/${environmentID}.`
      ].join("\n");
    default:
      return [
        "java \\",
        "  -javaagent:/opt/ohmyrasp/ohmyrasp-agent.jar \\",
        "  -Dohmyrasp.backend_url=https://control-plane.example.com \\",
        `  -Dohmyrasp.app_id=${applicationID} \\`,
        "  -Dohmyrasp.app_secret=<application-secret> \\",
        `  -Dohmyrasp.environment_id=${environmentID} \\`,
        "  -jar app.jar"
      ].join("\n");
  }
}
