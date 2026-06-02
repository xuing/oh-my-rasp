import { useEffect, useMemo, useState } from "react";
import { EyeOff, Eye, Trash2, Server, Tag, PackageOpen, Upload } from "lucide-react";
import { api, type Agent } from "../lib/api";
import { useAppScope } from "../lib/app-context";
import { focusStoredSection } from "../lib/focus";
import { useAgentArtifacts, useAgents, useApplications, useInvalidator, useMutation } from "../lib/queries";
import { PageHeader, RequireApplication, Grid } from "../components/page";
import { Panel, Stat, QueryState, StatusDot, Table, Th, Td, Mono, Button, Badge, Segmented, Field, TextInput, SelectInput } from "../components/ui";
import { isPrivileged } from "../lib/session";
import { relativeTime, shortId } from "../lib/format";
import { useT } from "../i18n";

export function InstancesPage() {
  const t = useT();
  useEffect(focusStoredSection, []);
  return (
    <>
      <PageHeader
        eyebrow={t("Fleet")}
        title={t("Instances")}
        description={t("Java agents registered to this application — health, version drift, assigned policy, and lifecycle.")}
      />
      <RequireApplication>{() => <InstancesBody />}</RequireApplication>
    </>
  );
}

function InstancesBody() {
  const t = useT();
  const agents = useAgents();
  const apps = useApplications();
  const scope = useAppScope();
  const invalidate = useInvalidator();
  const privileged = isPrivileged();
  const [filter, setFilter] = useState<"all" | "online" | "ignored">("all");
  const selectedApp = apps.data?.find((app) => app.id === scope.applicationId) ?? null;

  const alias = useMutation({
    mutationFn: (v: { id: string; alias: string }) => api.setAgentAlias(v.id, v.alias),
    onSuccess: () => invalidate("agents")
  });
  const ignore = useMutation({
    mutationFn: (v: { id: string; ignored: boolean }) => api.setAgentIgnored(v.id, v.ignored),
    onSuccess: () => invalidate("agents")
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.deleteAgent(id),
    onSuccess: () => invalidate("agents")
  });

  const all = agents.data ?? [];
  const rows = useMemo(() => {
    if (filter === "online") return all.filter((a) => (a.status ?? "").toLowerCase() === "online");
    if (filter === "ignored") return all.filter((a) => a.ignored_at);
    return all;
  }, [all, filter]);

  const online = all.filter((a) => (a.status ?? "").toLowerCase() === "online").length;
  const versions = new Set(all.map((a) => a.version).filter(Boolean));

  return (
    <div className="space-y-4">
      <Grid className="sm:grid-cols-3" data-section="agent-inventory" tabIndex={-1}>
        <Stat index={0} label={t("Registered")} value={all.length} hint={t("agents in scope")} />
        <Stat index={1} label={t("Online")} value={online} hint={t("reporting heartbeat")} accent={online ? "signal" : "neutral"} />
        <Stat index={2} label={t("Versions")} value={versions.size} hint={versions.size > 1 ? t("version drift present") : t("uniform")} accent={versions.size > 1 ? "critical" : "neutral"} />
      </Grid>

      {privileged && selectedApp && (
        <RegisterAgentPanel appId={selectedApp.id} environmentIds={selectedApp.environment_ids ?? []} selectedEnvId={scope.environmentId} />
      )}
      {privileged && <ArtifactPanel />}

      <div className="flex items-center justify-between">
        <Segmented
          value={filter}
          onChange={setFilter}
          options={[
            { value: "all", label: t("All") },
            { value: "online", label: t("Online") },
            { value: "ignored", label: t("Ignored") }
          ]}
        />
      </div>

      <Panel flush data-section="instances" tabIndex={-1}>
        <QueryState
          isLoading={agents.isLoading}
          isError={agents.isError}
          error={agents.error}
          isEmpty={rows.length === 0}
          emptyTitle={t("No instances")}
          emptyHint={t("Install the Java agent and point it at this application to register an instance.")}
          emptyIcon={<Server className="h-5 w-5" />}
        >
          <Table>
            <thead>
              <tr>
                <Th>{t("Status")}</Th>
                <Th>{t("Instance")}</Th>
                <Th>{t("Runtime")}</Th>
                <Th>{t("Policy")}</Th>
                <Th>{t("Last seen")}</Th>
                <Th>{t("Actions")}</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => (
                <AgentRow
                  key={a.id}
                  agent={a}
                  privileged={privileged}
                  onAlias={(alval) => alias.mutate({ id: a.id, alias: alval })}
                  onIgnore={(ig) => ignore.mutate({ id: a.id, ignored: ig })}
                  onRemove={() => remove.mutate(a.id)}
                />
              ))}
            </tbody>
          </Table>
        </QueryState>
      </Panel>
    </div>
  );
}

function AgentRow({
  agent,
  privileged,
  onAlias,
  onIgnore,
  onRemove
}: {
  agent: Agent;
  privileged: boolean;
  onAlias: (alias: string) => void;
  onIgnore: (ignored: boolean) => void;
  onRemove: () => void;
}) {
  const t = useT();
  const ignored = !!agent.ignored_at;
  return (
    <tr className={ignored ? "opacity-60" : undefined}>
      <Td>
        <StatusDot status={agent.status} />
      </Td>
      <Td>
        <div className="flex items-center gap-2 text-[13px] text-ink">
          {agent.alias || agent.hostname || t("unnamed")}
          {ignored && <Badge tone="neutral">{t("ignored")}</Badge>}
        </div>
        <Mono className="text-[11px] text-faint" title={agent.id}>
          {shortId(agent.id)}
        </Mono>
      </Td>
      <Td>
        <div className="text-[13px] text-muted">{agent.runtime ?? "java"}</div>
        <Mono className="text-[11px] text-faint">{agent.version ?? "—"}</Mono>
      </Td>
      <Td>
        {agent.policy_id ? (
          <Badge tone="signal">v{agent.policy_version ?? "?"}</Badge>
        ) : (
          <span className="text-faint">{t("unassigned")}</span>
        )}
      </Td>
      <Td>
        <span title={agent.last_seen_at}>{relativeTime(agent.last_seen_at)}</span>
      </Td>
      <Td>
        <div className="flex items-center gap-1">
          {privileged && (
            <>
              <Button
                variant="subtle"
                size="sm"
                title={t("Rename")}
                onClick={() => {
                  const next = window.prompt(t("Instance alias"), agent.alias ?? "");
                  if (next !== null) onAlias(next);
                }}
              >
                <Tag className="h-3.5 w-3.5" />
              </Button>
              <Button variant="subtle" size="sm" title={ignored ? t("Restore") : t("Ignore")} onClick={() => onIgnore(!ignored)}>
                {ignored ? <Eye className="h-3.5 w-3.5" /> : <EyeOff className="h-3.5 w-3.5" />}
              </Button>
              <Button
                variant="subtle"
                size="sm"
                title={t("Delete")}
                className="hover:text-critical"
                onClick={() => {
                  if (window.confirm(t("Delete this instance? Audit history is retained."))) onRemove();
                }}
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </>
          )}
        </div>
      </Td>
    </tr>
  );
}

function RegisterAgentPanel({
  appId,
  environmentIds,
  selectedEnvId
}: {
  appId: string;
  environmentIds: string[];
  selectedEnvId: string | null;
}) {
  const t = useT();
  const invalidate = useInvalidator();
  const [secret, setSecret] = useState("");
  const [environmentId, setEnvironmentId] = useState(selectedEnvId ?? environmentIds[0] ?? "");
  const [hostname, setHostname] = useState("");
  const [version, setVersion] = useState("25");
  const [message, setMessage] = useState("");

  useEffect(() => setEnvironmentId(selectedEnvId ?? environmentIds[0] ?? ""), [environmentIds, selectedEnvId]);

  const register = useMutation({
    mutationFn: () =>
      api.registerAgent({
        application_id: appId,
        application_secret: secret,
        environment_id: environmentId || undefined,
        hostname: hostname.trim(),
        runtime: "java",
        version: version.trim()
      }),
    onSuccess: (agent) => {
      setMessage(t("Agent registered: {id}", { id: shortId(agent.id) }));
      invalidate("agents", "audit-logs");
    }
  });

  return (
    <Panel title={t("Register Agent")} eyebrow={t("Onboarding")} data-section="register-agent" tabIndex={-1}>
      <form
        className="grid gap-3 sm:grid-cols-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (secret.trim() && hostname.trim() && version.trim()) register.mutate();
        }}
      >
        <Field label={t("Application secret")}>
          <TextInput value={secret} type="password" autoComplete="off" onChange={(e) => setSecret(e.target.value)} required />
        </Field>
        <Field label={t("Environment")}>
          <SelectInput value={environmentId} onChange={(e) => setEnvironmentId(e.target.value)}>
            <option value="">{t("All environments")}</option>
            {environmentIds.map((id) => (
              <option key={id} value={id}>
                {shortId(id)}
              </option>
            ))}
          </SelectInput>
        </Field>
        <Field label={t("Hostname")}>
          <TextInput value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="app-node-01" required />
        </Field>
        <Field label={t("JDK version")}>
          <TextInput value={version} onChange={(e) => setVersion(e.target.value)} required />
        </Field>
        <div className="sm:col-span-2 flex items-center gap-3">
          <Button type="submit" variant="primary" disabled={register.isPending || !secret.trim() || !hostname.trim() || !version.trim()}>
            <Server className="h-3.5 w-3.5" /> {register.isPending ? t("Registering…") : t("Register")}
          </Button>
          {message && <span className="text-[12px] text-signal">{message}</span>}
        </div>
      </form>
    </Panel>
  );
}

function ArtifactPanel() {
  const t = useT();
  const artifacts = useAgentArtifacts();
  const invalidate = useInvalidator();
  const [file, setFile] = useState<File | null>(null);
  const [systemType, setSystemType] = useState("linux-x64");
  const [languageVersion, setLanguageVersion] = useState("25");
  const [message, setMessage] = useState("");

  const upload = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error("missing file");
      const content = await fileToBase64(file);
      return api.uploadAgentArtifact({
        filename: file.name,
        language: "java",
        system_type: systemType,
        language_version: languageVersion,
        content_base64: content
      });
    },
    onSuccess: () => {
      setMessage(t("Artifact uploaded."));
      setFile(null);
      invalidate("agent-artifacts");
    }
  });

  return (
    <Panel
      title={t("Agent artifacts")}
      eyebrow={t("Upgrade")}
      data-section="agent-artifacts"
      tabIndex={-1}
      actions={
        <form
          className="flex flex-wrap items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (file) upload.mutate();
          }}
        >
          <TextInput className="w-32" value={systemType} onChange={(e) => setSystemType(e.target.value)} aria-label={t("System type")} />
          <TextInput className="w-24" value={languageVersion} onChange={(e) => setLanguageVersion(e.target.value)} aria-label={t("JDK version")} />
          <input
            className="max-w-[190px] text-[12px] text-faint file:mr-2 file:rounded file:border-0 file:bg-raised file:px-2 file:py-1 file:text-muted"
            type="file"
            accept=".zip,application/zip"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          />
          <Button size="sm" variant="primary" type="submit" disabled={!file || upload.isPending}>
            <Upload className="h-3.5 w-3.5" /> {t("Upload")}
          </Button>
        </form>
      }
      flush
    >
      {message && <div className="mx-5 mb-3 text-[12px] text-signal">{message}</div>}
      <QueryState isLoading={artifacts.isLoading} isError={artifacts.isError} error={artifacts.error} isEmpty={(artifacts.data?.items ?? []).length === 0} emptyTitle={t("No Agent artifacts discovered")} emptyIcon={<PackageOpen className="h-5 w-5" />}>
        <Table>
          <thead>
            <tr>
              <Th>{t("Artifact")}</Th>
              <Th>{t("Runtime")}</Th>
              <Th>{t("Size")}</Th>
              <Th>MD5</Th>
              <Th>{t("Updated")}</Th>
            </tr>
          </thead>
          <tbody>
            {(artifacts.data?.items ?? []).map((artifact) => (
              <tr key={`${artifact.filename}-${artifact.md5}`}>
                <Td>
                  <div className="text-[13px] text-ink">{artifact.filename}</div>
                  <Mono className="text-[11px] text-faint">{artifact.source ?? "managed"}</Mono>
                </Td>
                <Td>
                  {artifact.language} {artifact.language_version} · {artifact.system_type}
                </Td>
                <Td>{Math.ceil(artifact.size / 1024)} KiB</Td>
                <Td>
                  <Mono className="text-[11px]">{artifact.md5}</Mono>
                </Td>
                <Td>{relativeTime(artifact.updated_at)}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </QueryState>
    </Panel>
  );
}

function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error);
    reader.onload = () => {
      const result = String(reader.result ?? "");
      resolve(result.includes(",") ? result.split(",", 2)[1] : result);
    };
    reader.readAsDataURL(file);
  });
}
