import { useMemo, useState } from "react";
import { EyeOff, Eye, Trash2, Server, Tag } from "lucide-react";
import { api, type Agent } from "../lib/api";
import { useAgents, useInvalidator, useMutation } from "../lib/queries";
import { PageHeader, RequireApplication, Grid } from "../components/page";
import { Panel, Stat, QueryState, StatusDot, Table, Th, Td, Mono, Button, Badge, Segmented } from "../components/ui";
import { isPrivileged } from "../lib/session";
import { relativeTime, shortId } from "../lib/format";
import { useT } from "../i18n";

export function InstancesPage() {
  const t = useT();
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
  const invalidate = useInvalidator();
  const privileged = isPrivileged();
  const [filter, setFilter] = useState<"all" | "online" | "ignored">("all");

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
      <Grid className="sm:grid-cols-3">
        <Stat index={0} label={t("Registered")} value={all.length} hint={t("agents in scope")} />
        <Stat index={1} label={t("Online")} value={online} hint={t("reporting heartbeat")} accent={online ? "signal" : "neutral"} />
        <Stat index={2} label={t("Versions")} value={versions.size} hint={versions.size > 1 ? t("version drift present") : t("uniform")} accent={versions.size > 1 ? "critical" : "neutral"} />
      </Grid>

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

      <Panel flush>
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
          {privileged && (
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
          )}
        </div>
      </Td>
    </tr>
  );
}
