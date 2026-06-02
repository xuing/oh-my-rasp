import { useState } from "react";
import { UsersRound, BellRing, ScrollText, Info } from "lucide-react";
import { useUsers, useAlertRules, useAlertDeliveries, useAuditLogs, useVersion, useEdition } from "../lib/queries";
import { PageHeader, Grid } from "../components/page";
import { Panel, QueryState, Table, Th, Td, Badge, Mono, Segmented, SeverityTag } from "../components/ui";
import { relativeTime, shortDateTime, titleCase } from "../lib/format";
import { useT } from "../i18n";

type Tab = "users" | "alerts" | "audit" | "system";

export function AccessPage() {
  const t = useT();
  const [tab, setTab] = useState<Tab>("users");
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
  return (
    <Panel flush>
      <QueryState isLoading={users.isLoading} isError={users.isError} error={users.error} isEmpty={(users.data ?? []).length === 0} emptyTitle={t("No operators")} emptyIcon={<UsersRound className="h-5 w-5" />}>
        <Table>
          <thead>
            <tr>
              <Th>{t("Operator")}</Th>
              <Th>{t("Roles")}</Th>
              <Th>{t("Status")}</Th>
              <Th>{t("Created")}</Th>
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
              </tr>
            ))}
          </tbody>
        </Table>
      </QueryState>
    </Panel>
  );
}

function Alerts() {
  const t = useT();
  const rules = useAlertRules();
  const deliveries = useAlertDeliveries();
  return (
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
                <tr key={r.id}>
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
  );
}

function Audit() {
  const t = useT();
  const logs = useAuditLogs();
  return (
    <Panel flush>
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
      <Panel eyebrow={t("Build")} title={t("Version")} actions={<Info className="h-4 w-4 text-faint" />}>
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
    </Grid>
  );
}
