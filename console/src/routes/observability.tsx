import { Activity, Gauge, Cpu } from "lucide-react";
import { useObservability } from "../lib/queries";
import { PageHeader, RequireApplication, Grid } from "../components/page";
import { Panel, QueryState, Table, Th, Td, Mono, Badge } from "../components/ui";
import { microsToMillis, shortId } from "../lib/format";
import { useT } from "../i18n";

export function ObservabilityPage() {
  const t = useT();
  return (
    <>
      <PageHeader
        eyebrow={t("Performance")}
        title={t("Observability")}
        description={t("Runtime overhead of protection — hook latency percentiles, per-agent cost, and policy-version impact.")}
      />
      <RequireApplication>{() => <ObservabilityBody />}</RequireApplication>
    </>
  );
}

function pct(n: number) {
  return `${n.toFixed(1)}%`;
}
function kb(bytes: number) {
  if (!bytes) return "—";
  return `${(bytes / 1024).toFixed(0)} KB`;
}

function ObservabilityBody() {
  const t = useT();
  const obs = useObservability();
  const r = obs.data;

  return (
    <div className="space-y-4">
      <Panel
        eyebrow={t("Hook latency")}
        title={t("Detection cost by hook")}
        actions={<Badge tone="info"><Activity className="h-3 w-3" /> {t("p50 · p95")}</Badge>}
      >
        <QueryState
          isLoading={obs.isLoading}
          isError={obs.isError}
          error={obs.error}
          isEmpty={(r?.hook_latency ?? []).length === 0}
          emptyTitle={t("No latency samples")}
          emptyHint={t("Agents emit hook timing as performance events. Once instances report, percentiles populate here.")}
          emptyIcon={<Gauge className="h-5 w-5" />}
        >
          <Table>
            <thead>
              <tr>
                <Th>{t("Hook")}</Th>
                <Th>{t("Calls")}</Th>
                <Th>{t("Avg")}</Th>
                <Th>{t("p50")}</Th>
                <Th>{t("p95")}</Th>
                <Th>{t("Max")}</Th>
              </tr>
            </thead>
            <tbody>
              {(r?.hook_latency ?? []).map((h) => (
                <tr key={h.hook}>
                  <Td>
                    <span className="text-[13px] text-ink">{h.hook}</span>
                  </Td>
                  <Td>
                    <Mono>{h.calls}</Mono>
                  </Td>
                  <Td>
                    <Mono>{microsToMillis(h.average_latency_us)}</Mono>
                  </Td>
                  <Td>
                    <Mono>{microsToMillis(h.p50_latency_us)}</Mono>
                  </Td>
                  <Td>
                    <Mono className="text-medium">{microsToMillis(h.p95_latency_us)}</Mono>
                  </Td>
                  <Td>
                    <Mono className="text-faint">{microsToMillis(h.max_latency_us)}</Mono>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </QueryState>
      </Panel>

      <Grid className="lg:grid-cols-2">
        <Panel eyebrow={t("Per agent")} title={t("Agent overhead")}>
          <QueryState
            isLoading={obs.isLoading}
            isError={obs.isError}
            error={obs.error}
            isEmpty={(r?.agent_overhead ?? []).length === 0}
            emptyTitle={t("No agent samples")}
            emptyIcon={<Cpu className="h-5 w-5" />}
          >
            <Table>
              <thead>
                <tr>
                  <Th>{t("Agent")}</Th>
                  <Th>{t("CPU")}</Th>
                  <Th>{t("Mem")}</Th>
                  <Th>{t("Hook p95")}</Th>
                </tr>
              </thead>
              <tbody>
                {(r?.agent_overhead ?? []).map((a) => (
                  <tr key={a.agent_id}>
                    <Td>
                      <Mono title={a.agent_id}>{shortId(a.agent_id)}</Mono>
                    </Td>
                    <Td>
                      <Mono>{pct(a.cpu_overhead_pct)}</Mono>
                    </Td>
                    <Td>
                      <Mono>{kb(a.memory_overhead_bytes)}</Mono>
                    </Td>
                    <Td>
                      <Mono>{microsToMillis(a.hook_latency_p95_us)}</Mono>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </QueryState>
        </Panel>

        <Panel eyebrow={t("Per policy version")} title={t("Policy performance")}>
          <QueryState
            isLoading={obs.isLoading}
            isError={obs.isError}
            error={obs.error}
            isEmpty={(r?.policy_performance ?? []).length === 0}
            emptyTitle={t("No policy samples")}
            emptyIcon={<Gauge className="h-5 w-5" />}
          >
            <Table>
              <thead>
                <tr>
                  <Th>{t("Policy")}</Th>
                  <Th>{t("Ver")}</Th>
                  <Th>{t("CPU")}</Th>
                  <Th>{t("Hook p95")}</Th>
                </tr>
              </thead>
              <tbody>
                {(r?.policy_performance ?? []).map((p) => (
                  <tr key={`${p.policy_id}-${p.policy_version}`}>
                    <Td>
                      <Mono title={p.policy_id}>{shortId(p.policy_id)}</Mono>
                    </Td>
                    <Td>
                      <Badge tone="signal">v{p.policy_version}</Badge>
                    </Td>
                    <Td>
                      <Mono>{pct(p.cpu_overhead_pct)}</Mono>
                    </Td>
                    <Td>
                      <Mono>{microsToMillis(p.hook_latency_p95_us)}</Mono>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </QueryState>
        </Panel>
      </Grid>
    </div>
  );
}
