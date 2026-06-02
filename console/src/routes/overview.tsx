import { motion } from "motion/react";
import { ShieldAlert, ServerCog, Bug, Radar } from "lucide-react";
import { useOverview, useAgents } from "../lib/queries";
import { PageHeader, RequireApplication, Grid } from "../components/page";
import { Panel, Stat, QueryState, Badge, Mono } from "../components/ui";
import { TrendArea, BarMeter } from "../components/charts";
import { compactNumber, fullNumber } from "../lib/format";
import { useT } from "../i18n";

export function OverviewPage() {
  const t = useT();
  return (
    <>
      <PageHeader
        eyebrow={t("Security posture")}
        title={t("Overview")}
        description={t("Live posture for the selected application — threat trend, fleet health, and attack distribution.")}
      />
      <RequireApplication>{() => <OverviewBody />}</RequireApplication>
    </>
  );
}

function OverviewBody() {
  const t = useT();
  const overview = useOverview();
  const agents = useAgents();
  const o = overview.data;

  const trendTotal = (o?.attack_trend ?? []).reduce((s, p) => s + p.count, 0);
  const onlineAgents = o?.online_agents ?? 0;
  const totalAgents = o?.agent_count ?? 0;

  return (
    <div className="space-y-4">
      <Grid className="sm:grid-cols-2 xl:grid-cols-4">
        <Stat index={0} label={t("Total events")} value={compactNumber(o?.event_count)} hint={t("ingested, all types")} accent="neutral" />
        <Stat
          index={1}
          label={t("Attacks in window")}
          value={compactNumber(trendTotal)}
          hint={t("across the attack trend")}
          accent={trendTotal > 0 ? "critical" : "neutral"}
        />
        <Stat
          index={2}
          label={t("Instances online")}
          value={`${onlineAgents}/${totalAgents}`}
          hint={t("agents reporting")}
          accent={onlineAgents > 0 ? "signal" : "neutral"}
        />
        <Stat index={3} label={t("Crashes")} value={compactNumber(o?.crash_count)} hint={t("agent crash reports")} accent={o?.crash_count ? "critical" : "neutral"} />
      </Grid>

      <Panel eyebrow={t("Last activity")} title={t("Attack trend")} actions={<Badge tone="signal"><Radar className="h-3 w-3" /> {t("live")}</Badge>}>
        <QueryState isLoading={overview.isLoading} isError={overview.isError} error={overview.error}>
          <TrendArea data={o?.attack_trend ?? []} />
        </QueryState>
      </Panel>

      <Grid className="lg:grid-cols-3">
        <Panel eyebrow={t("Distribution")} title={t("By severity")}>
          <QueryState isLoading={overview.isLoading} isError={overview.isError} error={overview.error}>
            <BarMeter data={o?.events_by_severity} bySeverity emptyLabel={t("No events yet")} />
          </QueryState>
        </Panel>
        <Panel eyebrow={t("Distribution")} title={t("Top hooks")}>
          <QueryState isLoading={overview.isLoading} isError={overview.isError} error={overview.error}>
            <BarMeter data={o?.attacks_by_hook} emptyLabel={t("No attack hooks observed")} />
          </QueryState>
        </Panel>
        <Panel eyebrow={t("Distribution")} title={t("Top algorithms")}>
          <QueryState isLoading={overview.isLoading} isError={overview.isError} error={overview.error}>
            <BarMeter data={o?.attacks_by_algorithm} emptyLabel={t("No algorithm hits")} />
          </QueryState>
        </Panel>
      </Grid>

      <Grid className="lg:grid-cols-[1.4fr_1fr]">
        <Panel eyebrow={t("Reconnaissance")} title={t("Top user agents")}>
          <QueryState isLoading={overview.isLoading} isError={overview.isError} error={overview.error}>
            <BarMeter data={o?.attacks_by_user_agent} emptyLabel={t("No attacker user agents")} />
          </QueryState>
        </Panel>

        <Panel eyebrow={t("Fleet")} title={t("Instance health")}>
          <QueryState
            isLoading={agents.isLoading}
            isError={agents.isError}
            error={agents.error}
            isEmpty={(agents.data ?? []).length === 0}
            emptyTitle={t("No instances registered")}
            emptyHint={t("Install the Java agent in this application to begin reporting.")}
            emptyIcon={<ServerCog className="h-5 w-5" />}
          >
            <ul className="space-y-2">
              {(agents.data ?? []).slice(0, 6).map((a, i) => {
                const online = (a.status ?? "").toLowerCase() === "online";
                return (
                  <motion.li
                    key={a.id}
                    initial={{ opacity: 0, x: -6 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.04 }}
                    className="flex items-center justify-between rounded-md border border-hairline/70 bg-obsidian/60 px-3 py-2"
                  >
                    <div className="flex items-center gap-2.5">
                      <span className={`h-2 w-2 rounded-full ${online ? "bg-signal" : "bg-faint"}`} />
                      <div>
                        <div className="text-[13px] text-ink">{a.alias || a.hostname || a.id}</div>
                        <Mono className="text-[11px] text-faint">{a.runtime ?? "java"} · {a.version ?? "—"}</Mono>
                      </div>
                    </div>
                    <ShieldAlert className={`h-4 w-4 ${online ? "text-signal/60" : "text-faint"}`} />
                  </motion.li>
                );
              })}
            </ul>
          </QueryState>
        </Panel>
      </Grid>

      <p className="flex items-center gap-2 text-[12px] text-faint">
        <Bug className="h-3.5 w-3.5" />
        {t("Totals reflect the selected application scope and refresh every 30 seconds.")}
        <span className="readout">{t("events:")} {fullNumber(o?.event_count)}</span>
      </p>
    </div>
  );
}
