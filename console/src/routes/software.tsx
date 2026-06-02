import { useState } from "react";
import { Package, ShieldQuestion, FlaskConical } from "lucide-react";
import { useDependencies, useBaselineFindings } from "../lib/queries";
import { PageHeader, RequireApplication } from "../components/page";
import { Panel, QueryState, Table, Th, Td, Badge, SeverityTag, Mono, Segmented } from "../components/ui";
import { relativeTime, titleCase } from "../lib/format";
import { useT } from "../i18n";

export function SoftwarePage() {
  const t = useT();
  return (
    <>
      <PageHeader
        eyebrow={t("Supply chain & configuration")}
        title={t("Software & Posture")}
        description={t("Agent-reported dependency inventory (SCA) and configuration baseline findings for this application.")}
      />
      <RequireApplication>{() => <SoftwareBody />}</RequireApplication>
    </>
  );
}

function SoftwareBody() {
  const t = useT();
  const [tab, setTab] = useState<"deps" | "baseline">("deps");
  return (
    <div className="space-y-4">
      <Segmented
        value={tab}
        onChange={setTab}
        options={[
          { value: "deps", label: t("Dependencies") },
          { value: "baseline", label: t("Baseline") }
        ]}
      />
      {tab === "deps" ? <Dependencies /> : <Baseline />}
    </div>
  );
}

function Dependencies() {
  const t = useT();
  const deps = useDependencies();
  return (
    <Panel flush>
      <QueryState
        isLoading={deps.isLoading}
        isError={deps.isError}
        error={deps.error}
        isEmpty={(deps.data ?? []).length === 0}
        emptyTitle={t("No dependencies reported")}
        emptyHint={t("The Java agent reports its dependency inventory on startup. Records appear once an instance checks in.")}
        emptyIcon={<Package className="h-5 w-5" />}
      >
        <Table>
          <thead>
            <tr>
              <Th>{t("Package")}</Th>
              <Th>{t("Version")}</Th>
              <Th>{t("Ecosystem")}</Th>
              <Th>{t("Vulnerabilities")}</Th>
              <Th>{t("Observed")}</Th>
            </tr>
          </thead>
          <tbody>
            {(deps.data ?? []).map((d) => {
              const vulns = d.vulnerabilities ?? [];
              const worst = vulns[0];
              return (
                <tr key={d.id}>
                  <Td>
                    <div className="text-[13px] text-ink">{d.name}</div>
                    <Mono className="text-[11px] text-faint" title={d.package_path}>
                      {d.package_path ?? "—"}
                    </Mono>
                  </Td>
                  <Td>
                    <Mono>{d.version}</Mono>
                  </Td>
                  <Td>
                    <Badge tone="neutral">{d.ecosystem}</Badge>
                  </Td>
                  <Td>
                    {vulns.length === 0 ? (
                      <span className="text-faint">{t("clean")}</span>
                    ) : (
                      <div className="flex items-center gap-2">
                        <SeverityTag value={worst?.severity} />
                        {worst?.known_exploited && <Badge tone="danger">KEV</Badge>}
                        {vulns.length > 1 && <span className="readout text-[11px] text-faint">+{vulns.length - 1}</span>}
                      </div>
                    )}
                  </Td>
                  <Td>{relativeTime(d.observed_at)}</Td>
                </tr>
              );
            })}
          </tbody>
        </Table>
      </QueryState>
    </Panel>
  );
}

function Baseline() {
  const t = useT();
  const findings = useBaselineFindings();
  return (
    <Panel flush>
      <QueryState
        isLoading={findings.isLoading}
        isError={findings.isError}
        error={findings.error}
        isEmpty={(findings.data ?? []).length === 0}
        emptyTitle={t("No baseline findings")}
        emptyHint={t("Configuration baseline checks reported by the agent appear here.")}
        emptyIcon={<FlaskConical className="h-5 w-5" />}
      >
        <Table>
          <thead>
            <tr>
              <Th>{t("Finding")}</Th>
              <Th>{t("Category")}</Th>
              <Th>{t("Severity")}</Th>
              <Th>{t("Status")}</Th>
              <Th>{t("Remediation")}</Th>
            </tr>
          </thead>
          <tbody>
            {(findings.data ?? []).map((f) => (
              <tr key={f.id}>
                <Td>
                  <div className="flex items-center gap-2 text-[13px] text-ink">
                    <ShieldQuestion className="h-3.5 w-3.5 text-faint" />
                    {f.title}
                  </div>
                  <Mono className="text-[11px] text-faint">{f.check_id}</Mono>
                </Td>
                <Td>{titleCase(f.category)}</Td>
                <Td>
                  <SeverityTag value={f.severity} />
                </Td>
                <Td>
                  <Badge tone={f.status === "pass" ? "signal" : f.status === "fail" ? "danger" : "warn"}>{f.status ?? "—"}</Badge>
                </Td>
                <Td className="max-w-[280px]">
                  <span className="line-clamp-2 text-[12px] text-muted">{f.remediation ?? "—"}</span>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </QueryState>
    </Panel>
  );
}
