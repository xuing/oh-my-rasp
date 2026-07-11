import { useEffect, useMemo, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { Crosshair, X, FileWarning, Ban, ArchiveRestore, Trash2 } from "lucide-react";
import { api } from "../lib/api";
import { focusStoredSection } from "../lib/focus";
import { useEvents, useInvalidator, useMutation, useRecycleBin } from "../lib/queries";
import type { SecurityEvent } from "../lib/api";
import { PageHeader, RequireApplication } from "../components/page";
import { Panel, QueryState, SeverityTag, Segmented, Table, Th, Td, Mono, Badge, Button } from "../components/ui";
import { isPrivileged } from "../lib/session";
import { relativeTime, shortDateTime, shortId, titleCase } from "../lib/format";
import { useT } from "../i18n";

type Kind = "attack" | "error" | "crash";

const EMPTY_KEY: Record<Kind, string> = {
  attack: "No attack events",
  error: "No error events",
  crash: "No crash events"
};

export function ThreatsPage() {
  const t = useT();
  useEffect(focusStoredSection, []);
  return (
    <>
      <PageHeader
        eyebrow={t("Detection")}
        title={t("Threats")}
        description={t("Attack detections, runtime errors, and crashes reported by agents in this application.")}
      />
      <RequireApplication>{() => <ThreatsBody />}</RequireApplication>
    </>
  );
}

function ThreatsBody() {
  const t = useT();
  const [kind, setKind] = useState<Kind>("attack");
  const [view, setView] = useState<"active" | "recycle">("active");
  const [severity, setSeverity] = useState<string>("");
  const [selected, setSelected] = useState<SecurityEvent | null>(null);
  const privileged = isPrivileged();
  const invalidate = useInvalidator();

  const events = useEvents(kind, { severity: severity || undefined, limit: 200 });
  const recycled = useRecycleBin({ type: kind, severity: severity || undefined, limit: 200 });
  const data = view === "recycle" ? recycled : events;
  const rows = useMemo(() => data.data ?? [], [data.data]);

  const moveToRecycle = useMutation({
    mutationFn: (id: string) => api.moveEventsToRecycleBin([id]),
    onSuccess: () => invalidate("events", "recycle-bin", "audit-logs")
  });
  const restore = useMutation({
    mutationFn: (id: string) => api.restoreEventsFromRecycleBin([id]),
    onSuccess: () => invalidate("events", "recycle-bin", "audit-logs")
  });
  const purge = useMutation({
    mutationFn: (id: string) => api.purgeEventsFromRecycleBin([id]),
    onSuccess: () => invalidate("recycle-bin", "audit-logs")
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Segmented<Kind>
          value={kind}
          onChange={setKind}
          options={[
            { value: "attack", label: t("Attacks") },
            { value: "error", label: t("Errors") },
            { value: "crash", label: t("Crashes") }
          ]}
        />
        <div className="flex items-center gap-2">
          <Segmented
            value={view}
            onChange={setView}
            options={[
              { value: "active", label: t("Active") },
              { value: "recycle", label: t("Recycle bin") }
            ]}
          />
          <span className="eyebrow hidden sm:block">{t("Severity")}</span>
          <Segmented
            value={severity}
            onChange={setSeverity}
            options={[
              { value: "", label: t("All") },
              { value: "critical", label: t("Crit") },
              { value: "high", label: t("High") },
              { value: "medium", label: t("Med") },
              { value: "low", label: t("Low") }
            ]}
          />
        </div>
      </div>

      <Panel flush data-section={view === "recycle" ? "recycle-bin" : "threat-events"} tabIndex={-1}>
        <QueryState
          isLoading={data.isLoading}
          isError={data.isError}
          error={data.error}
          isEmpty={rows.length === 0}
          emptyTitle={view === "recycle" ? t("Recycle bin is empty") : t(EMPTY_KEY[kind])}
          emptyHint={t("When agents detect and report activity in this application, it appears here in real time.")}
          emptyIcon={<Crosshair className="h-5 w-5" />}
        >
          <Table>
            <thead>
              <tr>
                <Th>{t("Severity")}</Th>
                <Th>{t("Hook · Algorithm")}</Th>
                <Th>{t("Message")}</Th>
                <Th>{t("Instance")}</Th>
                <Th>{t("When")}</Th>
                <Th>{t("Actions")}</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => (
                <tr
                  key={e.id}
                  className="interactive cursor-pointer"
                  role="button"
                  tabIndex={0}
                  onClick={() => setSelected(e)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      setSelected(e);
                    }
                  }}
                >
                  <Td>
                    <SeverityTag value={e.severity} />
                  </Td>
                  <Td>
                    <div className="text-[13px] text-ink">{titleCase(e.hook) || "—"}</div>
                    <Mono className="text-[11px] text-faint">{e.algorithm || "—"}</Mono>
                  </Td>
                  <Td className="max-w-[320px]">
                    <span className="line-clamp-1 text-muted">{e.message || "—"}</span>
                  </Td>
                  <Td>
                    <Mono title={e.agent_id}>{shortId(e.agent_id)}</Mono>
                  </Td>
                  <Td>
                    <span title={shortDateTime(e.occurred_at)}>{relativeTime(e.occurred_at)}</span>
                  </Td>
                  <Td className="text-right">
                    <div className="flex justify-end gap-1">
                      {privileged && view === "active" && (
                        <Button
                          size="sm"
                          variant="subtle"
                          title={t("Move to recycle bin")}
                          disabled={moveToRecycle.isPending}
                          onClick={(event) => {
                            event.stopPropagation();
                            moveToRecycle.mutate(e.id);
                          }}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      )}
                      {privileged && view === "recycle" && (
                        <>
                          <Button
                            size="sm"
                            variant="subtle"
                            title={t("Restore")}
                            disabled={restore.isPending}
                            onClick={(event) => {
                              event.stopPropagation();
                              restore.mutate(e.id);
                            }}
                          >
                            <ArchiveRestore className="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            size="sm"
                            variant="subtle"
                            title={t("Purge")}
                            className="hover:text-critical"
                            disabled={purge.isPending}
                            onClick={(event) => {
                              event.stopPropagation();
                              if (window.confirm(t("Permanently purge this event?"))) purge.mutate(e.id);
                            }}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </>
                      )}
                      {!privileged && <span className="text-faint">→</span>}
                    </div>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </QueryState>
      </Panel>

      <AnimatePresence>{selected && <EventDrawer event={selected} onClose={() => setSelected(null)} />}</AnimatePresence>
    </div>
  );
}

function EventDrawer({ event, onClose }: { event: SecurityEvent; onClose: () => void }) {
  const t = useT();
  return (
    <>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={onClose}
        className="fixed inset-0 z-40 bg-void/70 backdrop-blur-sm"
      />
      <motion.aside
        initial={{ x: "100%" }}
        animate={{ x: 0 }}
        exit={{ x: "100%" }}
        transition={{ type: "spring", damping: 30, stiffness: 320 }}
        className="fixed inset-y-0 right-0 z-50 flex w-full max-w-md flex-col border-l border-hairline bg-panel"
      >
        <header className="flex items-start justify-between gap-4 border-b border-hairline px-5 py-4">
          <div>
            <span className="eyebrow">{t("Detection event")}</span>
            <h3 className="display mt-1 text-base font-semibold text-ink">{titleCase(event.hook) || event.algorithm || t("Detection")}</h3>
            <Mono className="text-[11px] text-faint">{event.id}</Mono>
          </div>
          <button onClick={onClose} className="rounded-md p-1.5 text-faint transition-colors hover:bg-raised hover:text-ink">
            <X className="h-4 w-4" />
          </button>
        </header>

        <div className="flex-1 space-y-5 overflow-y-auto px-5 py-5">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityTag value={event.severity} />
            {event.algorithm && <Badge tone="info">{event.algorithm}</Badge>}
            {event.policy_id && (
              <Badge tone="signal">
                <Ban className="h-3 w-3" /> {t("Policy")} {event.policy_version ?? ""}
              </Badge>
            )}
          </div>

          {event.message && (
            <div>
              <span className="eyebrow">{t("Message")}</span>
              <p className="mt-1.5 rounded-md border border-hairline bg-obsidian px-3 py-2 text-[13px] leading-relaxed text-ink">
                {event.message}
              </p>
            </div>
          )}

          <DefList
            rows={[
              [t("Occurred"), shortDateTime(event.occurred_at)],
              [t("Hook"), titleCase(event.hook)],
              [t("Algorithm"), event.algorithm || "—"],
              [t("Agent"), event.agent_id || "—"],
              [t("Environment"), event.environment_id || "—"],
              [t("Policy"), event.policy_id ? `${event.policy_id} · v${event.policy_version ?? "?"}` : "—"]
            ]}
          />

          <div>
            <span className="eyebrow mb-1.5 flex items-center gap-1.5">
              <FileWarning className="h-3.5 w-3.5" /> {t("Attributes")}
            </span>
            <pre className="readout max-h-72 overflow-auto rounded-md border border-hairline bg-obsidian p-3 text-[11px] leading-relaxed text-muted">
              {JSON.stringify(event.attributes ?? {}, null, 2)}
            </pre>
          </div>
        </div>

        <footer className="border-t border-hairline px-5 py-3">
          <Button variant="subtle" size="sm" onClick={onClose} className="w-full">
            {t("Close")}
          </Button>
        </footer>
      </motion.aside>
    </>
  );
}

function DefList({ rows }: { rows: [string, string][] }) {
  return (
    <dl className="divide-y divide-hairline/60 overflow-hidden rounded-md border border-hairline">
      {rows.map(([k, v]) => (
        <div key={k} className="flex items-center justify-between gap-4 px-3 py-2">
          <dt className="eyebrow">{k}</dt>
          <dd className="readout truncate text-[12px] text-ink" title={v}>
            {v}
          </dd>
        </div>
      ))}
    </dl>
  );
}
