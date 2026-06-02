import { useId } from "react";
import type { TrendPoint } from "../lib/api";
import { cn } from "../lib/cn";
import { compactNumber, normalizeSeverity, type Severity } from "../lib/format";
import { useT } from "../i18n";

/** Signal-lime area chart for an attack/event trend. Hand-drawn SVG. */
export function TrendArea({ data, height = 120 }: { data: TrendPoint[]; height?: number }) {
  const t = useT();
  const gid = useId();
  const w = 720;
  const h = height;
  const pad = 6;
  if (data.length === 0) {
    return <div className="flex h-[120px] items-center justify-center text-[12px] text-faint">{t("No trend data in range")}</div>;
  }
  const max = Math.max(...data.map((d) => d.count), 1);
  const stepX = data.length > 1 ? (w - pad * 2) / (data.length - 1) : 0;
  const x = (i: number) => pad + i * stepX;
  const y = (v: number) => pad + (h - pad * 2) * (1 - v / max);

  const line = data.map((d, i) => `${i === 0 ? "M" : "L"} ${x(i).toFixed(1)} ${y(d.count).toFixed(1)}`).join(" ");
  const area = `${line} L ${x(data.length - 1).toFixed(1)} ${h - pad} L ${x(0).toFixed(1)} ${h - pad} Z`;

  return (
    <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" className="h-[120px] w-full">
      <defs>
        <linearGradient id={`fill-${gid}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="var(--color-signal)" stopOpacity="0.32" />
          <stop offset="100%" stopColor="var(--color-signal)" stopOpacity="0" />
        </linearGradient>
      </defs>
      {[0.25, 0.5, 0.75].map((g) => (
        <line key={g} x1={pad} x2={w - pad} y1={pad + (h - pad * 2) * g} y2={pad + (h - pad * 2) * g} stroke="var(--color-hairline)" strokeWidth="1" />
      ))}
      <path d={area} fill={`url(#fill-${gid})`} />
      <path d={line} fill="none" stroke="var(--color-signal)" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
      {data.map((d, i) => (
        <circle key={i} cx={x(i)} cy={y(d.count)} r={data.length > 30 ? 0 : 2.5} fill="var(--color-obsidian)" stroke="var(--color-signal)" strokeWidth="1.5" />
      ))}
    </svg>
  );
}

const sevBar: Record<Severity, string> = {
  critical: "bg-critical",
  high: "bg-high",
  medium: "bg-medium",
  low: "bg-low",
  info: "bg-info"
};

/** Horizontal labelled bars from a key→count map. */
export function BarMeter({
  data,
  limit = 8,
  bySeverity = false,
  emptyLabel
}: {
  data: Record<string, number> | undefined;
  limit?: number;
  bySeverity?: boolean;
  emptyLabel?: string;
}) {
  const t = useT();
  const entries = Object.entries(data ?? {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit);
  if (entries.length === 0) {
    return <div className="py-6 text-center text-[12px] text-faint">{emptyLabel ?? t("No data")}</div>;
  }
  const max = Math.max(...entries.map(([, v]) => v), 1);
  return (
    <div className="space-y-2.5">
      {entries.map(([key, val]) => (
        <div key={key} className="group">
          <div className="mb-1 flex items-center justify-between gap-3">
            <span className="readout truncate text-[12px] text-muted" title={key}>
              {key}
            </span>
            <span className="readout text-[12px] tabular-nums text-faint">{compactNumber(val)}</span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-obsidian">
            <div
              className={cn(
                "h-full rounded-full transition-all duration-500",
                bySeverity ? sevBar[normalizeSeverity(key)] : "bg-signal/70"
              )}
              style={{ width: `${Math.max((val / max) * 100, 3)}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}
