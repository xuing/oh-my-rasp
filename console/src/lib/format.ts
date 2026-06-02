export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function normalizeSeverity(value: string | undefined): Severity {
  const v = (value ?? "").toLowerCase();
  if (v === "critical" || v === "high" || v === "medium" || v === "low") return v;
  return "info";
}

/** Tailwind text color class for a severity. */
export function severityText(sev: Severity): string {
  return {
    critical: "text-critical",
    high: "text-high",
    medium: "text-medium",
    low: "text-low",
    info: "text-info"
  }[sev];
}

/** Compact integer, e.g. 1280 -> "1.3k". */
export function compactNumber(n: number | undefined | null): string {
  if (n == null) return "—";
  return new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(n);
}

export function fullNumber(n: number | undefined | null): string {
  if (n == null) return "—";
  return new Intl.NumberFormat("en").format(n);
}

/** Relative time, e.g. "3m ago". Falls back to "—". */
export function relativeTime(iso: string | undefined | null): string {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "—";
  const diff = then - Date.now();
  const abs = Math.abs(diff);
  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ["day", 86_400_000],
    ["hour", 3_600_000],
    ["minute", 60_000],
    ["second", 1000]
  ];
  const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto", style: "short" });
  for (const [unit, ms] of units) {
    if (abs >= ms || unit === "second") {
      return rtf.format(Math.round(diff / ms), unit);
    }
  }
  return "—";
}

export function shortDateTime(iso: string | undefined | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString("en", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false
  });
}

/** Truncate an id for display while keeping it copyable in the title. */
export function shortId(id: string | undefined, head = 6, tail = 4): string {
  if (!id) return "—";
  if (id.length <= head + tail + 1) return id;
  return `${id.slice(0, head)}…${id.slice(-tail)}`;
}

export function microsToMillis(us: number | undefined | null): string {
  if (us == null) return "—";
  if (us < 1000) return `${us}µs`;
  return `${(us / 1000).toFixed(us < 10_000 ? 2 : 1)}ms`;
}

export function titleCase(value: string | undefined): string {
  if (!value) return "—";
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}
