import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes } from "react";
import { motion } from "motion/react";
import { cn } from "../lib/cn";
import { normalizeSeverity, type Severity } from "../lib/format";
import { useT } from "../i18n";

/* ----------------------------------- text ---------------------------------- */

export function Eyebrow({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn("eyebrow block", className)}>{children}</span>;
}

/* ---------------------------------- panel ---------------------------------- */

export function Panel({
  children,
  className,
  title,
  eyebrow,
  actions,
  flush
}: {
  children: ReactNode;
  className?: string;
  title?: ReactNode;
  eyebrow?: ReactNode;
  actions?: ReactNode;
  flush?: boolean;
}) {
  return (
    <section className={cn("panel relative", className)}>
      {(title || actions || eyebrow) && (
        <header className="flex items-start justify-between gap-4 px-5 pb-3 pt-4">
          <div>
            {eyebrow && <Eyebrow>{eyebrow}</Eyebrow>}
            {title && <h2 className="display mt-1 text-[15px] font-semibold text-ink">{title}</h2>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cn(!flush && "px-5 pb-5", (title || actions || eyebrow) && "rule-top pt-4", flush && "")}>
        {children}
      </div>
    </section>
  );
}

/* --------------------------------- buttons --------------------------------- */

type ButtonVariant = "primary" | "ghost" | "subtle" | "danger";
type ButtonSize = "sm" | "md";

const buttonBase =
  "inline-flex items-center justify-center gap-2 rounded-md font-medium whitespace-nowrap transition-all duration-150 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-signal/60 disabled:opacity-40 disabled:pointer-events-none";

const buttonVariants: Record<ButtonVariant, string> = {
  primary:
    "bg-signal text-on-signal hover:brightness-110 shadow-[0_8px_24px_-12px_var(--color-signal)] font-semibold",
  ghost: "border border-hairline-bright/70 text-ink hover:bg-raised hover:border-hairline-bright",
  subtle: "text-muted hover:text-ink hover:bg-raised",
  danger: "border border-critical/40 text-critical hover:bg-critical/10"
};

const buttonSizes: Record<ButtonSize, string> = {
  sm: "h-8 px-3 text-[13px]",
  md: "h-9.5 px-4 text-sm"
};

export function Button({
  variant = "ghost",
  size = "md",
  className,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant; size?: ButtonSize }) {
  return (
    <button className={cn(buttonBase, buttonVariants[variant], buttonSizes[size], className)} {...props} />
  );
}

/* ---------------------------------- badges --------------------------------- */

type BadgeTone = "neutral" | "signal" | "warn" | "danger" | "info";
const badgeTones: Record<BadgeTone, string> = {
  neutral: "border-hairline-bright/60 text-muted",
  signal: "border-signal/40 text-signal bg-signal/5",
  warn: "border-medium/40 text-medium bg-medium/5",
  danger: "border-critical/40 text-critical bg-critical/5",
  info: "border-low/40 text-low bg-low/5"
};

export function Badge({ children, tone = "neutral", className }: { children: ReactNode; tone?: BadgeTone; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded border px-2 py-0.5 font-mono text-[11px] uppercase tracking-wide",
        badgeTones[tone],
        className
      )}
    >
      {children}
    </span>
  );
}

const severityTone: Record<Severity, string> = {
  critical: "text-critical border-critical/40 bg-critical/5",
  high: "text-high border-high/40 bg-high/5",
  medium: "text-medium border-medium/40 bg-medium/5",
  low: "text-low border-low/40 bg-low/5",
  info: "text-info border-info/30 bg-info/5"
};

export function SeverityTag({ value, className }: { value: string | undefined; className?: string }) {
  const sev = normalizeSeverity(value);
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded border px-2 py-0.5 font-mono text-[11px] uppercase tracking-wide",
        severityTone[sev],
        className
      )}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {sev}
    </span>
  );
}

/* ------------------------------ status dot --------------------------------- */

export function StatusDot({ status }: { status?: string }) {
  const s = (status ?? "unknown").toLowerCase();
  const map: Record<string, string> = {
    online: "bg-signal",
    healthy: "bg-signal",
    active: "bg-signal",
    offline: "bg-faint",
    disabled: "bg-faint",
    degraded: "bg-medium",
    failed: "bg-critical",
    error: "bg-critical"
  };
  const color = map[s] ?? "bg-faint";
  const live = color === "bg-signal";
  return (
    <span className="inline-flex items-center gap-2">
      <span className={cn("h-2 w-2 rounded-full", color, live && "animate-pulse-ring")} />
      <span className="readout text-[12px] capitalize text-muted">{s}</span>
    </span>
  );
}

/* ----------------------------------- stat ---------------------------------- */

export function Stat({
  label,
  value,
  hint,
  accent,
  index = 0
}: {
  label: ReactNode;
  value: ReactNode;
  hint?: ReactNode;
  accent?: "signal" | "critical" | "neutral";
  index?: number;
}) {
  const accentClass = accent === "signal" ? "text-signal" : accent === "critical" ? "text-critical" : "text-ink";
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.05, duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
      className="panel px-5 py-4"
    >
      <Eyebrow>{label}</Eyebrow>
      <div className={cn("display readout mt-2 text-3xl font-semibold tabular-nums", accentClass)}>{value}</div>
      {hint && <div className="mt-1 text-[12px] text-faint">{hint}</div>}
    </motion.div>
  );
}

/* --------------------------------- inputs ---------------------------------- */

export function Field({ label, hint, children }: { label: ReactNode; hint?: ReactNode; children: ReactNode }) {
  return (
    <label className="block">
      <span className="eyebrow mb-1.5 block">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-[12px] text-faint">{hint}</span>}
    </label>
  );
}

const controlBase =
  "w-full rounded-md border border-hairline bg-obsidian px-3 text-sm text-ink placeholder:text-faint focus:border-signal/50 focus:outline-hidden focus:ring-2 focus:ring-signal/30 transition-colors";

export function TextInput({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cn(controlBase, "h-9.5", className)} {...props} />;
}

export function SelectInput({ className, children, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select className={cn(controlBase, "h-9.5 cursor-pointer pr-8", className)} {...props}>
      {children}
    </select>
  );
}

/* ------------------------------ segmented ---------------------------------- */

export function Segmented<T extends string>({
  value,
  options,
  onChange
}: {
  value: T;
  options: { value: T; label: ReactNode }[];
  onChange: (v: T) => void;
}) {
  return (
    <div className="inline-flex rounded-md border border-hairline bg-obsidian p-0.5">
      {options.map((opt) => (
        <button
          key={opt.value}
          onClick={() => onChange(opt.value)}
          className={cn(
            "rounded px-3 py-1.5 text-[13px] font-medium transition-colors",
            value === opt.value ? "bg-raised text-ink shadow-[0_1px_0_0_rgb(52_61_78/0.5)_inset]" : "text-faint hover:text-muted"
          )}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}

/* ------------------------------ table bits --------------------------------- */

export function Table({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className="overflow-x-auto">
      <table className={cn("w-full border-collapse text-sm", className)}>{children}</table>
    </div>
  );
}
export function Th({ children, className }: { children?: ReactNode; className?: string }) {
  return (
    <th
      className={cn(
        "border-b border-hairline px-4 py-2.5 text-left font-mono text-[11px] font-medium uppercase tracking-wider text-faint",
        className
      )}
    >
      {children}
    </th>
  );
}
export function Td({ children, className }: { children?: ReactNode; className?: string }) {
  return <td className={cn("border-b border-hairline/60 px-4 py-3 align-middle text-[13px] text-muted", className)}>{children}</td>;
}

/* ------------------------------ empty/skeleton ----------------------------- */

export function EmptyState({ title, hint, icon }: { title: ReactNode; hint?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-14 text-center">
      {icon && <div className="grid h-12 w-12 place-items-center rounded-lg border border-hairline bg-obsidian text-faint">{icon}</div>}
      <div className="display text-sm font-medium text-muted">{title}</div>
      {hint && <div className="max-w-sm text-[13px] text-faint">{hint}</div>}
    </div>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("scanline rounded-md bg-raised/60", className)} />;
}

/* ------------------------------ query state -------------------------------- */

export function QueryState({
  isLoading,
  isError,
  error,
  isEmpty,
  emptyTitle,
  emptyHint,
  emptyIcon,
  children
}: {
  isLoading: boolean;
  isError: boolean;
  error?: unknown;
  isEmpty?: boolean;
  emptyTitle?: ReactNode;
  emptyHint?: ReactNode;
  emptyIcon?: ReactNode;
  children: ReactNode;
}) {
  const t = useT();
  if (isLoading) {
    return (
      <div className="space-y-2 p-5">
        <Skeleton className="h-8 w-full" />
        <Skeleton className="h-8 w-5/6" />
        <Skeleton className="h-8 w-2/3" />
      </div>
    );
  }
  if (isError) {
    return (
      <EmptyState
        title={t("Data unavailable")}
        hint={error instanceof Error ? error.message : t("The control plane did not respond.")}
      />
    );
  }
  if (isEmpty) {
    return <EmptyState title={emptyTitle ?? t("Nothing to show")} hint={emptyHint} icon={emptyIcon} />;
  }
  return <>{children}</>;
}

/* --------------------------------- copy ------------------------------------ */

export function Mono({ children, title, className }: { children: ReactNode; title?: string; className?: string }) {
  return (
    <span className={cn("readout text-[12px] text-muted", className)} title={title}>
      {children}
    </span>
  );
}
