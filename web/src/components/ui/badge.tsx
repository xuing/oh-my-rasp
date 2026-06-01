import type { HTMLAttributes } from "react";
import { useUiCopy } from "../../i18n/copy";
import { cn } from "../../lib/cn";

const tones = {
  neutral: "border-slate-200 bg-slate-50 text-slate-700",
  green: "border-emerald-200 bg-emerald-50 text-emerald-700",
  red: "border-red-200 bg-red-50 text-red-700",
  amber: "border-amber-200 bg-amber-50 text-amber-800",
  blue: "border-blue-200 bg-blue-50 text-blue-700"
};

export type BadgeTone = keyof typeof tones;

export function Badge({ children, className, tone = "neutral", ...props }: HTMLAttributes<HTMLSpanElement> & { tone?: BadgeTone }) {
  const { copyLoose } = useUiCopy();
  const renderedChildren = typeof children === "string" ? copyLoose(children) : children;

  return (
    <span
      className={cn("inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium", tones[tone], className)}
      {...props}
    >
      {renderedChildren}
    </span>
  );
}
