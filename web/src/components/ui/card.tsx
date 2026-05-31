import type { HTMLAttributes, PropsWithChildren } from "react";
import { cn } from "../../lib/cn";

export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("rounded-lg border border-slate-200 bg-white", className)} {...props} />;
}

export function CardHeader({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("border-b border-slate-200 px-4 py-3", className)} {...props} />;
}

export function CardTitle({ children }: PropsWithChildren) {
  return <h2 className="text-sm font-semibold text-slate-950">{children}</h2>;
}

export function CardContent({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("p-4", className)} {...props} />;
}
