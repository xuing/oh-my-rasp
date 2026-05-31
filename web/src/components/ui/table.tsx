import type { TableHTMLAttributes } from "react";
import { cn } from "../../lib/cn";

export function Table({ className, ...props }: TableHTMLAttributes<HTMLTableElement>) {
  return (
    <table
      className={cn("w-full border-collapse overflow-hidden rounded-lg border border-slate-200 bg-white text-sm", className)}
      {...props}
    />
  );
}
