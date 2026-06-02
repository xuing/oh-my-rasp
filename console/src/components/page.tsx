import type { HTMLAttributes, ReactNode } from "react";
import { motion } from "motion/react";
import { Boxes } from "lucide-react";
import { useAppScope } from "../lib/app-context";
import { EmptyState } from "./ui";
import { useT } from "../i18n";

export function PageHeader({
  eyebrow,
  title,
  description,
  actions
}: {
  eyebrow: ReactNode;
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: -6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35 }}
      className="mb-6 flex flex-wrap items-end justify-between gap-4"
    >
      <div>
        <span className="eyebrow">{eyebrow}</span>
        <h1 className="display mt-1.5 text-2xl font-bold tracking-tight text-ink">{title}</h1>
        {description && <p className="mt-1.5 max-w-2xl text-sm text-muted">{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </motion.div>
  );
}

/** Most pages are scoped to an application. Gate them on a selection. */
export function RequireApplication({ children }: { children: (appId: string) => ReactNode }) {
  const scope = useAppScope();
  const t = useT();
  if (!scope.applicationId) {
    return (
      <div className="panel">
        <EmptyState
          icon={<Boxes className="h-5 w-5" />}
          title={t("Select an application")}
          hint={t(
            "Use the application switcher in the top bar to scope the console. Every view — threats, instances, policies, and configuration — is scoped to the selected application."
          )}
        />
      </div>
    );
  }
  return <>{children(scope.applicationId)}</>;
}

export function Grid({ children, className = "", ...props }: HTMLAttributes<HTMLDivElement> & { children: ReactNode; className?: string }) {
  return (
    <div className={`grid gap-4 ${className}`} {...props}>
      {children}
    </div>
  );
}
