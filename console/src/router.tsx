import type { ReactNode } from "react";
import {
  createRootRoute,
  createRoute,
  createRouter,
  lazyRouteComponent,
  redirect,
  Outlet,
  type ErrorComponentProps
} from "@tanstack/react-router";
import { authToken, isPrivileged } from "./lib/session";
import { AppShell } from "./components/shell";
import { AlertTriangle, Radar, RotateCcw } from "lucide-react";
import { storeFocusTarget } from "./lib/focus";
import { Button } from "./components/ui";
import { useT } from "./i18n";

// Each page is split into its own chunk and loaded on demand.
const lazy = (importer: () => Promise<Record<string, unknown>>, name: string) =>
  lazyRouteComponent(importer as never, name);

function RoutePending() {
  return (
    <div className="flex items-center gap-3 px-1 py-16 text-faint">
      <Radar className="h-5 w-5 animate-spin text-signal" />
      <span className="eyebrow">Loading module…</span>
    </div>
  );
}

/**
 * Route-level error boundary. A single malformed API record or a render-time
 * throw in any page is caught here instead of white-screening the whole SPA.
 * TanStack Router renders the nearest `errorComponent` up the tree; placing it
 * on the root route makes it the catch-all for every page.
 */
function RootErrorBoundary({ error }: ErrorComponentProps) {
  const t = useT();
  const detail = error instanceof Error ? error.message : String(error);
  return (
    <div className="app-atmosphere grid min-h-screen place-items-center px-6">
      <div className="panel relative w-full max-w-md p-8 text-center">
        <div className="mx-auto grid h-12 w-12 place-items-center rounded-lg border border-critical/40 bg-critical/5 text-critical">
          <AlertTriangle className="h-6 w-6" />
        </div>
        <h1 className="display mt-4 text-lg font-semibold text-ink">{t("Something went wrong")}</h1>
        <p className="mt-2 text-[13px] text-muted">
          {t("The console hit an unexpected error. Reloading usually clears it.")}
        </p>
        {detail && (
          <p className="readout mt-3 break-words rounded-md border border-hairline bg-obsidian px-3 py-2 text-left text-[12px] text-faint">
            {detail}
          </p>
        )}
        <div className="mt-5 flex justify-center">
          <Button variant="primary" onClick={() => window.location.reload()}>
            <RotateCcw className="h-4 w-4" /> {t("Reload console")}
          </Button>
        </div>
      </div>
    </div>
  );
}

const rootRoute = createRootRoute({
  component: () => <Outlet />,
  errorComponent: RootErrorBoundary,
  notFoundComponent: lazy(() => import("./routes/not-found"), "NotFoundPage")
});

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  beforeLoad: () => {
    if (authToken()) throw redirect({ to: "/" });
  },
  component: lazy(() => import("./routes/login"), "LoginPage")
});

// Pathless layout that renders the authenticated shell and guards every child.
const appLayout = createRoute({
  getParentRoute: () => rootRoute,
  id: "authenticated",
  beforeLoad: () => {
    if (!authToken()) throw redirect({ to: "/login" });
  },
  component: AppShell
});

const route = (path: string, component: ReturnType<typeof lazy>, adminOnly = false) =>
  createRoute({
    getParentRoute: () => appLayout,
    path,
    beforeLoad: adminOnly
      ? () => {
          if (!isPrivileged()) throw redirect({ to: "/" });
        }
      : undefined,
    component
  });

// Legacy / alternative URLs redirect into the application-centric structure.
const aliasRedirect = (path: string, to: string, focus?: string) =>
  createRoute({
    getParentRoute: () => appLayout,
    path,
    beforeLoad: () => {
      if (focus) storeFocusTarget(focus);
      throw redirect({ to });
    },
    component: (): ReactNode => null
  });

const routeTree = rootRoute.addChildren([
  loginRoute,
  appLayout.addChildren([
    route("/", lazy(() => import("./routes/overview"), "OverviewPage")),
    route("/threats", lazy(() => import("./routes/threats"), "ThreatsPage")),
    route("/applications", lazy(() => import("./routes/applications"), "ApplicationsPage")),
    route("/instances", lazy(() => import("./routes/instances"), "InstancesPage")),
    route("/policies", lazy(() => import("./routes/policies"), "PoliciesPage")),
    route("/protection", lazy(() => import("./routes/protection"), "ProtectionPage")),
    route("/software", lazy(() => import("./routes/software"), "SoftwarePage")),
    route("/observability", lazy(() => import("./routes/observability"), "ObservabilityPage")),
    route("/access", lazy(() => import("./routes/access"), "AccessPage"), true),
    aliasRedirect("/dashboard", "/"),
    aliasRedirect("/events", "/threats"),
    aliasRedirect("/agents", "/instances"),
    aliasRedirect("/maintain/hosts", "/instances", "register-agent"),
    aliasRedirect("/addInstance", "/instances", "register-agent"),
    aliasRedirect("/dependencies", "/software"),
    aliasRedirect("/safe/dependency", "/software"),
    aliasRedirect("/safe/baseline", "/software"),
    aliasRedirect("/algorithm", "/policies"),
    aliasRedirect("/safe/recycleBin", "/threats", "recycle-bin"),
    aliasRedirect("/maintain/whitelist", "/protection", "allowlist"),
    aliasRedirect("/algorithm/hardening", "/protection", "hardening"),
    aliasRedirect("/algorithm/alarm", "/access", "alert-rules"),
    aliasRedirect("/platform", "/access", "users"),
    aliasRedirect("/log/audit", "/access", "audit"),
    aliasRedirect("/settings/panel", "/access", "system"),
    aliasRedirect("/settings/alarm", "/access", "alert-rules"),
    aliasRedirect("/settings/systemInfo", "/access", "system"),
    aliasRedirect("/settings/poolVersion", "/instances", "agent-artifacts"),
    aliasRedirect("/settings/version", "/instances", "agent-inventory")
  ])
]);

export const router = createRouter({
  routeTree,
  defaultPreload: "intent",
  defaultPendingComponent: RoutePending,
  scrollRestoration: true
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
