import type { ReactNode } from "react";
import {
  createRootRoute,
  createRoute,
  createRouter,
  lazyRouteComponent,
  redirect,
  Outlet
} from "@tanstack/react-router";
import { authToken, isPrivileged } from "./lib/session";
import { AppShell } from "./components/shell";
import { Radar } from "lucide-react";

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

const rootRoute = createRootRoute({
  component: () => <Outlet />,
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
const aliasRedirect = (path: string, to: string) =>
  createRoute({
    getParentRoute: () => appLayout,
    path,
    beforeLoad: () => {
      throw redirect({ to });
    },
    component: (): ReactNode => null
  });

const routeTree = rootRoute.addChildren([
  loginRoute,
  appLayout.addChildren([
    route("/", lazy(() => import("./routes/overview"), "OverviewPage")),
    route("/threats", lazy(() => import("./routes/threats"), "ThreatsPage")),
    route("/instances", lazy(() => import("./routes/instances"), "InstancesPage")),
    route("/policies", lazy(() => import("./routes/policies"), "PoliciesPage")),
    route("/protection", lazy(() => import("./routes/protection"), "ProtectionPage")),
    route("/software", lazy(() => import("./routes/software"), "SoftwarePage")),
    route("/observability", lazy(() => import("./routes/observability"), "ObservabilityPage")),
    route("/access", lazy(() => import("./routes/access"), "AccessPage"), true),
    aliasRedirect("/dashboard", "/"),
    aliasRedirect("/events", "/threats"),
    aliasRedirect("/agents", "/instances"),
    aliasRedirect("/maintain/hosts", "/instances"),
    aliasRedirect("/dependencies", "/software"),
    aliasRedirect("/safe/dependency", "/software"),
    aliasRedirect("/safe/baseline", "/software"),
    aliasRedirect("/algorithm", "/policies"),
    aliasRedirect("/maintain/whitelist", "/protection"),
    aliasRedirect("/algorithm/hardening", "/protection"),
    aliasRedirect("/platform", "/access"),
    aliasRedirect("/log/audit", "/access")
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
