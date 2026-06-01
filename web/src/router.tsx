import { createRootRoute, createRoute, createRouter, redirect } from "@tanstack/react-router";
import {
  AccessPage,
  AgentsPage,
  ApplicationsPage,
  EventsPage,
  LoginPage,
  NoAccessPage,
  NotFoundPage,
  ObservabilityPage,
  OverviewPage,
  PoliciesPage,
  RootLayout
} from "./routes/pages";
import { currentSession } from "./lib/api";

const rootRoute = createRootRoute({
  component: RootLayout,
  notFoundComponent: NotFoundPage
});

function requireSession() {
  if (!currentSession().token) {
    throw redirect({ to: "/login" });
  }
}

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  beforeLoad: requireSession,
  component: OverviewPage
});

const applicationsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/applications",
  beforeLoad: requireSession,
  component: ApplicationsPage
});

const agentsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/agents",
  beforeLoad: requireSession,
  component: AgentsPage
});

const maintainHostsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/maintain/hosts",
  beforeLoad: requireSession,
  component: AgentsPage
});

const addInstanceRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/addInstance",
  beforeLoad: requireSession,
  component: AgentsPage
});

const maintainWhitelistRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/maintain/whitelist",
  beforeLoad: requireSession,
  component: AccessPage
});

const maintainClearDataRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/maintain/clearData",
  beforeLoad: requireSession,
  component: AccessPage
});

const maintainGeneralRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/maintain/general",
  beforeLoad: requireSession,
  component: AccessPage
});

const maintainUpgradeRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/maintain/upgrade",
  beforeLoad: requireSession,
  component: AgentsPage
});

const policiesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/policies",
  beforeLoad: requireSession,
  component: PoliciesPage
});

const algorithmRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/algorithm",
  beforeLoad: requireSession,
  component: PoliciesPage
});

const algorithmAlgorithmRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/algorithm/algorithm",
  beforeLoad: requireSession,
  component: PoliciesPage
});

const algorithmHardeningRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/algorithm/hardening",
  beforeLoad: requireSession,
  component: AccessPage
});

const algorithmAlarmRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/algorithm/alarm",
  beforeLoad: requireSession,
  component: AccessPage
});

const eventsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/events",
  beforeLoad: requireSession,
  component: EventsPage
});

const logExceptionsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/log/exceptions",
  beforeLoad: requireSession,
  component: EventsPage
});

const logCrashRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/log/crash",
  beforeLoad: requireSession,
  component: EventsPage
});

const logAuditRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/log/audit",
  beforeLoad: requireSession,
  component: AccessPage
});

const observabilityRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/observability",
  beforeLoad: requireSession,
  component: ObservabilityPage
});

const accessRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/access",
  beforeLoad: requireSession,
  component: AccessPage
});

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  component: LoginPage
});

const noAccessRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/noaccess",
  component: NoAccessPage
});

export const routeTree = rootRoute.addChildren([
  indexRoute,
  applicationsRoute,
  agentsRoute,
  maintainHostsRoute,
  addInstanceRoute,
  maintainWhitelistRoute,
  maintainClearDataRoute,
  maintainGeneralRoute,
  maintainUpgradeRoute,
  policiesRoute,
  algorithmRoute,
  algorithmAlgorithmRoute,
  algorithmHardeningRoute,
  algorithmAlarmRoute,
  eventsRoute,
  logExceptionsRoute,
  logCrashRoute,
  logAuditRoute,
  observabilityRoute,
  accessRoute,
  loginRoute,
  noAccessRoute
]);

export const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
