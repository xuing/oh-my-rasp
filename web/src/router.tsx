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

const policiesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/policies",
  beforeLoad: requireSession,
  component: PoliciesPage
});

const eventsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/events",
  beforeLoad: requireSession,
  component: EventsPage
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
  policiesRoute,
  eventsRoute,
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
