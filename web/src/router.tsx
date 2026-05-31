import { createRootRoute, createRoute, createRouter } from "@tanstack/react-router";
import {
  AccessPage,
  AgentsPage,
  ApplicationsPage,
  EventsPage,
  LoginPage,
  ObservabilityPage,
  OverviewPage,
  PoliciesPage,
  RootLayout
} from "./routes/pages";

const rootRoute = createRootRoute({
  component: RootLayout
});

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: OverviewPage
});

const applicationsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/applications",
  component: ApplicationsPage
});

const agentsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/agents",
  component: AgentsPage
});

const policiesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/policies",
  component: PoliciesPage
});

const eventsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/events",
  component: EventsPage
});

const observabilityRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/observability",
  component: ObservabilityPage
});

const accessRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/access",
  component: AccessPage
});

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  component: LoginPage
});

export const routeTree = rootRoute.addChildren([
  indexRoute,
  applicationsRoute,
  agentsRoute,
  policiesRoute,
  eventsRoute,
  observabilityRoute,
  accessRoute,
  loginRoute
]);

export const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
