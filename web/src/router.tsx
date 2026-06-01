import { createRootRoute, createRoute, createRouter } from "@tanstack/react-router";
import { lazy } from "react";
import { LoginPage, NoAccessPage, NotFoundPage, RootLayout } from "./routes/shell";
import { requireRoles, requireSession } from "./routes/guards";

const rootRoute = createRootRoute({
  component: RootLayout,
  notFoundComponent: NotFoundPage
});

const OverviewPage = lazy(() => import("./routes/pages").then(module => ({ default: module.OverviewPage })));
const ApplicationsPage = lazy(() => import("./routes/pages").then(module => ({ default: module.ApplicationsPage })));
const AgentsPage = lazy(() => import("./routes/pages").then(module => ({ default: module.AgentsPage })));
const PoliciesPage = lazy(() => import("./routes/pages").then(module => ({ default: module.PoliciesPage })));
const EventsPage = lazy(() => import("./routes/pages").then(module => ({ default: module.EventsPage })));
const ObservabilityPage = lazy(() => import("./routes/pages").then(module => ({ default: module.ObservabilityPage })));
const AccessPage = lazy(() => import("./routes/pages").then(module => ({ default: module.AccessPage })));
const AgentOnboardingPage = lazy(() => import("./routes/agent-onboarding").then(module => ({ default: module.AgentOnboardingPage })));
const MaintainHostsPage = lazy(() => import("./routes/legacy-focus").then(module => ({ default: module.MaintainHostsPage })));
const MaintainWhitelistPage = lazy(() => import("./routes/legacy-focus").then(module => ({ default: module.MaintainWhitelistPage })));
const MaintainClearDataPage = lazy(() => import("./routes/legacy-focus").then(module => ({ default: module.MaintainClearDataPage })));
const MaintainGeneralPage = lazy(() => import("./routes/legacy-focus").then(module => ({ default: module.MaintainGeneralPage })));
const MaintainUpgradePage = lazy(() => import("./routes/legacy-focus").then(module => ({ default: module.MaintainUpgradePage })));
const AlgorithmPage = lazy(() => import("./routes/legacy-focus").then(module => ({ default: module.AlgorithmPage })));
const AlgorithmHardeningPage = lazy(() => import("./routes/legacy-focus").then(module => ({ default: module.AlgorithmHardeningPage })));
const AlgorithmAlarmPage = lazy(() => import("./routes/legacy-focus").then(module => ({ default: module.AlgorithmAlarmPage })));
const LogExceptionsPage = lazy(() => import("./routes/legacy-focus").then(module => ({ default: module.LogExceptionsPage })));
const LogCrashPage = lazy(() => import("./routes/legacy-focus").then(module => ({ default: module.LogCrashPage })));
const LogAuditPage = lazy(() => import("./routes/legacy-focus").then(module => ({ default: module.LogAuditPage })));
const PlatformPage = lazy(() => import("./routes/legacy-focus").then(module => ({ default: module.PlatformPage })));
const PlatformUserPage = lazy(() => import("./routes/legacy-focus").then(module => ({ default: module.PlatformUserPage })));
const SettingsPanelPage = lazy(() => import("./routes/legacy-focus").then(module => ({ default: module.SettingsPanelPage })));
const SettingsAlarmPage = lazy(() => import("./routes/legacy-focus").then(module => ({ default: module.SettingsAlarmPage })));
const SettingsSystemInfoPage = lazy(() => import("./routes/legacy-focus").then(module => ({ default: module.SettingsSystemInfoPage })));
const SettingsPoolVersionPage = lazy(() => import("./routes/legacy-focus").then(module => ({ default: module.SettingsPoolVersionPage })));
const SettingsVersionPage = lazy(() => import("./routes/legacy-focus").then(module => ({ default: module.SettingsVersionPage })));

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  beforeLoad: requireSession,
  component: OverviewPage
});

const applicationsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/applications",
  beforeLoad: () => requireRoles(["admin", "security_engineer"]),
  component: ApplicationsPage
});

const agentsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/agents",
  beforeLoad: () => requireRoles(["admin", "security_engineer"]),
  component: AgentsPage
});

const maintainHostsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/maintain/hosts",
  beforeLoad: () => requireRoles(["admin", "security_engineer"]),
  component: MaintainHostsPage
});

const addInstanceRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/addInstance",
  beforeLoad: () => requireRoles(["admin", "security_engineer"]),
  component: AgentOnboardingPage
});

const maintainWhitelistRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/maintain/whitelist",
  beforeLoad: () => requireRoles(["admin", "security_engineer"]),
  component: MaintainWhitelistPage
});

const maintainClearDataRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/maintain/clearData",
  beforeLoad: () => requireRoles(["admin"]),
  component: MaintainClearDataPage
});

const maintainGeneralRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/maintain/general",
  beforeLoad: () => requireRoles(["admin"]),
  component: MaintainGeneralPage
});

const maintainUpgradeRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/maintain/upgrade",
  beforeLoad: () => requireRoles(["admin", "security_engineer"]),
  component: MaintainUpgradePage
});

const policiesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/policies",
  beforeLoad: () => requireRoles(["admin", "security_engineer"]),
  component: PoliciesPage
});

const algorithmRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/algorithm",
  beforeLoad: () => requireRoles(["admin", "security_engineer"]),
  component: AlgorithmPage
});

const algorithmAlgorithmRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/algorithm/algorithm",
  beforeLoad: () => requireRoles(["admin", "security_engineer"]),
  component: AlgorithmPage
});

const algorithmHardeningRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/algorithm/hardening",
  beforeLoad: () => requireRoles(["admin", "security_engineer"]),
  component: AlgorithmHardeningPage
});

const algorithmAlarmRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/algorithm/alarm",
  beforeLoad: () => requireRoles(["admin", "security_engineer"]),
  component: AlgorithmAlarmPage
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
  component: LogExceptionsPage
});

const logCrashRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/log/crash",
  beforeLoad: requireSession,
  component: LogCrashPage
});

const logAuditRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/log/audit",
  beforeLoad: () => requireRoles(["admin"]),
  component: LogAuditPage
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
  beforeLoad: () => requireRoles(["admin"]),
  component: AccessPage
});

const platformRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/platform",
  beforeLoad: () => requireRoles(["admin"]),
  component: PlatformPage
});

const platformUserRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/platform/user",
  beforeLoad: () => requireRoles(["admin"]),
  component: PlatformUserPage
});

const settingsPanelRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/settings/panel",
  beforeLoad: () => requireRoles(["admin"]),
  component: SettingsPanelPage
});

const settingsAlarmRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/settings/alarm",
  beforeLoad: () => requireRoles(["admin", "security_engineer"]),
  component: SettingsAlarmPage
});

const settingsSystemInfoRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/settings/systemInfo",
  beforeLoad: () => requireRoles(["admin"]),
  component: SettingsSystemInfoPage
});

const settingsPoolVersionRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/settings/poolVersion",
  beforeLoad: () => requireRoles(["admin", "security_engineer"]),
  component: SettingsPoolVersionPage
});

const settingsVersionRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/settings/version",
  beforeLoad: () => requireRoles(["admin", "security_engineer"]),
  component: SettingsVersionPage
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
  platformRoute,
  platformUserRoute,
  settingsPanelRoute,
  settingsAlarmRoute,
  settingsSystemInfoRoute,
  settingsPoolVersionRoute,
  settingsVersionRoute,
  loginRoute,
  noAccessRoute
]);

export const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
