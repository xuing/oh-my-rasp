import { useEffect, useRef, useState } from "react";
import { Link, Outlet, useNavigate } from "@tanstack/react-router";
import {
  Activity,
  ChevronsUpDown,
  Crosshair,
  LayoutDashboard,
  LogOut,
  Package,
  Radar,
  Server,
  ShieldCheck,
  SlidersHorizontal,
  UsersRound
} from "lucide-react";
import { useApplications } from "../lib/queries";
import { ensureApplication, selectApplication, selectEnvironment, useAppScope } from "../lib/app-context";
import { clearSession, isPrivileged, useSession } from "../lib/session";
import { shortId } from "../lib/format";
import { cn } from "../lib/cn";
import { useT } from "../i18n";
import { LanguageSwitcher, ThemeToggle } from "./controls";

interface NavItem {
  to: string;
  label: string;
  icon: typeof LayoutDashboard;
  admin?: boolean;
}
interface NavSection {
  heading: string;
  items: NavItem[];
}

const NAV: NavSection[] = [
  {
    heading: "Monitor",
    items: [
      { to: "/", label: "Overview", icon: LayoutDashboard },
      { to: "/threats", label: "Threats", icon: Crosshair },
      { to: "/software", label: "Software & Posture", icon: Package },
      { to: "/observability", label: "Observability", icon: Activity }
    ]
  },
  {
    heading: "Manage",
    items: [
      { to: "/instances", label: "Instances", icon: Server },
      { to: "/policies", label: "Policies", icon: ShieldCheck },
      { to: "/protection", label: "Protection Config", icon: SlidersHorizontal }
    ]
  },
  {
    heading: "Administer",
    items: [{ to: "/access", label: "Access & Audit", icon: UsersRound, admin: true }]
  }
];

export function AppShell() {
  const apps = useApplications();
  const scope = useAppScope();
  const t = useT();

  useEffect(() => {
    if (apps.data) ensureApplication(apps.data.map((a) => a.id));
  }, [apps.data]);

  const selectedApp = apps.data?.find((a) => a.id === scope.applicationId) ?? null;

  return (
    <div className="app-atmosphere relative flex min-h-screen">
      <Sidebar />
      <div className="relative z-10 flex min-w-0 flex-1 flex-col lg:pl-64">
        <Topbar
          applications={apps.data ?? []}
          selectedAppId={scope.applicationId}
          selectedEnvId={scope.environmentId}
          environmentIds={selectedApp?.environment_ids ?? []}
        />
        <main className="mx-auto w-full max-w-[1400px] flex-1 px-5 py-7 lg:px-8">
          <Outlet />
        </main>
        <footer className="mx-auto w-full max-w-[1400px] px-5 pb-6 pt-2 lg:px-8">
          <p className="eyebrow text-faint/70">{t("OhMyRasp Sentinel · runtime application self-protection control plane")}</p>
        </footer>
      </div>
    </div>
  );
}

function Sidebar() {
  const admin = isPrivileged();
  const t = useT();
  return (
    <aside className="fixed inset-y-0 left-0 z-20 hidden w-64 flex-col border-r border-hairline bg-obsidian/90 backdrop-blur-md lg:flex">
      <div className="flex items-center gap-3 border-b border-hairline px-5 py-5">
        <div className="relative grid h-9 w-9 place-items-center rounded-md border border-signal/30 bg-signal/10">
          <Radar className="h-5 w-5 text-signal" />
          <span className="absolute inset-0 animate-pulse-ring rounded-md" />
        </div>
        <div>
          <div className="display text-sm font-bold tracking-tight text-ink">OhMyRasp</div>
          <div className="eyebrow text-[10px] text-faint">{t("Sentinel Console")}</div>
        </div>
      </div>
      <nav className="flex-1 space-y-6 overflow-y-auto px-3 py-5">
        {NAV.map((section) => (
          <div key={section.heading}>
            <div className="eyebrow px-3 pb-2 text-[10px]">{t(section.heading)}</div>
            <div className="space-y-0.5">
              {section.items
                .filter((i) => !i.admin || admin)
                .map((item) => (
                  <Link
                    key={item.to}
                    to={item.to}
                    activeOptions={{ exact: item.to === "/" }}
                    className="group flex items-center gap-3 rounded-md px-3 py-2 text-[13px] font-medium text-muted transition-colors hover:bg-raised hover:text-ink"
                    activeProps={{
                      className:
                        "bg-raised text-ink shadow-[inset_2px_0_0_0_var(--color-signal)] [&_svg]:text-signal"
                    }}
                  >
                    <item.icon className="h-4 w-4 text-faint transition-colors group-hover:text-muted" />
                    {t(item.label)}
                  </Link>
                ))}
            </div>
          </div>
        ))}
      </nav>
      <div className="border-t border-hairline px-5 py-3">
        <div className="flex items-center gap-2">
          <span className="h-1.5 w-1.5 animate-pulse-ring rounded-full bg-signal" />
          <span className="eyebrow text-[10px]">{t("Protection active")}</span>
        </div>
      </div>
    </aside>
  );
}

function Topbar({
  applications,
  selectedAppId,
  selectedEnvId,
  environmentIds
}: {
  applications: { id: string; name: string }[];
  selectedAppId: string | null;
  selectedEnvId: string | null;
  environmentIds: string[];
}) {
  const t = useT();
  return (
    <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-hairline bg-obsidian/80 px-5 backdrop-blur-md lg:px-8">
      <div className="flex min-w-0 items-center gap-2">
        <span className="eyebrow hidden text-faint sm:block">{t("Application")}</span>
        <div className="relative">
          <select
            value={selectedAppId ?? ""}
            onChange={(e) => selectApplication(e.target.value || null)}
            className="h-9 max-w-[230px] cursor-pointer truncate rounded-md border border-hairline-bright/60 bg-panel pl-3 pr-9 text-sm font-medium text-ink transition-colors hover:border-signal/40 focus:outline-hidden focus:ring-2 focus:ring-signal/30"
            aria-label="Select application"
          >
            {applications.length === 0 && <option value="">{t("No applications")}</option>}
            {applications.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
          <ChevronsUpDown className="pointer-events-none absolute right-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-faint" />
        </div>

        {environmentIds.length > 0 && (
          <div className="hidden items-center md:flex">
            <span className="px-1 text-faint">/</span>
            <select
              value={selectedEnvId ?? ""}
              onChange={(e) => selectEnvironment(e.target.value || null)}
              className="readout h-9 cursor-pointer rounded-md border border-hairline bg-panel pl-3 pr-7 text-[12px] text-muted focus:outline-hidden focus:ring-2 focus:ring-signal/30"
              aria-label="Select environment"
            >
              <option value="">{t("All environments")}</option>
              {environmentIds.map((id) => (
                <option key={id} value={id}>
                  {shortId(id)}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      <div className="ml-auto flex items-center gap-2">
        <ThemeToggle />
        <LanguageSwitcher />
        <UserMenu />
      </div>
    </header>
  );
}

function UserMenu() {
  const session = useSession();
  const navigate = useNavigate();
  const t = useT();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);

  const user = session.user;
  const initials = (user?.name ?? user?.email ?? "?")
    .split(/\s+/)
    .map((s) => s[0])
    .slice(0, 2)
    .join("")
    .toUpperCase();

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-2.5 rounded-md border border-hairline bg-panel py-1.5 pl-1.5 pr-3 text-left transition-colors hover:border-hairline-bright"
      >
        <span className="grid h-7 w-7 place-items-center rounded bg-signal/15 font-mono text-[12px] font-semibold text-signal">
          {initials}
        </span>
        <span className="hidden leading-tight sm:block">
          <span className="block text-[13px] font-medium text-ink">{user?.name ?? t("Operator")}</span>
          <span className="readout block text-[10px] text-faint">{user?.roles?.[0] ?? "viewer"}</span>
        </span>
      </button>
      {open && (
        <div className="absolute right-0 top-12 w-56 overflow-hidden rounded-lg border border-hairline bg-panel shadow-2xl">
          <div className="border-b border-hairline px-4 py-3">
            <div className="text-[13px] font-medium text-ink">{user?.email}</div>
            <div className="mt-1 flex flex-wrap gap-1">
              {(user?.roles ?? []).map((r) => (
                <span key={r} className="readout rounded bg-raised px-1.5 py-0.5 text-[10px] text-muted">
                  {r}
                </span>
              ))}
            </div>
          </div>
          <button
            onClick={() => {
              clearSession();
              setOpen(false);
              navigate({ to: "/login" });
            }}
            className={cn(
              "flex w-full items-center gap-2.5 px-4 py-2.5 text-left text-[13px] text-muted transition-colors hover:bg-raised hover:text-critical"
            )}
          >
            <LogOut className="h-4 w-4" />
            {t("Sign out")}
          </button>
        </div>
      )}
    </div>
  );
}
