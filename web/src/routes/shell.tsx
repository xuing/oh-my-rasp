import { Link, Outlet, useNavigate } from "@tanstack/react-router";
import { Suspense, type FormEvent, type ReactNode, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  Activity,
  AppWindow,
  ChartNoAxesColumnIncreasing,
  Globe2,
  type LucideIcon,
  RadioTower,
  ScrollText,
  ShieldCheck
} from "lucide-react";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { navigationSections } from "../domain/control-plane";
import { setAppLanguage, supportedLanguages, type SupportedLanguage } from "../i18n";
import { UiText, useUiCopy } from "../i18n/copy";
import { currentSession, loginWithPassword, saveSession } from "../lib/api";

const iconMap: Record<string, LucideIcon> = {
  layout: ChartNoAxesColumnIncreasing,
  app: AppWindow,
  agent: RadioTower,
  policy: ShieldCheck,
  event: ScrollText,
  chart: ChartNoAxesColumnIncreasing,
  shield: ShieldCheck,
  activity: Activity,
  audit: ScrollText
};

const navigationKeyByPath: Record<string, string> = {
  "/": "overview",
  "/applications": "applications",
  "/agents": "agents",
  "/policies": "policies",
  "/events": "events",
  "/observability": "observability",
  "/access": "access"
};

export function RootLayout() {
  const { i18n, t } = useTranslation();
  const { copy } = useUiCopy();
  const [session, setSession] = useState(currentSession);

  useEffect(() => {
    const syncSession = () => setSession(currentSession());
    window.addEventListener("storage", syncSession);
    window.addEventListener("ohmyrasp.session.changed", syncSession);
    return () => {
      window.removeEventListener("storage", syncSession);
      window.removeEventListener("ohmyrasp.session.changed", syncSession);
    };
  }, []);

  return (
    <div className="min-h-screen bg-slate-100">
      <aside className="fixed inset-y-0 left-0 hidden w-72 border-r border-slate-200 bg-slate-950 text-white lg:block">
        <div className="border-b border-slate-800 px-5 py-5">
          <div className="text-lg font-semibold tracking-normal">{t("shell.product")}</div>
          <div className="mt-1 text-xs text-slate-400">{t("shell.subtitle")}</div>
        </div>
        <nav className="space-y-1 p-3">
          {navigationSections.map(section => {
            const Icon = iconMap[section.icon] ?? Activity;
            const navigationKey = navigationKeyByPath[section.path];
            return (
              <Link
                key={section.path}
                to={section.path}
                className="flex items-center gap-3 rounded-md px-3 py-2 text-sm text-slate-300 hover:bg-slate-900 hover:text-white"
                activeProps={{ className: "bg-slate-800 text-white" }}
              >
                <Icon className="h-4 w-4" />
                <span>{t(`navigation.${navigationKey}.label`, section.label)}</span>
              </Link>
            );
          })}
        </nav>
      </aside>
      <main className="lg:pl-72">
        <header className="border-b border-slate-200 bg-white px-4 py-4 lg:px-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="text-xl font-semibold tracking-normal text-slate-950">{t("shell.title")}</div>
              <div className="text-sm text-slate-500">{t("shell.summary")}</div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <LanguageSwitcher language={i18n.resolvedLanguage ?? i18n.language} />
              <Link
                to="/policies"
                className="inline-flex h-9 items-center justify-center rounded-md border border-slate-200 bg-white px-3 text-sm font-medium text-slate-900 transition-colors hover:bg-slate-50"
              >
                {t("shell.validateRule")}
              </Link>
              <Link
                to="/addInstance"
                className="inline-flex h-9 items-center justify-center gap-2 rounded-md border border-slate-900 bg-slate-900 px-3 text-sm font-medium text-white transition-colors hover:bg-slate-800"
              >
                {t("shell.registerAgent")}
              </Link>
              {session.token ? (
                <div className="inline-flex h-9 items-center rounded-md border border-slate-200 bg-white px-3 text-sm font-medium text-slate-700">
                  {session.userEmail || session.userName || t("shell.signedIn")}
                </div>
              ) : (
                <Link
                  to="/login"
                  className="inline-flex h-9 items-center justify-center rounded-md border border-slate-200 bg-white px-3 text-sm font-medium text-slate-900 hover:bg-slate-50"
                >
                  {t("shell.signIn")}
                </Link>
              )}
            </div>
          </div>
        </header>
        <nav aria-label={copy("Primary mobile")} className="border-b border-slate-200 bg-white px-4 py-2 lg:hidden">
          <div className="flex gap-2 overflow-x-auto">
            {navigationSections.map(section => {
              const navigationKey = navigationKeyByPath[section.path];
              return (
                <Link
                  key={section.path}
                  to={section.path}
                  className="inline-flex h-9 shrink-0 items-center rounded-md px-3 text-sm font-medium text-slate-700 hover:bg-slate-100 hover:text-slate-950"
                  activeProps={{ className: "bg-slate-900 text-white hover:bg-slate-900 hover:text-white" }}
                >
                  {t(`navigation.${navigationKey}.label`, section.label)}
                </Link>
              );
            })}
          </div>
        </nav>
        <div className="p-4 lg:p-6">
          <Suspense fallback={<div className="text-sm text-slate-500">{copy("Loading console view.")}</div>}>
            <Outlet />
          </Suspense>
        </div>
      </main>
    </div>
  );
}

function LanguageSwitcher({ language }: { language: string }) {
  const { t } = useTranslation();
  const selectedLanguage = supportedLanguages.some(option => option.code === language) ? (language as SupportedLanguage) : "en";

  return (
    <label className="inline-flex h-9 items-center gap-2 rounded-md border border-slate-200 bg-white px-2 text-sm font-medium text-slate-700">
      <Globe2 className="h-4 w-4 text-slate-500" />
      <span className="sr-only">{t("language.label")}</span>
      <select
        aria-label={t("language.label")}
        className="h-7 bg-transparent text-sm outline-none"
        value={selectedLanguage}
        onChange={event => void setAppLanguage(event.target.value as SupportedLanguage)}
      >
        {supportedLanguages.map(option => (
          <option key={option.code} value={option.code}>
            {option.nativeLabel}
          </option>
        ))}
      </select>
    </label>
  );
}

export function LoginPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setIsSubmitting(true);
    try {
      const result = await loginWithPassword(email, password);
      saveSession(result);
      await navigate({ to: "/" });
    } catch {
      setError(t("login.error"));
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div className="mx-auto flex min-h-[calc(100vh-9rem)] max-w-md items-center">
      <Card className="w-full">
        <CardHeader>
          <CardTitle>{t("login.title")}</CardTitle>
        </CardHeader>
        <CardContent>
          <form className="space-y-4" onSubmit={handleSubmit}>
            <Field id="email" label={t("login.email")} value={email} autoComplete="username" type="email" onChange={setEmail} />
            <Field id="password" label={t("login.password")} value={password} autoComplete="current-password" type="password" onChange={setPassword} />
            {error ? (
              <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700" role="alert">
                {error}
              </div>
            ) : null}
            <Button className="w-full" disabled={isSubmitting} type="submit">
              {isSubmitting ? t("login.submitting") : t("login.submit")}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

function Field({ autoComplete, id, label, onChange, type, value }: { autoComplete: string; id: string; label: string; onChange: (value: string) => void; type: string; value: string }) {
  return (
    <div className="space-y-2">
      <label className="text-sm font-medium text-slate-700" htmlFor={id}>
        {label}
      </label>
      <input
        id={id}
        name={id}
        autoComplete={autoComplete}
        type={type}
        value={value}
        onChange={event => onChange(event.target.value)}
        className="h-10 w-full rounded-md border border-slate-300 bg-white px-3 text-sm text-slate-950 outline-none focus:border-slate-900"
        required
      />
    </div>
  );
}

export function NoAccessPage() {
  return (
    <EmptyStatePage
      title={<UiText k="No access" />}
      summary={<UiText k="Your account does not have permission to open this page." />}
      action={<UiText k="Back to overview" />}
      to="/"
    />
  );
}

export function NotFoundPage() {
  const session = currentSession();
  return (
    <EmptyStatePage
      title={<UiText k="Page not found" />}
      summary={<UiText k="The page you requested does not exist." />}
      action={<UiText k={session.token ? "Back to overview" : "Go to login"} />}
      to={session.token ? "/" : "/login"}
    />
  );
}

function EmptyStatePage({ action, summary, title, to }: { action: ReactNode; summary: ReactNode; title: ReactNode; to: string }) {
  return (
    <div className="mx-auto flex min-h-[calc(100vh-9rem)] max-w-lg items-center">
      <Card className="w-full">
        <CardContent className="space-y-4">
          <div>
            <h1 className="text-xl font-semibold tracking-normal text-slate-950">{title}</h1>
            <p className="mt-2 text-sm leading-6 text-slate-600">{summary}</p>
          </div>
          <Link
            to={to}
            className="inline-flex h-9 items-center justify-center rounded-md border border-slate-900 bg-slate-900 px-3 text-sm font-medium text-white transition-colors hover:bg-slate-800"
          >
            {action}
          </Link>
        </CardContent>
      </Card>
    </div>
  );
}
