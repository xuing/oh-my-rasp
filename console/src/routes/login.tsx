import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { motion } from "motion/react";
import { Radar, ShieldCheck, Crosshair, Activity } from "lucide-react";
import { api, ApiError } from "../lib/api";
import { Button, Field, TextInput } from "../components/ui";
import { LanguageSwitcher, ThemeToggle } from "../components/controls";
import { useT } from "../i18n";

export function LoginPage() {
  const navigate = useNavigate();
  const t = useT();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await api.login(email.trim(), password);
      navigate({ to: "/" });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t("Sign in failed. Check your credentials."));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="app-atmosphere relative grid min-h-screen lg:grid-cols-[1.1fr_1fr]">
      <div className="absolute right-4 top-4 z-20 flex items-center gap-2">
        <ThemeToggle />
        <LanguageSwitcher />
      </div>

      {/* Brand panel */}
      <div className="relative z-10 hidden flex-col justify-between overflow-hidden border-r border-hairline p-12 lg:flex">
        <div className="flex items-center gap-3">
          <div className="relative grid h-10 w-10 place-items-center rounded-md border border-signal/30 bg-signal/10">
            <Radar className="h-5 w-5 text-signal" />
            <span className="absolute inset-0 animate-pulse-ring rounded-md" />
          </div>
          <div>
            <div className="display text-base font-bold text-ink">OhMyRasp</div>
            <div className="eyebrow text-[10px]">{t("Sentinel Console")}</div>
          </div>
        </div>

        <div className="max-w-md">
          <span className="eyebrow">{t("Runtime application self-protection")}</span>
          <h1 className="display mt-4 text-4xl font-bold leading-[1.05] tracking-tight text-ink text-balance">
            {t("Watch every call.")} <span className="text-signal">{t("Block the breach.")}</span>
          </h1>
          <p className="mt-4 text-sm leading-relaxed text-muted">
            {t(
              "One command deck for your fleet — application-scoped threats, policy enforcement, instance health, and configuration, instrumented in real time."
            )}
          </p>
          <div className="mt-10 grid grid-cols-3 gap-3">
            {[
              { icon: Crosshair, label: "Threat telemetry" },
              { icon: ShieldCheck, label: "Policy rollout" },
              { icon: Activity, label: "Overhead insight" }
            ].map((f) => (
              <div key={f.label} className="panel px-3 py-4">
                <f.icon className="h-4 w-4 text-signal" />
                <div className="mt-2 text-[12px] leading-tight text-muted">{t(f.label)}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="eyebrow text-faint/70">{t("Single-organization · self-hosted · OSS edition")}</div>
      </div>

      {/* Form panel */}
      <div className="relative z-10 flex items-center justify-center p-6">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
          className="panel w-full max-w-sm p-8"
        >
          <div className="mb-1 flex items-center gap-2 lg:hidden">
            <Radar className="h-5 w-5 text-signal" />
            <span className="display font-bold text-ink">OhMyRasp</span>
          </div>
          <span className="eyebrow">{t("Authenticate")}</span>
          <h2 className="display mt-1 text-xl font-semibold text-ink">{t("Sign in to the console")}</h2>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              void submit();
            }}
            className="mt-6 space-y-4"
          >
            <Field label={t("Email")}>
              <TextInput
                type="email"
                autoComplete="username"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="admin@ohmyrasp.local"
                required
              />
            </Field>
            <Field label={t("Password")}>
              <TextInput
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                required
              />
            </Field>

            {error && (
              <div className="rounded-md border border-critical/40 bg-critical/5 px-3 py-2 text-[13px] text-critical">
                {error}
              </div>
            )}

            <Button type="submit" variant="primary" size="md" className="w-full" disabled={busy}>
              {busy ? t("Authenticating…") : t("Enter console")}
            </Button>
          </form>

          <p className="mt-6 text-[12px] leading-relaxed text-faint">
            {t(
              "Sessions are issued by the control plane and expire automatically. Credentials are verified with bcrypt server-side."
            )}
          </p>
        </motion.div>
      </div>
    </div>
  );
}
