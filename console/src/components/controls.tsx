import { Languages, Moon, Sun } from "lucide-react";
import { setLang, supportedLanguages, useLang, useT } from "../i18n";
import { toggleTheme, useTheme } from "../lib/theme";

export function ThemeToggle() {
  const theme = useTheme();
  const t = useT();
  const dark = theme === "dark";
  return (
    <button
      onClick={toggleTheme}
      title={dark ? t("Light") : t("Dark")}
      aria-label={t("Theme")}
      className="grid h-9 w-9 place-items-center rounded-md border border-hairline bg-panel text-muted transition-colors hover:border-hairline-bright hover:text-ink"
    >
      {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
    </button>
  );
}

export function LanguageSwitcher() {
  const lang = useLang();
  const t = useT();
  return (
    <div className="relative">
      <Languages className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-faint" />
      <select
        value={lang}
        onChange={(e) => setLang(e.target.value as typeof lang)}
        aria-label={t("Language")}
        className="h-9 cursor-pointer appearance-none rounded-md border border-hairline bg-panel pl-8 pr-3 text-[13px] font-medium text-muted transition-colors hover:border-hairline-bright hover:text-ink focus:outline-hidden focus:ring-2 focus:ring-signal/30"
      >
        {supportedLanguages.map((l) => (
          <option key={l.code} value={l.code}>
            {l.nativeLabel}
          </option>
        ))}
      </select>
    </div>
  );
}
