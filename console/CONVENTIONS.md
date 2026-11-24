# Console Conventions

These rules are mandatory for every new component, route, or change in `console/`.

## 1. Internationalization (i18n)

The console ships **English (`en`), 中文 (`zh`), and 日本語 (`ja`)**. The active locale is global, persisted under `ohmyrasp.console.lang`, synced to `document.documentElement.lang`, and switchable from the top bar and login screen.

### Rules

1. **No hard-coded user-facing text.** Every string a user can read (page titles, descriptions, labels, table headers, buttons, empty states, toasts, `title`/`aria-label`, `window.prompt`/`confirm` messages) must go through `t()`:
   ```tsx
   import { useT } from "../i18n";
   const t = useT();
   return <h1>{t("Overview")}</h1>;
   ```
2. **English is the key.** `t("Sign in")` returns the translated string for the active locale, or the English key itself when `lang === "en"` or no entry exists.
3. **Add `zh` and `ja` together.** When introducing a new English string, add both its `zh` and `ja` entries to `src/i18n/messages.ts` in the same change.
4. **Interpolate with `{name}`:** `t("{count} pattern(s) · one per line", { count })`.
5. **Verbatim exceptions (do not wrap):** backend/data values (status enums like `active`/`queued`, IDs, package names, raw `algorithm`/`hook` identifiers) and universal technical tokens (`CPU`, `p50`, `p95`, `KEV`, `v1`).
6. **Enforcement and known limitations:** `npm run i18n:check` (`scripts/i18n-coverage.ts`) checks `zh`/`ja` key parity and ensures every directly-quoted `t("...")` call exists in both tables. It runs automatically in `npm run build` and `npm test`.
   Because the script only matches literal `t("...")` calls, it cannot detect unwrapped JSX/attribute text or indirect keys such as `t(item.label)` / `t(EMPTY_KEY[kind])`. Sweep new code manually before finishing:
   ```bash
   grep -rnE '(placeholder|title|aria-label)="[A-Z][a-z]' src
   grep -rnE '>[A-Z][a-z]+( [A-Za-z]+){0,6}<' src/components src/routes | grep -v 't('
   ```
   Full enforcement requires an ESLint rule banning literal JSX text (`react/jsx-no-literals` or `eslint-plugin-i18next/no-literal-string`) with a data/enum allowlist.

## 2. Theming (light and dark)

Dark and light themes are persisted under `ohmyrasp.console.theme` and default to `prefers-color-scheme: light` vs. dark. Dark tokens live in `@theme` in `src/styles.css`, and `.light` on `<html>` activates the `:root.light` overrides.

### Rules

1. **Use semantic tokens only, never hard-coded colors.** Style with token utilities (`bg-panel`, `text-ink`, `text-muted`, `border-hairline`, `text-signal`, severity `text-critical`/`-high`/`-medium`/`-low`, etc.). Do not use hex/rgb literals or fixed Tailwind palette classes (`bg-zinc-900`, `text-white`) in components.
2. **Verify both themes.** New screens and components must remain legible in both dark mode and `.light` mode (`src/styles.css`).
3. **Text on a signal fill** must use `text-on-signal` (stays dark in both themes), not `text-obsidian`.
4. **SVG and canvas colors** must reference CSS custom properties (`var(--color-signal)`) rather than literal colors so charts adapt across themes.
5. **Add a token instead of a literal.** If a new semantic color is needed, add a `--color-*` token to `@theme` and `:root.light` in `src/styles.css`, then use the generated utility.

## 3. File Locations

- `src/i18n/index.ts`: locale store (`currentLang`, `setLang`, `useLang`, `useT`, `translate`)
- `src/i18n/messages.ts`: `zh` and `ja` translation tables
- `src/lib/theme.ts`: theme store (`useTheme`, `setTheme`, `toggleTheme`)
- `src/components/controls.tsx`: `ThemeToggle` and `LanguageSwitcher` (shared by shell and login)
- `src/styles.css`: Tailwind v4 `@theme` dark tokens and `:root.light` overrides
