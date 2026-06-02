# Console Conventions — MANDATORY for all future work

These rules are part of the framework. Any new component, page, or change to the
`console/` UI **must** follow them. CI/review should reject changes that don't.

## 1. Internationalization (i18n)

The console ships **English, 中文 (zh), and 日本語 (ja)**. The locale is global,
persisted (`ohmyrasp.console.lang`), and switchable from the top bar (and login).

**Rules:**

1. **No hard-coded user-facing text.** Every string a user can read — page titles,
   descriptions, labels, table headers, buttons, empty states, toasts, `title`/
   `aria-label`, `window.prompt`/`confirm` messages — MUST go through `t()`.
   ```tsx
   import { useT } from "../i18n";
   const t = useT();
   return <h1>{t("Overview")}</h1>;
   ```
2. **English is the key.** `t("Sign in")` returns the translation, or the English
   key itself if none exists. So English needs no table entry.
3. **Add `zh` and `ja` together.** When you introduce a new English string, add its
   `zh` and `ja` entries to `src/i18n/messages.ts` in the same change.
4. **Interpolate with `{name}`:** `t("{count} pattern(s) · one per line", { count })`.
5. **Verbatim exceptions (do NOT wrap):** values that come from the backend/data
   (status enums like `active`/`queued`, IDs, package names, raw `algorithm`/`hook`
   identifiers) and universal tokens (`CPU`, `p50`, `p95`, `KEV`, `v1`). These are
   shown as-is across all locales.
6. **Enforcement:** `npm run i18n:check` verifies zh/ja key parity and that every
   directly-quoted `t("…")` key is translated. It runs as part of `npm run build`.
   **Known limitation — do not over-trust a green check:** the script can only see
   `t("literal")` calls. It **cannot** detect:
   - a raw JSX/attribute string that *should* have been wrapped but wasn't, and
   - indirect keys like `t(item.label)` / `t(EMPTY_KEY[kind])` (present here, but
     not counted by the script).
   So a passing check ≠ full coverage. When adding UI, also sweep for stragglers:
   ```
   grep -rnE '(placeholder|title|aria-label)="[A-Z][a-z]' src
   grep -rnE '>[A-Z][a-z]+( [A-Za-z]+){0,6}<' src/components src/routes | grep -v 't('
   ```
   For real strictness, add an ESLint rule banning literal JSX text
   (`react/jsx-no-literals` or `eslint-plugin-i18next/no-literal-string`) with an
   allowlist for data/enum values — that is the only mechanism that enforces rule #1.

## 2. Theming (light + dark)

Two themes are supported, persisted (`ohmyrasp.console.theme`), defaulting to the
OS preference. Dark is the base; `.light` on `<html>` re-skins it.

**Rules:**

1. **Only use semantic tokens — never hard-coded colors.** Style with the token
   utilities (`bg-panel`, `text-ink`, `text-muted`, `border-hairline`, `text-signal`,
   severity `text-critical`/`-high`/`-medium`/`-low`, etc.). Never write hex/rgb
   literals or fixed Tailwind palette colors (`bg-zinc-900`, `text-white`) in
   components.
2. **Both themes must work.** Because everything is token-based, light/dark is
   automatic — but verify new screens in both. The token scale lives in
   `src/styles.css` (`@theme` = dark defaults, `:root.light` = light overrides).
3. **Text on a signal fill** uses `text-on-signal` (stays dark in both themes), not
   `text-obsidian`.
4. **SVG / canvas colors** must reference CSS variables (`var(--color-signal)`),
   not literals, so charts adapt to the theme.
5. **Add a token, not a literal.** If you need a new color, add a `--color-*` token
   to `@theme` (and its `:root.light` value), then use the generated utility.

## 3. Where things live

- `src/i18n/` — `index.ts` (store + `useT`), `messages.ts` (zh/ja tables).
- `src/lib/theme.ts` — theme store (`useTheme`, `toggleTheme`).
- `src/components/controls.tsx` — `ThemeToggle`, `LanguageSwitcher` (reused by shell + login).
- `src/styles.css` — design tokens for both themes.
