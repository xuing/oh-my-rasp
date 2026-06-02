# OhMyRasp Sentinel Console

A ground-up rewrite of the OhMyRasp control-plane web interface — an
**application-centric** command deck for runtime application self-protection.

This is a clean replacement for the legacy `web/` console. It does not share code
with it; it is designed around the way operators actually run a RASP fleet:
**pick an application, then everything is scoped to it.**

## Why it exists

The previous console was org-flat: 7 nav items rendered every application's data
mixed together, with no way to scope to one application, and per-application
protection settings were collapsed into global rows. This console fixes the
information architecture:

- A **global application switcher** in the top bar is the primary context. The
  selected application (and an optional environment sub-scope) scopes every view —
  overview, threats, instances, policies, software, observability, and protection
  config. Selection persists across reloads.
- **Per-application protection configuration** (hardening, allowlist, alerting,
  dependency policy) is edited where it belongs — under the selected application —
  and the UI states plainly that changes don't bleed into other applications.
- Legacy URLs (`/dashboard`, `/events`, `/agents`, `/maintain/whitelist`, …)
  redirect into the new structure instead of dumping users on a catch-all page.

## Themes & i18n

- **Light and dark themes**, persisted and defaulting to the OS preference, toggled
  from the top bar. Built on semantic CSS-variable tokens (`src/styles.css`:
  `@theme` = dark, `:root.light` = light), so the whole UI re-skins automatically.
- **English / 中文 / 日本語**, switchable from the top bar and login, persisted to
  `localStorage`. English-as-key dictionary in `src/i18n/`; `npm run i18n:check`
  enforces that every `t()` key is translated in both non-English locales (and the
  `build` script runs it).

**These are framework rules, not options** — see [`CONVENTIONS.md`](CONVENTIONS.md).
All new UI must route text through `t()` and use semantic color tokens.

## Design

"Sentinel" — an obsidian instrument deck. Dark, high-contrast, precise:

- **Type:** Archivo (display) · Hanken Grotesk (body) · JetBrains Mono (readouts).
- **Palette:** layered graphite surfaces, a disciplined signal-lime accent for
  active/healthy/primary, and a severity signal scale for threats.
- **Texture:** faint top signal-glow, a fine masked grid, brushed-metal hairlines.
- Hand-rolled SVG charts (no generic chart library), staggered load reveals.

## Stack (current standards)

React 19 · TypeScript 6 · Vite 8 · Tailwind CSS v4 (CSS-first `@theme`) ·
TanStack Router + Query · Motion · lucide-react. Routes are lazy-loaded so the
initial bundle stays small (no >500 KB chunk).

## Develop

```bash
npm install
npm run dev          # http://localhost:5273  (proxies /api → VITE_API_TARGET, default :18090)
```

Point at a running control plane:

```bash
VITE_API_TARGET=http://localhost:18090 npm run dev
```

## Build & ship

```bash
npm run build        # tsc -b && vite build  →  dist/
npm run preview      # serve the production build
```

A production image (`Dockerfile` + `nginx.conf`) serves the SPA same-origin with
the API (`/api` is proxied to the `api` service), so it drops into the existing
`docker-compose.yml` in place of the `web` service.

## Structure

```
src/
  lib/         api client + types, session, app-context (the scope store), queries, format
  components/  ui (design system), charts (SVG), shell (app-centric layout + switcher), page kit
  routes/      login, overview, threats, instances, policies, protection, software, observability, access, not-found
  router.tsx   auth-guarded lazy routes + legacy redirects
  main.tsx     providers (QueryClient + Router)
```
