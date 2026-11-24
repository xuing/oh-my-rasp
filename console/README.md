# OhMyRASP Console

Application-centric React frontend for the OhMyRasp control plane (`console/`).

See [`../docs/console.md`](../docs/console.md) for the full screen inventory, technology stack, nginx security headers, and E2E setup, and [`CONVENTIONS.md`](CONVENTIONS.md) for the mandatory i18n and theming rules every UI change must follow.

## Quick Start

Requires the Node.js range in `engines.node` of `console/package.json`.

```bash
npm ci
npm run dev          # binds 0.0.0.0:5273, proxies /api -> VITE_API_TARGET (default http://localhost:18090)
```

Point the dev proxy at a custom control-plane API URL:

```bash
VITE_API_TARGET=http://127.0.0.1:18090 npm run dev
```

## Build and Verify

```bash
npm run build        # i18n:check && tsc -b && vite build -> dist/
npm run preview      # preview production build locally
npm run lint         # eslint .
npm run typecheck    # tsc -b --noEmit
npm run i18n:check   # verify zh/ja translation parity and quoted t("...") keys
npm test             # i18n:check && lint && typecheck && test:e2e
```

Playwright suites: `npm run test:e2e` (mocked API on `http://127.0.0.1:5273`) and `npm run test:e2e:live` (live Compose console at `OHMYRASP_E2E_LIVE_URL`, default `http://127.0.0.1:18091`).

## Directory Layout

```text
src/
  lib/         API client + types, session store, app/env scope store, queries, theme, format
  components/  UI primitives, SVG charts, app-centric shell + switcher, page helpers, toast
  i18n/        useT(), translate(), zh/ja message tables
  routes/      login, overview, threats, applications, instances, policies, protection, software, observability, access, not-found
  router.tsx   auth-guarded lazy routes, RootErrorBoundary, legacy alias redirects
  main.tsx     QueryClient + Router providers
  styles.css   Tailwind v4 @theme dark tokens and :root.light overrides
```
