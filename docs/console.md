# Console

The `console/` directory contains the OhMyRasp control-plane web frontend. It is a single-page React application served same-origin with the Go control-plane API.

## Technology Stack

Versions are pinned in `console/package.json` and `console/Dockerfile`:

| Layer | Package |
|---|---|
| Runtime requirement | Node.js (range in `engines.node`; Node Alpine image tag in `console/Dockerfile`) |
| UI framework | `react`, `react-dom` |
| Type checking | `typescript` and `@typescript/native` (aliases defined in `package.json`) |
| Build tool | `vite` (`@vitejs/plugin-react`) |
| Routing | `@tanstack/react-router` |
| Data fetching | `@tanstack/react-query` |
| Styling | `tailwindcss`, `@tailwindcss/vite` (CSS-first `@theme` in `src/styles.css`) |
| Animation & icons | `motion`, `lucide-react` |
| E2E tests | `@playwright/test` |
| i18n | Built-in `useT()` / `translate()` (`en`, `zh`, `ja`) verified by `scripts/i18n-coverage.ts` |

## Navigation, Scoping, and Error Handling

- **Application-centric scope**: `src/lib/app-context.ts` stores the active `applicationId` and optional `environmentId` across reloads so views stay scoped to one application.
- **Lazy-loaded routes and error boundary**: `src/router.tsx` splits each route into its own chunk and wraps the root route in `RootErrorBoundary` so a malformed API record or render error does not blank the entire application.
- **Role guard**: routes under `appLayout` require a session token (`authToken()`); `/access` additionally requires `isPrivileged()` (`admin` or `security_engineer` in `src/lib/session.ts`).
- **i18n & themes**: English-as-key translations live in `src/i18n/messages.ts` (`zh` and `ja`), and dark/light CSS variables live in `src/styles.css` (`@theme` dark default, `:root.light` overrides). All contributor rules live in [`../console/CONVENTIONS.md`](../console/CONVENTIONS.md).

## Screens

Routes defined in `console/src/router.tsx` and linked from `console/src/components/shell.tsx`:

| Screen | Path | Route module | Description |
|---|---|---|---|
| Overview | `/` | `src/routes/overview.tsx` | Live security posture for the selected application: threat trends, fleet health summary, and attack-type distribution. |
| Threats | `/threats` | `src/routes/threats.tsx` | Attack, hook-error, and crash event timelines with scope/severity/hook/time filters and the Event Recycle Bin (soft-delete, restore, purge). |
| Applications | `/applications` | `src/routes/applications.tsx` | Application and environment inventory, registration details, and application secret rotation. |
| Instances | `/instances` | `src/routes/instances.tsx` | Live agent fleet, daemon workload inventory and bindings, daemon token rotation, and agent artifact catalog/upload/download. |
| Policies | `/policies` | `src/routes/policies.tsx` | Policy-set creation, rule validation, rule simulation against recorded events, draft editing, version publishing, canary rollout, and rollback. |
| Protection Config | `/protection` | `src/routes/protection.tsx` | Per-application allowlists, hardening mode, dependency vulnerability thresholds, retention controls, and maintenance cleanup. |
| Software & Posture | `/software` | `src/routes/software.tsx` | Agent-reported dependency inventory (package paths, licenses, CVEs) and configuration baseline findings. |
| Observability | `/observability` | `src/routes/observability.tsx` | Hook latency percentiles, per-agent overhead, and policy-version performance reports. |
| Access & Audit | `/access` | `src/routes/access.tsx` | Restricted to `admin` and `security_engineer` roles: user administration, RBAC roles, alert rules, alert delivery history, audit logs, system settings, and edition status. |
| Login | `/login` | `src/routes/login.tsx` | Session authentication with theme and language toggles. |

Legacy URL paths (`/dashboard`, `/events`, `/agents`, `/dependencies`, `/safe/dependency`, `/safe/baseline`, `/algorithm`, `/safe/recycleBin`, `/maintain/whitelist`, `/algorithm/hardening`, `/algorithm/alarm`, `/platform`, `/log/audit`, `/settings/panel`, `/settings/alarm`, `/settings/systemInfo`, `/settings/poolVersion`, `/settings/version`) redirect via `aliasRedirect` in `src/router.tsx` into the current route tree.

## Local Development

Run from `console/` (Node.js range in `engines.node` of `console/package.json`):

```bash
npm ci
npm run dev
```

Per `console/vite.config.ts`, `npm run dev` binds `0.0.0.0:5273` (`strictPort: true`, `allowedHosts: true`) and proxies `/api`, `/healthz`, `/readyz`, `/v1/version`, and `/metrics` to `VITE_API_TARGET` (default `http://localhost:18090`). To target another API address:

```bash
VITE_API_TARGET=http://127.0.0.1:18090 npm run dev
```

Preview the production bundle locally:

```bash
npm run preview
```

## Verification

All scripts in `console/package.json`:

```bash
# Check zh/ja translation parity and quoted t("...") coverage
npm run i18n:check

# ESLint (src/**/*.{ts,tsx} + scripts)
npm run lint

# TypeScript project type-check (no emit)
npm run typecheck

# i18n check + tsc -b + Vite production build into dist/
npm run build

# Mocked Playwright E2E suite (serves dev server on http://127.0.0.1:5273)
npx playwright install chromium   # first run only
npm run test:e2e

# Full local verification (i18n:check && lint && typecheck && test:e2e)
npm test

# Live Playwright E2E smoke test against a running Compose stack
# Reads credentials from OHMYRASP_E2E_ADMIN_PASSWORD or ../.env
npm run test:e2e:live
```

`playwright.config.ts` excludes `live-console.spec.ts` and runs mocked browser flows against `http://127.0.0.1:5273`. `playwright.live.config.ts` runs `e2e/live-console.spec.ts` against `OHMYRASP_E2E_LIVE_URL` (default `http://127.0.0.1:18091`).

## Container and Nginx Proxy

`console/Dockerfile` builds `dist/` with a Node Alpine image and serves it from an nginx Alpine image (tags in `console/Dockerfile`) on port `8080` (`WEB_PORT=18091` in `docker-compose.yml`). `console/nginx.conf`:

- Proxies `/api/` to `http://api:8080/api/` with `Host`, `X-Forwarded-For`, and `X-Forwarded-Proto`.
- Serves `/assets/` with `Cache-Control: public, immutable` (`expires 1y`) and falls back SPA routes to `/index.html`.
- Applies strict security headers on every response: `Content-Security-Policy` (`default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Permissions-Policy: geolocation=(), microphone=(), camera=()`.

## Source Layout

```text
console/
  src/
    components/  UI primitives, SVG charts, shell + topbar switcher, page helpers, toast
    i18n/        useT(), translate(), zh/ja message tables
    lib/         API client + types, session store, app-context scope, queries, theme, format
    routes/      lazy-loaded page components
    router.tsx   auth-guarded route tree, RootErrorBoundary, legacy alias redirects
    main.tsx     QueryClient + Router providers
    styles.css   Tailwind v4 @theme dark tokens and :root.light overrides
  e2e/           Playwright mocked (console.spec.ts) and live (live-console.spec.ts) suites
  scripts/       i18n-coverage.ts
```

## Related Documentation

- [Console Conventions](../console/CONVENTIONS.md): mandatory i18n and semantic theming rules
- [Architecture](architecture.md): how the console connects to the Go API and storage layer
- [API Reference](api-reference.md): REST endpoints consumed by the console
- [Getting Started](getting-started.md): starting the full stack locally
