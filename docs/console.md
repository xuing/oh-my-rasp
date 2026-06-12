# Console

The `console/` directory is the OhMyRasp control-plane frontend. It is a
from-scratch React 19 application built with Vite 8, TanStack Router, TanStack
Query, and Tailwind CSS v4. It is the sole supported frontend; the legacy
`web/` directory is no longer active.

## Technology stack

| Layer | Library / version |
|---|---|
| UI framework | React 19 + TypeScript |
| Build tool | Vite 8 |
| Routing | TanStack Router |
| Data fetching | TanStack Query v5 |
| Styling | Tailwind CSS v4 |
| Animation | Motion (motion/react) |
| i18n | Built-in (English, Chinese, Japanese) |
| E2E tests | Playwright |

Every user-facing string is rendered through the `t()` hook. The language
switcher persists the selection to `localStorage` and syncs `document.lang`.
`npm run i18n:check` verifies that all three locale tables are complete; the
`build` script runs this check automatically.

## Screens

All routes live under an authenticated shell that requires a valid API token.
Unauthenticated requests are redirected to `/login`.

| Screen | Path | Description |
|---|---|---|
| Overview | `/` | Live security posture for the selected application: threat trend chart, fleet health summary, and attack-type distribution. |
| Threats | `/threats` | Attack, hook-error, and crash event timelines with filters for application, environment, agent, policy, severity, hook, time range, and result limit. Includes an Event Recycle Bin panel for soft-deleting, restoring, or permanently removing events. |
| Applications | `/applications` | Application inventory — create and delete applications, view registration details, and rotate the application secret used by agent operations. |
| Instances | `/instances` | Agent fleet management — live agent list with status, workload bindings, daemon token reveal/rotation, agent artifact catalog, artifact upload, and artifact download. |
| Policies | `/policies` | Policy-set lifecycle: create policy sets, author and validate rules, simulate rules against recorded events, publish drafts, scope rollout, and roll back to a previous version. |
| Protection | `/protection` | Per-application protection configuration: allowlist management, hardening mode, dependency vulnerability severity threshold, and data retention and maintenance cleanup settings. |
| Software | `/software` | Software composition analysis and runtime posture — agent-reported dependency inventory (SBOMs with package paths, licenses, and CVE identifiers) and configuration baseline findings. |
| Observability | `/observability` | Runtime overhead reporting: hook latency percentiles, per-agent overhead, and policy-version performance impact, filtered by application and policy. |
| Access | `/access` | Administration only — user accounts, RBAC roles, alert rules, alert delivery history, audit logs, system settings, edition/license status, and audited protection controls. |

The Access screen is restricted to privileged users (admin and security-engineer
roles). All other screens are available to any authenticated user.

Several legacy URL patterns redirect into the new route structure so that
bookmarks and external links remain valid (for example `/events` redirects to
`/threats` and `/agents` redirects to `/instances`).

## Local development

```bash
# Install dependencies (Node >= 24 required)
npm install

# Start the dev server, exposed on all interfaces
npm run dev -- --host 0.0.0.0 --port 5173
```

The `dev` command proxies API requests to the local control-plane API
(`http://localhost:8080` by default — see `vite.config.ts`).

## Verification

```bash
# Type-check and verify i18n completeness, then build
npm run build

# Run Playwright end-to-end tests
npm run test:e2e

# Run all checks (i18n + typecheck + e2e)
npm test
```

## Docker Compose

`docker-compose.yml` builds the `console/` directory as the `web` service.
The built static assets are served by the nginx container at port 80 and
proxied to the Go API at port 8080.

## Related documentation

- [Architecture](architecture.md) — how the console fits into the overall
  system
- [API Reference](api-reference.md) — the REST endpoints the console calls
- [Getting Started](getting-started.md) — running the full stack locally
