# web

New React control-plane frontend for the self-hosted OhMyRasp platform. This is
a from-scratch rewrite using React 19, TypeScript, Vite 8, TanStack Router,
TanStack Query, Tailwind CSS 4, and local shadcn-style primitives.

The current shell covers the required platform domains:

- Overview
- Applications
- Agents
- Policies
- Events
- Observability
- Access & Audit

The shell provides a desktop sidebar plus a compact mobile primary navigation
bar, and header shortcuts route directly into policy validation and Agent
registration workflows.

The app includes an API-backed login form. The overview, applications, Agents,
policies, events, observability, and access pages use live API queries with
explicit loading, error, and empty states when data is unavailable. The applications page can
rotate application secrets used by Agent operations, and the access page includes
RBAC roles, user administration, system settings, alert rules, alert delivery
history, audit logs, the OSS self-hosted edition/license status, and audited
protection configuration controls for allowlists, hardening mode, dependency
vulnerability thresholds, retention, and maintenance cleanup. The cleanup panel can preview or apply application-scoped
operational data cleanup across events, dependencies, baseline findings, and
alert deliveries, with the backend enforcing a destructive confirmation phrase.

The Agents page also exposes daemon workload operations: administrators and
security engineers can reveal or rotate the daemon token, review reported
process/container workloads, display injection outcomes, and bind or unbind
those workloads to managed applications before Agent installation. It also shows
the Agent artifact catalog exposed by the control API, lets operators upload
managed Java Agent ZIP packages, then verifies daemon application credentials
and Java Agent artifact metadata with the current daemon token before
downloading the selected Agent ZIP through the browser.

The Policies page supports policy-set creation, rule validation/simulation,
draft rule updates, scoped rollout, and rollback from the live API.

The Events page supports live query filters for application, environment, Agent,
policy, severity, hook, occurred-at time range, and result limit across attack,
hook, performance, and crash event timelines. It also includes an Event Recycle
Bin panel for moving events out of active investigation views, restoring them,
or permanently deleting already-recycled events. The dependency inventory on
that page also supports filtered reads by application, Agent, dependency name,
ecosystem, vulnerability severity, observed-at time range, and result limit, and
displays package paths, licenses, and vulnerability identifiers. The baseline
findings table supports application, environment, Agent, severity, status,
category, observed-at, and limit filters for runtime posture checks.

The Observability page supports live application and policy filters for rule
overhead, Hook latency, Agent overhead, and policy-version impact reports.

## Local Development

```bash
npm install
npm run dev -- --host 0.0.0.0 --port 5173
```

## Verification

```bash
npm run build
npm test
npm run e2e
```
