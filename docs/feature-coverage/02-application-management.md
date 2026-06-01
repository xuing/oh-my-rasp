# 2. Application Management

Status: Completed

## Evaluation

| Feature | Best-practice alignment | Current need | Necessity | Decision |
|---|---|---|---|---|
| Application list and selection | Aligns. Operators need a scoped inventory before managing Agents, policies, events, and environments. | Needed. Applications are the primary tenancy and credential boundary in this project. | Necessary. | Implemented with `GET /api/v1/applications` and the Applications page. |
| Create application | Aligns. Application creation should mint a one-time Agent secret and create an audit trail. | Needed for onboarding protected services. | Necessary. | Implemented with `POST /api/v1/applications`; create returns the one-time secret. |
| Delete application | Aligns when implemented as an audited active-inventory removal rather than silent destructive cleanup. | Needed so operators can retire services cleanly. | Necessary. | Implemented with `DELETE /api/v1/applications/{appID}`. The Postgres store soft-deletes applications and unbinds daemon workloads; MemoryStore removes active dependent inventory for tests. |
| Application configuration endpoint | Partially aligns as a legacy compatibility shape, but monolithic app config is not the best model for this project. | Not needed as a separate endpoint. App behavior is split across application metadata, environments, policy rollouts, daemon workload bindings, alert rules, and system settings. | Unnecessary as a single legacy endpoint. | Implementation unnecessary. Keep configuration in explicit bounded resources. |
| Application initialization endpoint | Aligns as a behavior, but not as a separate endpoint. | Needed during create. | Necessary as create-time initialization. | Implemented through application creation, which initializes ID, secret, audit entry, and later environment attachment. |
| Application export | Aligns. Inventory export is useful for backup, review, and migration. | Needed for operations. | Necessary. | Implemented with `GET /api/v1/applications/export` and a JSON download action in the Applications page. |
| Application summary | Aligns. High-level app counts belong in analytics/overview rather than application CRUD. | Needed for dashboard context. | Necessary. | Covered by `GET /api/v1/analytics/overview` and Overview metrics. |
| Get application secret | Does not align as a persistent read. Long-lived secret readback increases blast radius. | Not needed. Create and rotate return the secret once; agents authenticate with the stored hash/value path server-side. | Unnecessary. | Implementation unnecessary. Use one-time display on create/rotate, then rotate if the operator loses the secret. |
| Regenerate application secret | Aligns. Rotation is the safer alternative to readback. | Needed for credential hygiene and incident response. | Necessary. | Implemented with `POST /api/v1/applications/{appID}/secret/rotate`; old Agent credentials are rejected. |
| Application environments | Aligns. Environments are explicit deployment scopes and policy rollout targets. | Needed. | Necessary. | Implemented with `POST /api/v1/applications/{appID}/environments` and environment-aware Agent registration/policy rollout. |
| Command labels and command settings | Weak alignment for this architecture. Static command labels couple UI state to daemon injection commands. | Not needed. Daemon commands are derived from observed workloads, application binding, daemon token authorization, and application secrets. | Unnecessary. | Implementation unnecessary. Workload bind/unbind and daemon command generation provide the current, auditable control model. |

## Completed Features

- Application list, creation, environment creation, secret rotation, overview counts, active-inventory deletion, and JSON export.
- Frontend actions for application creation, environment creation, secret rotation, application export, and application deletion.
- Backend OpenAPI contract, generated handlers, RBAC-protected routes, MemoryStore behavior, and Postgres persistence for export/delete.
- Audit coverage for application creation, secret rotation, environment creation, and deletion.

## New Capabilities

- Operators can export application inventory as JSON from both API and UI.
- Operators can remove an application from active inventory through an audited DELETE endpoint.
- Deleted applications no longer appear in application list/export responses.
- Daemon workloads bound to a deleted application are unbound in Postgres so future daemon command generation will not inject retired services.

## Implementation Tasks

Agent side:

- No Agent code changes required. Existing Agent registration and heartbeat paths already depend on application ID, environment ID, and current application secret.

Backend side:

- Add OpenAPI operations for application export and deletion.
- Regenerate OpenAPI server bindings.
- Add `DeleteApplication` to the control store interface.
- Implement active-inventory deletion in MemoryStore and Postgres.
- Add RBAC-protected routes for export/delete.
- Add HTTP API tests for export, deletion, repeated deletion, and audit logging.

Frontend side:

- Add typed API helpers for application export and deletion.
- Add Applications page controls with localized labels, success messages, and error messages.
- Extend Playwright coverage for export/delete interactions.

## Verification

- `docker run --rm -v "$PWD":/src -w /src golang:1.26 go test ./...` from `api/`.
- `cd web && npm run build`
- `cd web && npm test`
- `cd web && npm run e2e`
- `docker compose build --no-cache api migrate web && docker compose up -d web`
- Live API acceptance against `http://127.0.0.1:18090` for create, environment create, export, delete, list, and export-after-delete.
- Live UI acceptance against `http://127.0.0.1:18091/applications` for localized application-management controls.
