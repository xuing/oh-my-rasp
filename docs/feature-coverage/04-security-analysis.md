# 4. Security Analysis

Status: Completed

## Evaluation

| Feature | Best-practice alignment | Current need | Necessity | Decision |
|---|---|---|---|---|
| Standalone runtime vulnerability list and status lifecycle | Weak alignment for this project right now. Runtime attacks, dependency vulnerabilities, and baseline findings have different lifecycles and should not be forced into one legacy vulnerability object. | Not currently needed. The project already models attack events, dependency vulnerabilities, and baseline findings separately. | Unnecessary now. | Implementation unnecessary. Keep separate evidence models until a dedicated vulnerability-management workflow is introduced. |
| Attack event search, report, detail, and parameters | Aligns. Event search and structured attributes are core RASP analysis workflows. | Needed for triage and cyber-range acceptance. | Necessary. | Implemented through `GET/POST /api/v1/events/attack` and Events page detail/parameter rows. |
| Per-event allowlist dialog | Does not align as an implicit write from one event. Allowlist changes should be explicit policy/configuration changes with review and audit. | Not currently needed. The Access page already has centralized allowlist configuration. | Unnecessary now. | Implementation unnecessary. Keep allowlist changes in protection settings. |
| Attack-event fix solution widget | Weak alignment. Attack events are observed facts; remediation belongs to rules, baseline findings, dependency vulnerabilities, and later case-management workflows. | Not currently needed as a separate component. | Unnecessary now. | Implementation unnecessary for attack events. Baseline remediation and dependency fixed versions are displayed where they are authoritative. |
| Event recycle bin | Aligns. Operators need reversible removal and audited purge for noisy or obsolete events. | Needed. | Necessary. | Implemented with search, delete-to-recycle-bin, restore, purge, details, and parameters. |
| Baseline security checks | Aligns. Configuration findings need search, severity/status, resource, remediation, and structured parameters. | Needed. | Necessary. | Implemented with `GET/POST /api/v1/baseline-findings` and Events page baseline detail rows. |
| Archived policy alarm compatibility endpoint | Weak alignment. It would duplicate baseline findings and create legacy API coupling. | Not needed. | Unnecessary. | Implementation unnecessary. Baseline findings are the supported model. |
| Dependency report and search | Aligns. Dependency inventory and vulnerability metadata are necessary for library security analysis. | Needed. | Necessary. | Implemented with `GET/POST /api/v1/dependencies`. |
| Dependency aggregation | Aligns. Operators need a quick count of vulnerable dependencies, known exploited findings, ecosystem distribution, and vulnerability severity distribution. | Needed. | Necessary. | Implemented with `GET /api/v1/dependencies/summary` and frontend summary cards. |
| Dependency deletion | Weak alignment as a per-row destructive operation. Dependencies are security evidence and latest observations. | Not currently needed. Maintenance cleanup already supports scoped retention cleanup. | Unnecessary now. | Implementation unnecessary. Keep removal audited through maintenance cleanup rather than ad hoc row deletion. |
| External vulnerability-source lookup | Aligns as a future intelligence integration, but not as a required base feature. | Not currently needed. Agents and scanners can report vulnerability metadata with dependency observations. | Unnecessary now. | Implementation unnecessary. Treat external source syncing as a later dedicated integration. |
| Dependency export | Aligns. Inventory export supports audits, reviews, and migration. | Needed. | Necessary. | Implemented with `GET /api/v1/dependencies/export` and the Events page export action. |

## Completed Features

- Attack event search/report/detail/parameter display.
- Recycle-bin search, restore, purge, and event parameter display.
- Baseline finding search/detail with remediation and structured parameters.
- Dependency inventory search plus vulnerability metadata display.
- Dependency aggregate summary API and frontend summary cards.
- Dependency export API and frontend JSON download.
- API tests for dependency export and summary.
- Web unit/E2E coverage for Events page data flows remains green.

## New Capabilities

- Operators can export dependency inventory as JSON.
- Operators can see global dependency counts, vulnerable dependency counts, known exploited counts, and top ecosystems.
- Dependency vulnerability severity is aggregated server-side.
- Events page rows now expose event attributes and baseline remediation inline, covering the current attack/baseline parameter workflows without legacy Vue component coupling.

## Implementation Tasks

Agent side:

- No new Agent code required. Existing attack, dependency, and baseline report contracts are sufficient for this section.

Backend side:

- Add dependency export and summary endpoints to OpenAPI.
- Regenerate strict OpenAPI bindings.
- Add `DependencySummary` to the control store interface.
- Implement dependency summary in MemoryStore and Postgres.
- Wire RBAC-protected dependency export/summary routes.
- Extend HTTP API tests.

Frontend side:

- Add typed dependency summary/export helpers.
- Add Events page dependency summary cards and export action.
- Show attack parameters, recycled-event parameters, baseline parameters, and remediation inline.
- Add localized copy for the new analysis controls.

## Verification

- `docker run --rm -v "$PWD":/src -w /src golang:1.26 go generate ./...` from `api/`.
- `docker run --rm -v "$PWD":/src -w /src golang:1.26 go test ./...` from `api/`.
- `cd web && npm run build`
- `cd web && npm test`
- `cd web && npm run e2e`
- `docker compose build --no-cache api migrate web && docker compose up -d web`
- Live API acceptance against `http://127.0.0.1:18090` for Agent registration, dependency ingest, baseline ingest, dependency summary, and dependency export.
- Live UI acceptance against `http://127.0.0.1:18091/events` for dependency summary cards, export control, attack parameters, baseline fix solutions, and no missing translation markers.
