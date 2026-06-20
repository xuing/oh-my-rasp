# 05. Protection Settings and Detection Algorithms

## Decision

Status: Completed

The legacy protection surface maps to three current OhMyRasp areas:

- Protection and hardening settings are managed as audited system settings in the Access & Audit page and are also reachable from `/algorithm/hardening` and `/algorithm/alarm` compatibility routes.
- Detection algorithms are managed as policy rules in the Policies page and are also reachable from `/algorithm` and `/algorithm/algorithm`.
- Java Agent hook coverage is validated by unit tests, the multi-Tomcat playground, and live protected/baseline acceptance checks.

This follows current best practice better than reproducing the older one-application-one-config shape: policy state is versioned, testable, canary-capable, auditable, and separated from runtime evidence.

## Completed Features

- Added `GET /api/v1/policies/algorithms` to expose the supported hook and algorithm catalog.
- Added `POST /api/v1/policies/{policyID}/restore-default` to restore the built-in detector catalog as a new draft policy version.
- Kept restore-default safe by creating a draft instead of publishing automatically.
- Updated the policy editor to select hooks and algorithms from the backend catalog.
- Added a policy-page algorithm catalog so operators can see all supported hooks and detector names.
- Added a Restore Defaults action in the policy editor.
- Added alert delivery interval configuration through the audited `alerts.delivery` system setting.
- Added compatibility routes for `/algorithm`, `/algorithm/algorithm`, `/algorithm/hardening`, and `/algorithm/alarm`.
- Expanded the Java playground catalog so all browser-runnable cases include request scanner and missing-User-Agent detections.

## Agent Tasks Delivered

- The Java Agent exposes request, response, SQL, SQL exception, command, process, file, directory, SSRF, DNS, JNDI, XXE, deserialization, OGNL, eval, load-library, upload, WebDAV, rename, link, include, and webshell detector hooks through `OhMyRaspHooks`.
- The playground now includes browser-runnable synthetic request cases for `request_scanner` and `request_unusual`, while retaining the header-based acceptance checks.
- The Tomcat 9, 10, and 11 baseline/protected playground services were rebuilt and verified.

## Backend Tasks Delivered

- Added a structured algorithm catalog model in the control domain.
- Added default policy rule generation from the catalog, covering every supported detector algorithm.
- Added memory and PostgreSQL restore-default implementations with audit action `policy.restore_default`.
- Added OpenAPI contract entries and regenerated generated bindings.
- Added HTTP routes and strict OpenAPI handlers.
- Added unit and HTTP API tests for catalog coverage and restore-default behavior.

## Frontend Tasks Delivered

- Added API client types and hooks for the policy algorithm catalog.
- Added a restore-default policy client action.
- Replaced free-form hook entry in the policy editor with catalog-backed hook and algorithm selectors.
- Added a visible algorithm catalog to the Policies page.
- Added alert interval configuration to the protection configuration form.
- Added compatibility routes for the archived `/algorithm` paths.
- Updated E2E mocks and workflow coverage.

## Implementation Unnecessary Decisions

### SMTP Email Test

The legacy `/v1/api/app/email/test` endpoint is not implemented. A test-email endpoint is only useful when the product owns SMTP credentials, delivery templates, and secret rotation. This project currently stores alert targets and delivery evidence, but it does not configure an SMTP transport. Adding a fake or partial email-test endpoint would create a misleading pass/fail signal and encourage operators to store secrets before the alert delivery subsystem needs them.

Best-practice alternative: keep alert rules and alert delivery history implemented, and add an SMTP/provider integration later as a dedicated, secret-managed delivery module.

### Legacy Plugin Management

The legacy plugin pages and plugin APIs are not implemented. Runtime security plugins need a stable ABI, sandboxing model, signature or provenance checks, compatibility rules, and rollback semantics. The current project is still centered on a Java Agent plus a versioned policy catalog. Implementing upload/update/delete plugin flows before that contract exists would increase supply-chain risk and produce an unstable extension point.

Best-practice alternative: keep detector expansion inside reviewed Agent releases and versioned policies until a safe plugin ABI is designed.

### Exact Legacy Advanced Dialog

The archived `advancedDialog.vue` is not reproduced as a same-shaped modal. The current policy editor already exposes the advanced fields that matter operationally: hook, algorithm, action, severity, expression, tags, validation, testing, rollout, and rollback. Recreating the old modal would duplicate the same state without improving safety.

Best-practice alternative: keep advanced policy controls inline with validation and test feedback.

### Non-Java Framework Hooks

Some archived categories, such as PHP include semantics and framework-specific upload/plugin surfaces, are represented as detector algorithms and explicit playground policies but are not treated as automatic Java bytecode hooks. That is intentional: the current project is a Java Agent. Cross-runtime semantics should be implemented by runtime-specific agents rather than forced into Java instrumentation.

## Acceptance Evidence

- `docker run --rm -v "$PWD/api":/src -w /src golang:1.26 go generate ./...`
- `docker run --rm -v "$PWD/api":/src -w /src golang:1.26 go test ./...`
- `cd console && npm run build && npm test && npm run test:e2e`
- `cd java-agent && ./scripts/acceptance.sh`
- `docker compose build api migrate web && docker compose up -d web`
- Live control-plane API check: algorithm catalog returned 24 hooks; restore-default created 54 draft rules; `alerts.delivery.interval_seconds` persisted.
- Live control-plane UI check: `/algorithm/algorithm` exposed the algorithm catalog and Restore Defaults action; `/algorithm/alarm` exposed Alert Interval Seconds.
- Live playground check: public baseline page renders 53 runnable cases and 22 archived Java labs.
- Live protected checks: request scanner and missing-User-Agent cases redirect on protected Tomcat 9, 10, and 11.
