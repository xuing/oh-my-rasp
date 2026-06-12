# Internal — historical artifacts

The files in this directory are audit and planning documents produced during the
initial build phase of OhMyRasp. They are preserved for traceability and to
record decisions made at that time. They are **not** descriptions of the current
system — the current architecture, feature set, and implementation status are
documented under `docs/`.

## Files

| File | Description |
|---|---|
| `original-prompt.md` | The original Chinese-language design brief that initiated the project — defines the RASP scope, technology choices, and first-version requirements. |
| `feature-coverage.md` | Chinese-language feature-coverage tree comparing the legacy archived frontend and backend routes against the then-current OhMyRasp implementation. |
| `architecture-gap-audit.md` | Independent audit (2026-06-02) challenging the optimistic feature-coverage accounting and documenting what was not yet working end-to-end at that point. |
| `architecture-gap-repair-plan.md` | Repair plan (AG-01 through AG-18) derived from the gap audit, tracking each finding from Open through Fixed or Deferred by Design. |
| `application-scoping-refactor-plan.md` | Implementation plan for the application-centric architecture refactor that followed the AG repair pass; marked complete as of 2026-06-02. |
| `console-frontend-review.md` | Acceptance ledger for the rewritten `console/` frontend, recording the remediation items found in the original review and the evidence that each was addressed. |
| `mock-implementation-audit.md` | Audit of all seeded, generated, and placeholder code paths that existed in the early codebase, and the cleanup actions that removed them. |
| `feature-coverage/` | Supporting data directory for the feature-coverage tree. |
