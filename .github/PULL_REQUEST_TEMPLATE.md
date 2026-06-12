## What and why

<!--
Describe the change and the motivation behind it. Link to the issue(s)
this closes with "Closes #NNN" so GitHub auto-closes them on merge.
-->

Closes #

## Changes

<!--
Bullet-point summary of the notable changes. Be specific enough that a
reviewer can follow without reading every line of diff.
-->

-

## Tests run

<!--
List the test commands you executed and their outcome. At minimum run
the suite for the component(s) you touched.

  api/        go test ./...
  console/    pnpm test (vitest)
  java-agent/ mvn verify -pl agent-jdk25
  daemon/     cargo test
-->

- [ ] Relevant unit / integration tests pass locally.
- [ ] New behaviour is covered by tests (or explain why it is not
      practical).

## Checklist

- [ ] **Docs updated** — if you changed user-visible behaviour, updated
      the relevant file(s) under `docs/` or inline in the component.
- [ ] **i18n keys** — if the change adds or renames UI strings in
      `console/`, the corresponding keys are present in all locale files
      under `console/src/locales/`.
- [ ] **Coverage docs regenerated** — if you added or modified a hook or
      detector in `java-agent/`, re-run the coverage generator and
      committed the updated `java-agent/docs/DETECTION-COVERAGE.md` and
      `java-agent/docs/FALSE-POSITIVE-REPORT.md`.
- [ ] **Breaking changes** — if this PR changes an API contract, wire
      format, or config schema, the change is called out explicitly above
      and migration steps are documented.
- [ ] **No secrets or credentials** committed (checked with
      `git diff HEAD~1 | grep -iE 'password|secret|token|key'`).
