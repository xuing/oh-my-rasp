## What and why

<!--
Describe the change and motivation. Link related issue(s) with "Closes #NNN".
-->

Closes #

## Changes

<!--
Specific bullet-point summary of observable changes.
-->

-

## Tests run

<!--
List executed commands and outcomes for every touched component:
  api/            go test ./...
  console/        npm run build && npm test
  java-agent/     gradle --no-daemon :agent-jdk25:check
                  bash scripts/check-detector-parity.sh
                  python3 scripts/check-vulhub-java-coverage.py
  daemon/         cargo test --locked
  deploy/shirudo/ ./deploy/shirudo/verify-shirudo-upatch.sh
-->

- [ ] Relevant unit / integration tests pass locally.
- [ ] New behaviour is covered by tests (or explain why not practical).

## Checklist

- [ ] **Docs updated:** updated the owning reference under `docs/` in the same PR (linking to source files/symbols; `docs/internal/` left frozen).
- [ ] **Console i18n keys:** if UI strings in `console/` changed, `console/src/i18n/messages.ts` passes `npm run i18n:check`.
- [ ] **Generated docs fresh:** if hooks, detectors, or Vulhub scripts changed, ran `python3 java-agent/scripts/gen-detection-coverage.py --check`, `python3 java-agent/scripts/gen-hook-targets.py --check`, `bash java-agent/scripts/run-fp-report.sh`, and `python3 deploy/shirudo/gen-readmes.py --check`, and committed updated outputs.
- [ ] **Breaking changes:** API, wire-format, or config schema changes are called out above with migration steps.
- [ ] **No secrets or credentials** committed (checked with `git diff HEAD~1 | grep -iE 'password|secret|token|key'`).
