# Development reference

This directory holds the durable technical ledgers kept in sync with the Java agent source code.

## algorithm-coverage.md

[`algorithm-coverage.md`](algorithm-coverage.md) records every hook point and detection algorithm implemented in the `agent-jdk25` detector classes, organized by runtime era (Java 25 primary, Java 8/11/17 backports) and attack family. Update it in the same commit whenever you add, remove, or rename a detector or change an acceptance key.

## vulhub-coverage.md

[`vulhub-coverage.md`](vulhub-coverage.md) tracks Vulhub component and CVE replay coverage, expected baseline exploitation proof, matching Java LTS agent, and protected-side block condition.

`python3 java-agent/scripts/check-vulhub-java-coverage.py` cross-references this checklist against the acceptance scripts in `java-agent/acceptance/`. CI fails if a checked entry has no matching acceptance script or if an acceptance script covers an unlisted target. Update this file in the same patch as any new Vulhub target, moving entries out of candidates only after both baseline exploitation and protected-side blocking pass.

## Auto-generated docs

These files are generated from source and must not be edited by hand:

| File | Generator | CI check |
|---|---|---|
| [`java-agent/docs/DETECTION-COVERAGE.md`](../../java-agent/docs/DETECTION-COVERAGE.md) | `java-agent/scripts/gen-detection-coverage.py` | `python3 java-agent/scripts/gen-detection-coverage.py --check` |
| [`java-agent/docs/FALSE-POSITIVE-REPORT.md`](../../java-agent/docs/FALSE-POSITIVE-REPORT.md) | `java-agent/scripts/run-fp-report.sh` | Re-run after detector changes |
| [`deploy/shirudo/README.md`](../../deploy/shirudo/README.md) and `deploy/shirudo/ohmyrasp-*/README.md` | `deploy/shirudo/gen-readmes.py` | `python3 deploy/shirudo/gen-readmes.py --check` (run by `deploy/shirudo/verify-shirudo-upatch.sh`) |

Regenerate affected files in the same pull request whenever hooks, detectors, transformers, or acceptance scripts change:

```bash
python3 java-agent/scripts/gen-detection-coverage.py
bash java-agent/scripts/run-fp-report.sh
python3 deploy/shirudo/gen-readmes.py
```
