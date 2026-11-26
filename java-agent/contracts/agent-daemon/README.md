# Agent-daemon contract fixtures

The Java agent and the Rust daemon share two local files and no code: the agent appends **events** to an NDJSON spool, and the daemon writes a **control** document the agent polls. [Architecture](../../../docs/architecture.md#agent-to-daemon-local-file-contract) explains the exchange. The files here are the examples both sides are tested against, and they are the reference for which fields exist and what they look like. A format change on one side fails a test on the other until the example is regenerated and the diff reviewed.

The directory is under `java-agent/` because the Gradle container the project uses mounts only `java-agent/` (see `scripts/check-agent.sh` and `.github/workflows/agent.yml`). The daemon tests read it as `../java-agent/contracts/agent-daemon`. There is one copy.

## Files

| Path | Produced by | Compared or read by |
|---|---|---|
| `events/primary/*.json` | `EventContractTest` and `TelemetryContractTest` in `agent-jdk25`: the real hooks and `JsonEventLogger` | The same tests (equality); `daemon/src/contract_tests.rs` (parsing and upload body) |
| `events/backport/*.json` | `Java8EventContractTest` in `backport-tests`: the real hooks, `OhMyRaspJava8Agent.premain` and `RaspRuntime`, on all three backport lines | The same test (equality, on each line); `daemon/src/contract_tests.rs` |
| `control/*.json` | `daemon/src/contract_tests.rs`: the real `Controller`, driven through the desired states | The same test (equality, and a reload by the daemon); `ControlContractTest` in `agent-jdk25` and `Java8ControlContractTest` in `backport-tests` |
| `control/expected.properties` | By hand | The three control tests: what each control document means |
| `control/rejected/*.json` | By hand | `ControlContractTest` and `Java8ControlContractTest`: each must leave the agent's state unchanged |

Each event file is one line. The control documents are the daemon's pretty-printed output.

## What the examples cover

- **Events, primary agent:** a blocked detection inside an HTTP request, with `request` fields and the redaction of `parameters` and `headers`; a monitored detection outside a request, whose `request` is empty; a latency telemetry line.
- **Events, backport agents:** a blocked detection after a request was entered; a monitored detection outside a request; a latency telemetry line; the agent start line, one file per line. A backport detection carries the `event` member, a numeric `timestamp`, and no `kind`, `request` or `latency_us`; the daemon reads `kind` as `detection` when it is absent.
- **Control:** each mode; a per-algorithm switch off and one explicitly on; a policy installed, with its string escapes; the same state after the policy is withdrawn, which drops the `policy` key. Every document carries the `revision` the daemon wrote.
- **Rejected control documents:** `truncated`, `not-an-object`, `invalid-utf8`, `nested-too-deep`, `trailing-text` and `utf8-bom`. Each says `"mode":"off"` where it parses far enough to say anything, so an agent that applied it would change state.

## Normalisation of volatile fields

A test normalises what the writer produced, then compares it to the file byte for byte (a file ends with one newline). The fixed values below are what the files hold.

| Field | Rule |
|---|---|
| Primary `timestamp` | An ISO-8601 instant string, replaced by `2026-01-01T00:00:00Z`. The test fails if the field is not one. |
| Backport `timestamp` | Epoch milliseconds, replaced by `1767225600000`. A start line has none. |
| `latency_us` | Replaced by `1234`. |
| `headers`, `details` (primary) | The agent emits the members in hash order, so the test sorts them by key before comparing. The files hold them sorted. |
| Start line `java_version`, `java_vendor` | Replaced by `1.8.0_402` and `Example Vendor`. |
| Backport line token | In rule ids (`javaN_...`) and in message text (`Java N`), the line's own token (`java8`, `java11`, `java17` and its number) is replaced by `javaN` / `Java N`, so one file serves the three lines. The three lines write identical lines apart from that token for every file except the start line, whose hooks the lines list in different orders: `agent-start-<line>.json` is one file per line and keeps its token. |
| Control `updated_at` | An RFC 3339 UTC time, replaced by `2026-01-01T00:00:00Z`. The test fails if the field is not one. |

No stack text, host name or process id appears in these lines. A new volatile field needs a rule here and in the normaliser of each test that reads it.

## Changing the format

A deliberate change to either file's format is one command and a reviewed diff. Each side rewrites the files it produces; run it, read `git diff` on this directory, and then run both suites without the flag so the other side is checked against the new files.

```bash
# Daemon: control/*.json
(cd daemon && OHMYRASP_CONTRACTS_UPDATE=1 cargo test --locked contract_tests)

# Agents: events/**. Run from the repository root; --tests belongs to the task before it.
docker run --rm -u "$(id -u):$(id -g)" -e GRADLE_USER_HOME=/gradle-home \
  -v "$HOME/.cache/ohmyrasp-gradle-home:/gradle-home" -v "$PWD/java-agent:/workspace" -w /workspace \
  "$(awk '$1 == "FROM" && $2 ~ /^gradle:/ { print $2; exit }' java-agent/Dockerfile)" \
  gradle --no-daemon --no-problems-report -Pcontracts.update=true \
  :agent-jdk25:test --tests '*ContractTest' :agent-java8:test --tests '*ContractTest' \
  :agent-java11:test --tests '*ContractTest' :agent-java17:test --tests '*ContractTest'
```

`expected.properties` and `rejected/` are written by hand: change them with the format. After an update run, run the suites again without the flag: with the flag the three backport lines each rewrite the shared files, so only a normal run shows that the lines still agree.

## Differences the examples pin today

These are facts about the current code, kept visible here so that a change to any of them shows up as a diff. None is a test failure.

- The backport agent start line has no `kind`, so the daemon ingests it as a detection with an empty hook, algorithm and action: it counts in the attack log and is uploaded as a low-severity "agent event". The primary agent writes no start line.
- The backports write `timestamp` as a number. The daemon reads only a string, so a backport detection is uploaded with the time the daemon read it as `occurred_at`.
- The agent redacts the values in `parameters` and `headers` but writes `query` as it came, and the daemon uploads `request.query`. A secret in the query string leaves the host.
- The start lines of `agent-java8` and of `agent-java11` and `agent-java17` list their hooks in different orders, and the latter two carry a `startup_probe` member. The daemon reads none of them.
- The daemon's own reader accepts only lowercase `off`, `monitor` and `block` for `mode`; the agents also accept `record`, `observe`, `log`, `protect` and the other aliases, in any case. A control file an operator edited by hand with an alias is reinitialised when the daemon starts.
- The agents ignore a control file larger than 1 MiB. The daemon writes the cloud policy into it without a limit.
- The backport agents read only `mode` from the control file. The per-algorithm switches, the revision and the policy apply on the primary agent only.
