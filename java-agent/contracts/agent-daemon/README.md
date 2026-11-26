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
| `control/hand-edited/*.json`, `control/hand-edited/expected.properties` | By hand | `ControlContractTest` and `Java8ControlContractTest` (the agents apply the mode the manifest says); `daemon/src/contract_tests.rs` (the daemon keeps the document and rewrites the canonical mode) |
| `control/limits.properties` | By hand | The size limit of a control document: `daemon/src/control.rs`, and the control tests of both agent engines, compare their own constant with it |
| `control/rejected/*.json` | By hand | `ControlContractTest` and `Java8ControlContractTest`: each must leave the agent's state unchanged |

Each event file is one line. The control documents are the daemon's pretty-printed output.

## What the examples cover

- **Events, primary agent:** a blocked detection inside an HTTP request, with `request` fields and the redaction of `parameters`, `headers` and the sensitive values inside `query`; a monitored detection outside a request, whose `request` is empty; a latency telemetry line.
- **Events, backport agents:** a blocked detection after a request was entered; a monitored detection outside a request; a latency telemetry line; the agent start line, one file per line. A backport detection carries the `event` member, a numeric `timestamp`, and no `kind`, `request` or `latency_us`. The start line has `event` and no `kind` or `timestamp`.
- **Control:** each mode; a per-algorithm switch off and one explicitly on; a policy installed, with its string escapes; the same state after the policy is withdrawn, which drops the `policy` key. Every document carries the `revision` the daemon wrote.
- **Hand-edited control documents:** the daemon's document with `mode` changed to each spelling both agent engines accept (`disabled`, `none`, `record`, `observe`, `log`, `blocking`, `protect`), to upper and mixed case, and padded with spaces. The agents must apply the mode, and the daemon must read the document instead of reinitialising it, and write the canonical word next time.
- **Rejected control documents:** `truncated`, `not-an-object`, `invalid-utf8`, `nested-too-deep`, `trailing-text` and `utf8-bom`. Each says `"mode":"off"` where it parses far enough to say anything, so an agent that applied it would change state.

## How the daemon reads a line

The daemon classifies each line by `kind` when it has one, and by its other members when it has none (`AgentEvent::class` in `daemon/src/model.rs`; `daemon/src/contract_tests.rs` checks every example against it).

| Line | Read as | What the daemon does |
|---|---|---|
| `kind` is `detection`; or no `kind` and `event` is `ohmyrasp-detection`; or no `kind` and the line has an `algorithm` and an `action` | detection | Attack log, detection counters, upload |
| `kind` is `telemetry` | telemetry | Latency panel only |
| `kind` is `lifecycle`; or no `kind` and `event` is `ohmyrasp-<line>-agent-start` | lifecycle | The `agent` entry of `/api/stats` (agent line, Java version and vendor); nothing else |
| Any other `kind`, including a `kind` that is present and not a string (counted as `(non-string)`, never inferred from the other members); or no `kind` and nothing above matches | ignored | Counted under `ignored_kinds` in `/api/stats` and logged at debug level; never a detection, never uploaded |

`timestamp` is an RFC 3339 string, kept as written, or a number of epoch milliseconds, which the daemon converts to RFC 3339 UTC. A line with neither, or with a number it cannot convert (negative, or past year 9999), has no time of its own and the upload carries the time the daemon read it as `occurred_at`.

## Spellings of the mode

An operator can edit the control file by hand, and both agent engines accept more spellings than the three words the daemon writes. The two engines accept the same set: `off`, `disabled`, `none` for off; `monitor`, `record`, `observe`, `log` for monitor; `block`, `blocking`, `protect` for block; in any letter case, with characters up to U+0020 around the word ignored. The daemon reads exactly that set (`Mode::parse` in `daemon/src/control.rs`) and writes the canonical word (`off`, `monitor` or `block`) the next time it writes the file. A value nobody accepts is ignored by the agents, which keep their mode, while the daemon reinitialises the file; the console and `--default-mode` take the same spellings.

## The size limit of the control file

Both agent engines ignore a control file larger than `max_control_bytes` of [`control/limits.properties`](control/limits.properties) (a file of exactly that size is read), which also stops mode changes from reaching them. The daemon therefore refuses to write a larger document, whether the change is a cloud policy or a console update: it keeps the previous document, logs an error that names the size and the limit, and reports the refusal until a write succeeds, as `control_status.write_refused` in `/api/stats`, as the `ohmyrasp_control_write_refused` gauge of `/metrics`, as a line in the local console, and as a `409` answer to `POST /api/control`. The size is measured on the file as found, not on the document the daemon would write from it: a file padded with blanks past the limit is one the agents were ignoring, mode changes included. At start-up the daemon writes such a file again when the document fits, logs a warning that names the size found, the size written and the limit, and says in `control_status.oversized_file_replaced` that the agents apply it from then on. When the document does not fit either, the file is left as it is and reported as a refusal (`change` is `existing`) whose `agents_apply_state` is false: the agents ignore the file and keep the mode they had, so they are not applying the daemon's in-memory state. A refused policy or console change has `agents_apply_state` true, because the file the agents read still holds the daemon's document. A refused cloud policy is identified by its assignment (the policy id and version the cloud reports, else a hash of the policy text), not by the size of the document, and logged once per assignment however often the heartbeat pulls it again. The policy version the daemon reports upstream (in the status and in each uploaded event) is the one installed in the control file, never the refused assignment: the upload schema has no way to say "assigned, but refused", so the refusal is visible only locally, in `control_status.write_refused`. The refusal is cleared by the next successful write, and when the cloud's policy becomes the installed one again (or is withdrawn while none is installed).

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

- The start lines of `agent-java8` and of `agent-java11` and `agent-java17` list their hooks in different orders, and the latter two carry a `startup_probe` member. The daemon reads none of them.
- The backport agents read only `mode` from the control file. The per-algorithm switches, the revision and the policy apply on the primary agent only.
