# Java agent rules

What lives where under `java-agent/`, which command checks a change, and the rules that are easy to break here. Build and packaging details are in [README.md](README.md); the full contributor workflow is in [../CONTRIBUTING.md](../CONTRIBUTING.md#java-agent).

## Layout

| Path | Holds |
|---|---|
| `agent-jdk25/` | The primary agent, for JDK 21 and 25. |
| `agent-java8/`, `agent-java11/`, `agent-java17/` | The backport lines. Three separate source trees, each written for its own JDK. |
| `shared/` | Sources compiled into every line. |
| `backport-tests/` | The unit tests of the three backport lines, written once. |
| `probes/` | Packaged-agent probes, one directory each, and the registry that runs them. |
| `acceptance/` | End-to-end suites: `runtime/` per JDK, `vulhub/<component>/` per Vulhub target. |
| `rules/` | Rule descriptions. The detection coverage doc is generated from them. |
| `scripts/` | Generators and checkers. |

## After a change

```bash
python3 scripts/gates.py run --changed                 # from the repo root: the checks this change triggers
java-agent/scripts/check-agent.sh --line java17 file-read   # one line: unit tests, then one probe on that line's JDK
java-agent/scripts/check-agent.sh --help               # lines and probes
```

`check-agent.sh` takes several lines at once (`--line java8,java11,java17`) and `all` in place of a probe name.

## Rules

**A backport change reaches all three lines.** `agent-java8`, `agent-java11` and `agent-java17` may differ in syntax, never in what they decide. Make the same behaviour change in each line in the same commit, and put its test in `backport-tests/`, where one test runs on all three. A test that only one line can run stays in that line's `src/test` and says why in its first line. `scripts/check-backport-drift.py` compares the three trees after replacing the version token and fails on a difference that [`scripts/backport-drift.java11.diff`](scripts/backport-drift.java11.diff) and [`scripts/backport-drift.java17.diff`](scripts/backport-drift.java17.diff) do not record. Record a difference you mean (newer syntax, a per-release constant) with `--update`, and say why in the commit.

**Backport lines gain no invokedynamic call sites.** Their hooks run inside JDK bootstrap classes, where the first use of a lambda, a method reference, a record's generated `toString`/`equals`/`hashCode` or a pattern `switch` links at run time and can re-enter the hooked call. Write an anonymous or static nested class there. `var`, text blocks, `switch` expressions over strings or enums and `instanceof` patterns compile without such call sites and are fine. `scripts/check-dynamic-calls.py --check` compares the built JARs with [`scripts/dynamic-calls.baseline.json`](scripts/dynamic-calls.baseline.json); `check-agent.sh` runs it for backport lines. Raise the baseline only for code that never runs inside a hook, and say why in the commit.

**`shared/` stays Java 8 source.** The Java 8 line compiles it with `--release 8`.

**Probes are registered by directory.** A new probe is a directory under `probes/` with a `check.py`, plus a `probe.toml` when it needs staged fixtures or applies to some lines only (give the reason). Do not name a probe in a workflow or script: both call `probes/run.py`.

**Acceptance scripts are found by path.** A new one goes in `acceptance/vulhub/<component>/<scenario>-<jdk>.sh` or `acceptance/runtime/`. A script anywhere else is not counted by the coverage tooling.

**A hook aimed at a library is recorded against real versions.** A hook that matches a third-party class and method stops applying, silently, when a release renames them. Adding or changing one means adding the library and its versions to [`probes/hook-targets/libraries.toml`](probes/hook-targets/libraries.toml) (the oldest still common, one where the API changed, the newest, and one line saying why), running `java-agent/scripts/check-agent.sh --line jdk25 hook-targets --update` and, for a backport hook, `--line java8,java11,java17 hook-targets --update`, and reviewing the diff of `probes/hook-targets/recorded/` and then `python3 java-agent/scripts/gen-hook-targets.py`. A library version with no hooked method needs a `none` entry with its reason in `libraries.toml` (a reason that starts with FINDING marks a hook to fix, not to accept); a hook family that hooks no library (it targets the JDK, or an application class) is listed in `probes/hook-targets/allowlist.toml`, which the probe keeps minimal. [`docs/HOOK-TARGETS.md`](docs/HOOK-TARGETS.md) is generated from the recorded maps.

**A primary-agent rule lives in its family's detector class.** Hooks in `agent-jdk25` call the class in `agent-jdk25/src/main/java/io/ohmyrasp/agent/detect/` that owns the decision, and its tests are in `<Detector>Test` beside the other detector tests; [docs/detection.md](../docs/detection.md#primary-agent-detector-layout) maps each kind of evidence to its class. `DetectorEngine` holds only the HTTP request chain, whose first-match order `DetectorEngineDispatchTest` pins. Put a helper that a second family needs in a shared utility of the package (`DetectorStrings`, `FilePaths`, `RequestDecoding`, `RequestValues`, `RequestJson`), not in one of the families. To check one family, run `java-agent/scripts/check-agent.sh --tests '*FileAccessDetectorTest'`, with that family's test class in place of `FileAccessDetectorTest`.

**A new rule id needs a description.** Add it to `rules/general.json` or `rules/product.json`, then regenerate the docs as [../AGENTS.md](../AGENTS.md) describes.
