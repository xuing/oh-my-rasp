# ohmyrasp-jdk25

The `ohmyrasp-jdk25` package installs the `ohmyrasp-jdk25` Java upatch: a
standalone, daemonless OhMyRASP runtime self-protection agent targeting
Java 25 JVMs (classfile version `<= 69`).

## Behavior

- **Standalone and daemonless**: Built with `standalone=true`,
  `lock_config=true`, and `control=none`. No control-file poller or
  background event-writer threads are started, and `/tmp/ohmyrasp-control.json`
  is ignored.
- **Blocking enforcement**: Blocks detected exploit attempts (such as
  malicious JNDI lookups, unauthorized sensitive file access, SQL
  injection, and command execution) by throwing `OhMyRaspBlockException`.
- **Logging**: Emits structured JSON detection events directly to `stderr`
  (`log=stderr`, `latency_sample=0`) with no `/tmp/ohmyrasp-events.jsonl`
  file output and no `hook_latency` telemetry.

## Deployment and limits

- `shirudo` seals the signed JAR at `/run/shirudo-java/ohmyrasp-jdk25.jar`
  and appends `-javaagent:/run/shirudo-java/ohmyrasp-jdk25.jar` to
  `JAVA_TOOL_OPTIONS` in `/run/environment.d/shirudo.conf`.
- Only JVMs started by a systemd user manager after the upatch is loaded
  read `/run/environment.d/shirudo.conf`; system services and containers
  must pass `-javaagent:/run/shirudo-java/ohmyrasp-jdk25.jar` explicitly.
- A Java agent is an application-level mitigation inside the JVM, not a
  kernel security boundary against `root` or the JVM-launching user.
- The signed `.upatch` artifact must stay under shirudo's 16 MiB limit.
