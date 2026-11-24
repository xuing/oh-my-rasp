# ohmyrasp-java8

The `ohmyrasp-java8` package installs the `ohmyrasp-java8` Java upatch: a
standalone, daemonless OhMyRASP runtime self-protection agent targeting
Java 8 JVMs (classfile version `<= 52`).

## Behavior

- **Standalone and daemonless**: Built with `standalone=true`,
  `lock_config=true`, and `control=none`. No control-file poller or
  background event-writer threads are started, and `/tmp/ohmyrasp-control.json`
  is ignored.
- **Blocking enforcement**: Blocks detected exploit attempts (such as
  malicious JNDI lookups, unauthorized sensitive file access, SQL
  injection, and command execution) by throwing `Java8RaspBlockException`.
- **Logging**: Emits structured JSON detection events directly to `stderr`
  (`log=stderr`, `latency_sample=0`) with no `/tmp/ohmyrasp-events.jsonl`
  file output and no `hook_latency` telemetry.

## Deployment and limits

- `shirudo` seals the signed JAR at `/run/shirudo-java/ohmyrasp-java8.jar`
  and appends `-javaagent:/run/shirudo-java/ohmyrasp-java8.jar` to
  `JAVA_TOOL_OPTIONS` in `/run/environment.d/shirudo.conf`.
- Only JVMs started by a systemd user manager after the upatch is loaded
  read `/run/environment.d/shirudo.conf`; system services and containers
  must pass `-javaagent:/run/shirudo-java/ohmyrasp-java8.jar` explicitly.
- Java 8 truncates `JAVA_TOOL_OPTIONS` at 1024 bytes and 64 options without
  raising an error (JDK-8288483); keep other `environment.d` JVM options
  short when running alongside this upatch.
- A Java agent is an application-level mitigation inside the JVM, not a
  kernel security boundary against `root` or the JVM-launching user.
- The signed `.upatch` artifact must stay under shirudo's 16 MiB limit.
