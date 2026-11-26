# ohmyrasp

> **Generated** by `deploy/shirudo/gen-readmes.py` from `java-agent/` sources.

OhMyRASP runtime self-protection for every Java on the host. The `ohmyrasp` package installs one Java upatch, `ohmyrasp.jar`, a standalone, daemonless agent that holds all four OhMyRASP agent lines. Each JVM that starts with `-javaagent` on it, Java 8 to Java 25, runs the line that fits its Java version: the Java 8, 11 or 17 line, or the primary line on Java 21 and later. It hooks the JVM's own sinks (process execution, JNDI, deserialization, SQL, file writes, XXE, SSRF, expression engines) and blocks exploit-grade calls inside the JVM, backed by **136** end-to-end Vulhub acceptance scenarios.

## Install and uninstall

```sh
sudo shirudo bpm install <repository>/ohmyrasp
sudo shirudo bpm uninstall ohmyrasp
```

The upatch is also loadable on its own (`shirudo upatch load ohmyrasp.upatch`, `shirudo upatch unload ohmyrasp.unload.upatch`). shirudo seals the JAR at `/run/shirudo-java/ohmyrasp.jar` and adds `-javaagent:/run/shirudo-java/ohmyrasp.jar` to the `JAVA_TOOL_OPTIONS` of the JVMs that systemd user managers start. A JVM that is already running has to restart to pick the change up. System services and containers do not inherit it: pass the same `-javaagent` in their own unit or `JAVA_TOOL_OPTIONS`.

The agent never stops a JVM from starting. A JVM that fits no line (Java 9 or 10) writes one `ohmyrasp-agent-skipped` JSON line to stderr and starts without protection. Another OhMyRASP package on the same host is harmless: one line starts per JVM and the other JAR writes `"reason":"already-active"`.

## Check that it is active

A protected JVM writes one line to its standard error when it starts, before the application runs. The line names the Java line that started. The Java 21 and later line also shows the baked mode, `block` here and `monitor` in a monitor build:

| JVM | First line on stderr |
|---|---|
| Java 8 | `{"event":"ohmyrasp-java8-agent-start","mode":"premain", ...}` |
| Java 11 | `{"event":"ohmyrasp-java11-agent-start","mode":"premain", ...}` |
| Java 17 | `{"event":"ohmyrasp-java17-agent-start","mode":"premain", ...}` |
| Java 21 and 25 | `[OHMYRASP] agent started with ASM transformer, standalone=true, mode=block, args=` |

JVMs that start a Java agent with an appended bootstrap path may also print `OpenJDK 64-Bit Server VM warning: Sharing is only supported for boot loader classes because bootstrap classpath has been appended`. It is the JVM's notice that class-data sharing is limited, not an error.

A JVM that was already running when the package was loaded shows none of this: it has to restart. A JVM whose line is not started says why in one JSON line instead:

- `{"event":"ohmyrasp-agent-skipped","reason":"unsupported-java", ...}`: this JAR holds no line that fits the JVM's Java version (a per-line JAR on a Java it does not cover, or any JAR on Java 9 or 10). This JAR protects nothing; the JVM and the application start.
- `{"event":"ohmyrasp-agent-skipped","reason":"already-active", ...}`: another OhMyRASP JAR started a line first. The JVM is protected.
- `{"event":"ohmyrasp-agent-start-failed", ...}`: the line threw while starting. Protection is inactive or incomplete, and the JVM still starts.

Detections are JSON objects, one per line, on the JVM's standard error (`"event":"ohmyrasp-detection"`, with the hook, the rule in `algorithm`, and `action`: `block` or `monitor`). Nothing is written to a file. Read them where the JVM's stderr goes: `journalctl -u <unit>` for a systemd unit, `docker logs <container>` for a container.

## Monitor and block builds

The mode is baked into the JAR when it is built, and no control file or environment variable changes it at run time. A package built with `build.sh --mode block` (the default) blocks exploit-grade calls; one built with `build.sh --mode monitor` writes the same events with `monitor` as the action and blocks nothing. Start with a monitor build to observe a host, then install the block build.

```sh
./deploy/shirudo/ohmyrasp/build.sh --mode monitor "<version>" --keys-dir "<keys>"
```

## Advisories listed in `fixes`

This package lists these advisories in the `fixes` key of its Beefile. The list means that the agent blocks the tested exploit path of that advisory inside the JVM; it does not patch the vulnerable library. Each advisory is backed by a Vulhub acceptance script that exploits an unprotected container and then sends the same request to a protected one.

| Advisory | Acceptance script (under `java-agent/`) |
|---|---|
| CVE-2021-44228 | `acceptance/vulhub/log4j/solr-java8.sh` |
| CVE-2022-22965 | `acceptance/vulhub/spring/java11.sh` |
| CVE-2022-22963 | `acceptance/vulhub/spring/function-java8.sh` |
| CVE-2022-22947 | `acceptance/vulhub/spring/gateway-java8.sh` |
| CVE-2017-5638 | `acceptance/vulhub/struts2/s2045-java8.sh`, `acceptance/vulhub/struts2/s2046-java8.sh` |
| CVE-2020-17530 | `acceptance/vulhub/struts2/s2061-java8.sh` |
| CVE-2017-18349 | `acceptance/vulhub/fastjson/java8.sh` |
| CVE-2016-4437 | `acceptance/vulhub/shiro/4437-java8.sh` |
| CVE-2020-14882 | `acceptance/vulhub/weblogic/14883-java8.sh` |
| CVE-2017-12615 | `acceptance/vulhub/tomcat/12615-java8.sh` |
| CVE-2019-17558 | `acceptance/vulhub/solr/velocity-java8.sh` |
| CVE-2023-21839 | `acceptance/vulhub/weblogic/21839-java8.sh` |

## Limits

- A Java agent is an application-level mitigation inside the JVM, not a kernel security boundary against `root` or the JVM-launching user.
- OpenJDK 8 reads at most 1024 bytes of `JAVA_TOOL_OPTIONS`; the short package name keeps the option at 41 bytes.
- The signed `.upatch` artifact must stay under shirudo's 16 MiB limit.

## Documentation

- [Shirudo packages: which to install, build, verify](https://github.com/xuing/oh-my-rasp/blob/main/deploy/shirudo/README.md)
- [Which JAR to attach, and what the launcher does](https://github.com/xuing/oh-my-rasp/blob/main/docs/agent.md#which-jar-to-attach)
- [Detection coverage and policies](https://github.com/xuing/oh-my-rasp/blob/main/docs/detection.md)
- [Releases](https://github.com/xuing/oh-my-rasp/releases)
