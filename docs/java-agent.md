# OhMyRasp

OhMyRasp is a Java-native RASP proof of concept for JDK 25. It uses ASM class
transformation in a `-javaagent` to intercept risky runtime behavior and emits
JSONL security events.

## Current PoC Coverage

- HTTP request context capture in Tomcat/Jakarta Servlet.
- Command execution through `ProcessBuilder`.
- File read, write, delete, and directory listing through `java.io` and common
  `java.nio.file.Files` entry points.
- Outbound URL, DNS, JNDI, SQL callsite, XXE, and Java deserialization hooks.
- Java detector implementations for the migrated algorithm catalog covered by
  the acceptance suite. See `docs/java-agent-algorithm-coverage.md`.

## Build And Run

The repository intentionally uses dynamic dependency versions such as
`latest.release` and Docker's JDK 25 moving tags to match the project
requirement that packages resolve to the newest available release.

```bash
docker compose up --build
```

The comparative testbed starts two Tomcat containers:

```text
http://localhost:18080/            baseline homepage
http://localhost:18081/            protected homepage
http://localhost:18080/rasp/ui     baseline, no RASP agent
http://localhost:18081/rasp/ui     protected, OhMyRasp blocking mode
```

The `/rasp/ui` page is a comparative runner. Blue baseline controls send
requests to port `18080`; red protected controls and the protected batch action
intentionally send requests to port `18081`.

Protected-agent events are written to:

```text
logs/protected/events.jsonl
```

## Acceptance

Run the end-to-end Docker acceptance script:

```bash
bash scripts/acceptance.sh
```

It builds the agent and playground WAR in a JDK 25 Gradle image, starts Tomcat
once without the agent and once with
`-javaagent:/opt/ohmyrasp/ohmyrasp-agent.jar -Dohmyrasp.block=true`, exercises
the clickable API endpoints, and fails if protected attacks do not redirect to
`/rasp/blocked` or the expected algorithm events are missing from
`logs/protected/events.jsonl`.
