# OhMyRasp

OhMyRasp is a Java-native RASP proof of concept for JDK 25. It uses ASM class
transformation in a `-javaagent` to intercept risky runtime behavior, writes
local JSONL security events, and can register with the control plane to send
heartbeats, pull policy metadata, and upload detections through the API.

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

To connect an agent to the control plane, pass arguments to `-javaagent` or set
the equivalent system properties/environment variables:

```bash
-javaagent:/opt/ohmyrasp/ohmyrasp-agent.jar=backend_url=http://127.0.0.1:18090,app_id=app_default,app_secret=<secret>,environment_id=env_default
```

Supported keys are `backend_url`, `app_id`, `app_secret`, `environment_id`,
`hostname`, `runtime`, and `version`. The matching system properties use the
`ohmyrasp.` prefix, such as `ohmyrasp.backend_url`; the matching environment
variables use `OHMYRASP_`, such as `OHMYRASP_BACKEND_URL`.

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
