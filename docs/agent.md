# OhMyRasp

OhMyRasp is a Java-native RASP proof of concept for JDK 25. It uses ASM class
transformation in a `-javaagent` to intercept risky runtime behavior, writes
local JSONL security events, and can register with the control plane to send
heartbeats, pull policy metadata, and upload detections through the API.

## Current PoC Coverage

- HTTP request context capture in Tomcat 9 `javax.servlet` and Tomcat 10/11
  `jakarta.servlet` runtimes.
- Command execution through `ProcessBuilder`.
- File read, write, delete, and directory listing through `java.io` and common
  `java.nio.file.Files` entry points.
- Outbound URL, DNS, JNDI, SQL callsite, XXE, and Java deserialization hooks.
- Java detector implementations for the migrated algorithm catalog covered by
  the acceptance suite. See `docs/development/algorithm-coverage.md`.
- Registry-driven hook modules under `io.ohmyrasp.agent.asm`, so new hook
  families can be added as focused plug-ins without growing the transformer.

## Build And Run

Gradle and library versions are pinned so builds are reviewable and
reproducible. Dependabot proposes updates, while the CI runtime matrix pulls the
latest Temurin release in each supported JDK line (8, 11, 17, 21, and 25).

```bash
docker compose up --build
```

The comparative testbed starts three Tomcat versions. Each version has one
baseline container without the agent and one protected container with the RASP
agent in blocking mode:

```text
http://localhost:18080/rasp/ui     Tomcat 9 baseline, no RASP agent
http://localhost:18081/rasp/ui     Tomcat 9 protected, OhMyRasp blocking mode
http://localhost:18082/rasp/ui     Tomcat 10 baseline, no RASP agent
http://localhost:18083/rasp/ui     Tomcat 10 protected, OhMyRasp blocking mode
http://localhost:18084/rasp/ui     Tomcat 11 baseline, no RASP agent
http://localhost:18085/rasp/ui     Tomcat 11 protected, OhMyRasp blocking mode
```

The `/rasp/ui` page is a comparative runner. It can target any configured
Tomcat baseline/protected environment and can run the full case set against all
baseline or all protected ports.

Protected-agent events are written to:

```text
logs/tomcat9-protected/events.jsonl
logs/tomcat10-protected/events.jsonl
logs/tomcat11-protected/events.jsonl
```

The archived Java cyber range target labs are exposed to the Playground
through `/rasp/labs` and are grouped by underlying mechanics: expression and
template injection, deserialization and gadget loading, XML/SSRF behavior, and
SQL/file-write/webshell behavior. The catalog lives at
`java-agent/playground/src/main/resources/ohmyrasp/labs/archived-java-ranges.json`.

To connect an agent to the control plane, pass arguments to `-javaagent` or set
the equivalent system properties/environment variables:

```bash
-javaagent:/opt/ohmyrasp/ohmyrasp-agent.jar=backend_url=http://127.0.0.1:18090,app_id=app_default,app_secret=<secret>,environment_id=env_default
```

Supported keys are `backend_url`, `app_id`, `app_secret`, `environment_id`,
`hostname`, `runtime`, and `version`. The matching system properties use the
`ohmyrasp.` prefix, such as `ohmyrasp.backend_url`; the matching environment
variables use `OHMYRASP_`, such as `OHMYRASP_BACKEND_URL`.

When running through Docker Compose, protected Tomcat containers pass these
environment variables through to the agent. On Linux, `host.docker.internal` is
mapped to the Docker host, so a local control plane can be reached with:

```bash
OHMYRASP_BACKEND_URL=http://host.docker.internal:18090 \
OHMYRASP_APP_ID=<app-id> \
OHMYRASP_APP_SECRET=<app-secret> \
OHMYRASP_ENVIRONMENT_ID=<environment-id> \
docker compose up -d --build
```

With those values set, the agent registers, sends heartbeats, pulls assigned
policy metadata, and uploads detections to `/api/v1/events/attack`.

## Acceptance

Run the end-to-end Docker acceptance script:

```bash
bash scripts/acceptance.sh
```

It builds the agent, the Jakarta playground WAR, and the generated Javax
playground WAR in a JDK 25 Gradle image. It then starts Tomcat 9, 10, and 11 in
baseline/protected pairs, exercises the clickable API endpoints, and fails if
protected attacks do not redirect to `/rasp/blocked` or the expected algorithm
events are missing from any protected Tomcat event log.
