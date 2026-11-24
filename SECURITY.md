# Security Policy

## Supported versions

OhMyRASP is pre-1.0 software. Only the latest commit on `main` and the most recent tagged release receive security fixes. Older releases do not receive backported patches.

## Reporting a vulnerability

**Preferred:** Use GitHub's private vulnerability reporting at <https://github.com/xuing/oh-my-rasp/security/advisories/new>. This keeps the report confidential and links it directly to the repository for coordinated remediation.

**Alternative:** Email <xuing22@gmail.com> with `SECURITY` in the subject line if you cannot access GitHub's advisory workflow.

### What to include

- A concise description of the vulnerability class and its impact.
- Affected component(s) (for example `java-agent`, `deploy/shirudo`, `api`, `daemon`, or `console`).
- Reproduction steps or a minimal proof of concept.
- Tested environment (JDK version, agent mode, OS).
- Any mitigating factors already identified.

## Response targets

This is a community-maintained project. The following are best-effort targets, not contractual SLAs:

| Milestone | Target |
|---|---|
| Acknowledgement | Within 72 hours of receipt |
| Status update / triage outcome | Within 14 days |

If you have not received an acknowledgement within 72 hours, follow up by email in case the report was filtered as spam.

## Coordinated disclosure

Do not publish a proof of concept or technical details publicly before a fix has shipped. Reporters are credited in release notes and advisories upon resolution. If you have a specific disclosure deadline, state it in your initial report.

## Scope

### In scope

- **Detection bypasses:** payloads reaching a hooked sink while the agent is in `block` mode without being detected or blocked.
- **Shirudo upatch packaging and config locking (`deploy/shirudo/`):** bypasses of baked `META-INF/ohmyrasp-shirudo.properties` (`lock_config=true`, `mode=block`), `Beefile` validation issues, or manifest/classpath loading flaws in staged upatch JARs.
- **Control-plane authentication and authorization flaws:** privilege escalation, unauthenticated access, or RBAC bypasses in the Go API server (`api/`).
- **Agent-induced JVM instability:** crashes, deadlocks, or memory corruption introduced by bytecode instrumentation in `java-agent/`.
- **Daemon privilege or isolation issues:** file permission, IPC, or privilege flaws in the Rust host daemon (`daemon/`).
- **Console authentication or session issues:** XSS, CSRF, or session-handling defects in `console/`.

### Out of scope

- Vulnerabilities in the intentionally vulnerable Tomcat playground applications under `java-agent/` (these exist as attack test targets).
- Vulnerabilities inside third-party Vulhub containers used for integration testing.
- Attacks requiring physical access to the host machine, or `root`/JVM-launcher tampering when running a standalone `-javaagent` without kernel enforcement.
- Resource-exhaustion denial-of-service attacks without an underlying code defect.
