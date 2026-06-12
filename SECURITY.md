# Security Policy

## Supported versions

Oh-My-RASP is pre-1.0 software. Only the latest commit on `main` and
the most recent tagged release receive security fixes. Older releases do
not receive backported patches.

## Reporting a vulnerability

**Preferred:** Use GitHub's private vulnerability reporting at
<https://github.com/xuing/oh-my-rasp/security/advisories/new>. This
keeps the report confidential and links it to the repository so fixes
can be coordinated without public exposure.

**Alternative:** Email <xuing22@gmail.com> with "SECURITY" in the
subject line. Please use this only if you cannot access GitHub's
advisory workflow.

### What to include

A useful report typically contains:

- A concise description of the vulnerability class and its impact.
- The component(s) affected (e.g., `java-agent`, `api`, `daemon`,
  console).
- Reproduction steps or a minimal proof of concept.
- The environment you tested against (JDK version, agent mode, OS).
- Any mitigating factors you have already identified.

## Response targets

This is a young, community-maintained project. The following are
best-effort targets, not contractual SLAs:

| Milestone | Target |
|---|---|
| Acknowledgement | Within 72 hours of receipt |
| Status update / triage outcome | Within 14 days |

If you have not received an acknowledgement within 72 hours, please
follow up by email in case the report was lost in spam.

## Coordinated disclosure

Please do not publish a proof of concept or technical details publicly
before a fix has shipped. We aim to credit reporters in the release
notes and advisory once the issue is resolved. If you need to disclose
by a specific date, let us know in your initial report so we can work
toward that timeline.

## Scope

### In scope — especially valued

Oh-My-RASP is itself a security product. The following classes of
finding are in scope and highly valued:

- **Detection bypasses** — a payload that reaches a hooked sink while
  the agent is in block mode without being detected or blocked. This is
  the most critical class of finding for a RASP.
- **Control-plane authentication and authorization flaws** — privilege
  escalation, unauthenticated access, or RBAC bypass in the Go API
  server.
- **Agent-induced JVM instability** — crashes, deadlocks, or memory
  corruption introduced by instrumentation in the Java agent
  (`java-agent/`).
- **Daemon privilege or isolation issues** in the Rust host daemon
  (`daemon/`).
- **Console authentication or session issues** in the React management
  console (`console/`).

### Out of scope

- Vulnerabilities in the intentionally-vulnerable playground and testbed
  applications (Tomcat playground apps under `java-agent/`) — these apps
  exist specifically to be attacked as test targets.
- Vulnerabilities in third-party Vulhub containers used for integration
  testing.
- Issues that require physical access to the host machine.
- Denial-of-service attacks that rely solely on resource exhaustion
  without a code-level defect.

## Thank you

Responsible disclosure helps make Oh-My-RASP better for everyone who
relies on it to protect their production JVMs. We appreciate the effort
security researchers put into responsible reporting.
