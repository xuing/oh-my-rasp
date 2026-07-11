# Changelog

All notable changes to OhMyRASP are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- Relocate (shade) the bundled ASM library under `io.ohmyrasp.agent.shaded.asm`
  in the primary `agent-jdk25` JAR so the agent can no longer shadow the
  instrumented application's own ASM on the bootstrap classloader. The Java 8/11/17
  backports already shaded ASM; this brings the primary agent in line.
- Add strict security headers (Content-Security-Policy, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy) to the console's
  nginx configuration.

### Added
- Continuous integration for the Java agent (`java-agent/**`) and the Rust
  daemon (`daemon/**`), which previously ran no automated tests.
- Dependency scanning (Dependabot), CodeQL, `govulncheck`, and `cargo audit`.
- `NOTICE` file recording third-party attribution for the shaded ASM dependency.
- `CODE_OF_CONDUCT.md`.

### Changed
- README: removed a broken model-self-assessment badge and corrected the
  detection description to accurately state that detection is signature-based
  with request-parameter correlation and call-stack analysis layered on top
  (not dataflow taint tracking).

### Fixed
- Console: failed mutations (policy rollout/rollback, user disable, secret
  rotation, cleanup) now surface an error to the operator instead of failing
  silently; a route-level error boundary prevents a single malformed record
  from blanking the entire console.
- Daemon: telemetry temp files (spool, control, outbox) are created with
  owner-only (`0600`) permissions instead of world-readable defaults.

<!--
Release process: when cutting a version, move the Unreleased section to a new
`## [X.Y.Z] - YYYY-MM-DD` heading and start a fresh Unreleased block. See
docs/runbooks/release.md.
-->

## [0.1.0] - 2026-06-01

Initial public preview: Java RASP agent (JDK 8/11/17/25), Rust host daemon,
Go control-plane API (Postgres + ClickHouse + Valkey), React console, and a
Helm chart with Prometheus/Grafana/Alertmanager observability.
