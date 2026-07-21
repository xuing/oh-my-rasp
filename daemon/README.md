# OhMyRASP Host Daemon

A small, self-contained Rust daemon that runs alongside the OhMyRASP Java agent
on a host and takes over **everything that is not detection**:

- **Ingests** the agent's security events by tailing its NDJSON spool file.
- **Forwards** detections to the cloud control plane — owning the registration
  handshake, heartbeats, and event enrichment the agent used to do itself.
- **Buffers offline**: when the cloud is down or disabled, events accumulate in a
  durable on-disk outbox and replay on reconnect (realtime *and* offline modes).
- **Serves a local console** (single HTML page) showing the raw attack log, the
  per-algorithm switches, the detection mode, and the **business-latency impact**.
- **Controls the agent** by writing a control file the agent polls — the one
  mechanism that works both for the daemon console and for hand-editing in a
  fully standalone deployment.

The agent talks **only** to the daemon (through two files: events out, control
in). The daemon is the only process that talks to the cloud. The agent never
blocks on the daemon — if the daemon is absent, the agent keeps protecting the
app and simply writes its local log.

```
 Java agent                         Host daemon (this crate)              Cloud
 ──────────                         ────────────────────────              ─────
 hook → detect ─┐  events.jsonl   ┌─ tail ─▶ store ─▶ console (HTTP) :7070
                ├───(append)─────▶┤                   ▲
 control poll ◀─┘  control.json   └─ enrich ─▶ uploader ─(retry/outbox)─▶ /api/v1
        ▲                ▲                                                  events
        └── writes ──────┘  (mode + algorithm toggles)
```

## Build

Requires Rust 1.97.1 or newer (edition 2024); the exact CI toolchain is pinned
in `rust-toolchain.toml` and updated automatically.

```bash
cargo build --release      # -> target/release/ohmyrasp-daemon
cargo test                 # unit + tailer integration tests
cargo clippy --all-targets # lint clean
```

## Run

Standalone (no cloud), tailing the agent's default spool and serving the console
on `127.0.0.1:7070`:

```bash
ohmyrasp-daemon
# open http://127.0.0.1:7070
```

With the cloud uplink enabled:

```bash
ohmyrasp-daemon \
  --backend-url http://127.0.0.1:18090 \
  --console-bind 127.0.0.1:7070
# identity via env:
#   OHMYRASP_APP_ID, OHMYRASP_APP_SECRET, OHMYRASP_ENVIRONMENT_ID
```

Common flags:

| Flag | Purpose |
|------|---------|
| `--config <file>` | TOML config (else `./ohmyrasp-daemon.toml` if present) |
| `--spool <file>` | Agent event spool to tail (default `/tmp/ohmyrasp-events.jsonl`) |
| `--control <file>` | Control file to write (default `/tmp/ohmyrasp-control.json`) |
| `--console-bind <addr>` | Console bind address (default `127.0.0.1:7070`) |
| `--backend-url <url>` | Cloud base URL; implies `--cloud` |
| `--cloud` | Enable the cloud uplink |
| `--from-start` | Replay the whole spool instead of tailing only new events |

See [`ohmyrasp-daemon.example.toml`](./ohmyrasp-daemon.example.toml) for the full
config surface; every key is overridable by `OHMYRASP_*` env vars.

## Container & demo stack

A multi-stage [`Dockerfile`](./Dockerfile) (rust → `debian-slim`, rustls so no
OpenSSL) builds a ~130 MB image:

```bash
docker build -t ohmyrasp/daemon:dev .
```

[`../java-agent/docker-compose.daemon.yml`](../java-agent/docker-compose.daemon.yml)
runs the full local loop — one agent-protected Tomcat plus the daemon, sharing a
single volume for the event spool (agent → daemon) and the control file
(daemon → agent):

```bash
cd ../java-agent
docker compose -f docker-compose.daemon.yml up -d --build
# console: http://localhost:7070 ; protected app: http://localhost:18090
```

From the console you can watch the latency panel fill from live traffic, see
attacks land in the log, and flip Off/Monitor/Block — the protected Tomcat
honors the new mode within its control-file poll interval.

## Console & HTTP API

The console at `/` is a single embedded page (no build step, no CDN — works on an
air-gapped host). It polls these JSON endpoints, which are also usable directly:

| Endpoint | Description |
|----------|-------------|
| `GET /api/stats` | Counters, latency percentiles, cloud status, control state |
| `GET /api/events?limit=&hook=&action=` | Recent events, newest first, **raw line preserved** |
| `GET /api/control` | Current mode + algorithm toggles |
| `POST /api/control` | `{ "mode": "block", "algorithms": { "sqli": false } }` |
| `GET /healthz` | Liveness |

The console shows the in-hook detection latency the agent reports per event
(`latency_us`) as p50/p95/p99/max/avg — the "delay added to business" panel — and
lets an operator flip the detection mode (Off / Monitor / Block) or disable any
algorithm on this host. Both actions are persisted to the control file and picked
up by the agent within its poll interval.

## Contract with the agent

**Events out** — one JSON object per line, the agent's existing `JsonEventLogger`
shape. The daemon tolerates missing fields and keeps the full original object for
display. Recognised keys: `timestamp, hook, algorithm, action, confidence,
message, request{…}, details{…}`, plus optional `kind` (`detection`|`telemetry`)
and `latency_us`.

**Control in** — the control file the daemon writes and the agent polls:

```json
{ "mode": "monitor", "algorithms": { "sql_userinput": false }, "revision": 3, "updated_at": "…" }
```

- `mode`: `off` (detection disabled — lowest overhead), `monitor` (detect + record,
  never block), `block` (detect + record + block active-request attacks).
- `algorithms`: per-algorithm enable flags; an absent algorithm is enabled.
- `revision`: monotonic; lets the agent cheaply detect changes.

## Cloud forwarding & offline buffering

When the uplink is enabled the daemon registers the host, heartbeats on an
interval, and enriches each forwarded detection with the cloud identity
(`application_id`, `agent_id`, `environment_id`, `policy_id`) before `POST`ing to
`/api/v1/events/attack` — exactly the contract the agent used to satisfy directly.
On failure or while disabled, detections are held in a bounded in-memory queue
that is flushed to `buffer/outbox.ndjson` on shutdown and replayed on the next
start, so nothing is silently lost. Pure telemetry (`kind = "telemetry"`) stays
local and only feeds the latency panel.

## Module map

| File | Responsibility |
|------|----------------|
| `config.rs` | Layered config (defaults → TOML → env → CLI) |
| `cli.rs` | Command-line flags |
| `tailer.rs` | Polling spool follower (append/partial-line/rotation safe) |
| `model.rs` | Agent event parsing + cloud enrichment |
| `store.rs` | In-memory ring + counters + latency reservoir |
| `control.rs` | Control state + atomic control-file persistence |
| `cloud.rs` | HTTP client to the Go control plane |
| `uploader.rs` | Identity lifecycle + forwarding + offline outbox |
| `console.rs` + `dashboard.html` | Console router + embedded UI |
