# OhMyRASP Host Daemon

`ohmyrasp-daemon` is a Rust daemon that runs on the host alongside the OhMyRASP Java agent and handles everything outside in-JVM detection:

- **Ingests** security and latency events by polling the agent's NDJSON spool file (`JsonEventLogger` output).
- **Forwards** detections to the control plane, owning registration, heartbeats, policy pulls, and cloud event enrichment.
- **Buffers offline**: holds pending detections in a bounded queue and persists them to `outbox.ndjson` on graceful shutdown for replay on restart.
- **Serves a local console** (single embedded HTML page) showing the live attack log, per-algorithm switches, detection mode, and in-hook latency percentiles.
- **Controls the agent** by atomically writing `control.json`, which the agent polls without restarting the JVM.

The agent interacts only with the two local files (`events.jsonl` out, `control.json` in). If the daemon is stopped or absent, the agent continues protecting the JVM and appending to its local log.

```text
 Java agent                         Host daemon (this crate)              Control Plane
 ──────────                         ────────────────────────              ─────────────
 hook -> detect ─┐  events.jsonl  ┌─ tail -> store -> console (HTTP) :7070
                 ├──(append)─────>┤                   ^
 control poll <──┘  control.json  └─ enrich -> uploader (outbox/retry) -> /api/v1
        ^                ^
        └── writes ──────┘  (mode + algorithm toggles + policy)
```

## Pre-built Binary or Build from Source

Pre-built `ohmyrasp-daemon-linux-amd64.tar.gz` binaries are published on [GitHub Releases](https://github.com/xuing/oh-my-rasp/releases) alongside `SHA256SUMS.txt` and GitHub provenance attestations (`gh attestation verify ohmyrasp-daemon-linux-amd64.tar.gz -R xuing/oh-my-rasp`).

Building from source requires the Rust toolchain pinned in [`rust-toolchain.toml`](./rust-toolchain.toml) (edition 2024, rustup installs it automatically):

```bash
cargo build --release --locked   # -> target/release/ohmyrasp-daemon
cargo test --locked              # unit + tailer + console + control + outbox tests
cargo clippy --all-targets       # lint check
```

## Run

Standalone (no control plane), tailing `/tmp/ohmyrasp-events.jsonl` and serving the console on `127.0.0.1:7070`:

```bash
ohmyrasp-daemon
# console available at http://127.0.0.1:7070
```

With the control-plane uplink enabled:

```bash
OHMYRASP_APP_ID=<app-id> \
OHMYRASP_APP_SECRET=<app-secret> \
OHMYRASP_ENVIRONMENT_ID=<env-id> \
ohmyrasp-daemon \
  --backend-url http://127.0.0.1:18090 \
  --console-bind 127.0.0.1:7070
```

## CLI Flags and Configuration

Flags defined in `src/cli.rs`:

| Flag | Default / behavior | Purpose |
|---|---|---|
| `-c, --config <FILE>` | `./ohmyrasp-daemon.toml` if present | Load TOML configuration file |
| `--spool <FILE>` | `/tmp/ohmyrasp-events.jsonl` | Agent NDJSON event spool file to tail |
| `--control <FILE>` | `/tmp/ohmyrasp-control.json` | Control JSON file written for the agent to poll |
| `--default-mode <MODE>` | `monitor` | Initial mode (`off`, `monitor`, or `block`) written when no control file exists yet; an existing control file keeps its mode |
| `--console-bind <ADDR>` | `127.0.0.1:7070` | Local HTTP console socket address |
| `--backend-url <URL>` | `""` | Control-plane base URL; implies `--cloud` |
| `--cloud` | `false` | Enable cloud uplink (requires `app_id`, `app_secret`, `environment_id`) |
| `--from-start` | `false` | Replay existing spool from byte 0 instead of tailing from current EOF |

Configuration precedence (`src/config.rs`): built-in defaults -> TOML file -> environment variables -> CLI flags.

Environment variables read by `Config::apply_env`: `OHMYRASP_DAEMON_LOG`, `OHMYRASP_DAEMON_SPOOL_PATH`, `OHMYRASP_DAEMON_CONTROL_PATH`, `OHMYRASP_DAEMON_DEFAULT_MODE`, `OHMYRASP_DAEMON_CONSOLE_BIND`, `OHMYRASP_DAEMON_CLOUD_ENABLED` (`1`/`true`/`yes`/`on`), `OHMYRASP_BACKEND_URL`, `OHMYRASP_APP_ID`, `OHMYRASP_APP_SECRET`, `OHMYRASP_ENVIRONMENT_ID`, `OHMYRASP_HOSTNAME`, `OHMYRASP_VERSION`.

`ControlConfig::mode` validates `default_mode` at startup (`off`, `monitor`, `block`, or recognized aliases in `Mode::parse`) and exits with an error on invalid values rather than silently falling back to `monitor`. See [`ohmyrasp-daemon.example.toml`](./ohmyrasp-daemon.example.toml) for all TOML sections (`[log]`, `[spool]`, `[control]`, `[console]`, `[cloud]`, `[buffer]`, `[store]`) and their defaults (`buffer.dir = "/tmp/ohmyrasp-daemon"`, `buffer.max_pending = 10000`, `store.capacity = 2000`, `spool.poll_interval_ms = 250`, `control.default_mode = "monitor"`).

## Container and Demo Stack

`Dockerfile` uses a multi-stage Rust slim builder -> Debian slim runtime build (tags in [`Dockerfile`](./Dockerfile)) (`reqwest` with `rustls`, no OpenSSL runtime dependency; `ca-certificates` included for HTTPS uplinks) and exposes port `7070`:

```bash
docker build -t ohmyrasp/daemon:dev .
```

[`../java-agent/docker-compose.daemon.yml`](../java-agent/docker-compose.daemon.yml) starts an agent-protected Tomcat 11 container and the daemon sharing one volume for `events.jsonl` and `control.json`:

```bash
cd ../java-agent
docker compose -f docker-compose.daemon.yml up -d --build --wait
# console: http://localhost:7070 ; protected app: http://localhost:18090
```

The stack runs the daemon with `--default-mode=block`, so a fresh volume starts in blocking mode. The daemon-owned `control.json` overrides the agent's `-Dohmyrasp.block` flag; `down -v` resets a mode changed in the console.

## Console and HTTP API

`GET /` serves the embedded `dashboard.html` page with no external asset or build dependencies. JSON and operational routes in `src/console.rs`:

| Endpoint | Description |
|---|---|
| `GET /` | Embedded single-page local console |
| `GET /healthz` | Returns `ok` |
| `GET /metrics` | Prometheus text exposition (`ohmyrasp_cloud_enabled`, `ohmyrasp_cloud_connected`, `ohmyrasp_cloud_registered`, `ohmyrasp_cloud_policy_version`, `ohmyrasp_control_write_refused`, `ohmyrasp_events_pending`, `ohmyrasp_events_uploaded_total`, `ohmyrasp_events_failed_total`, `ohmyrasp_events_dropped_total`) |
| `GET /api/events?limit=&hook=&action=` | Recent retained detections, newest first (`limit` clamped to `1..2000`, default `200`), preserving raw JSON in `raw` |
| `GET /api/stats` | Event counters (`ignored_kinds` counts lines of an unknown kind), the agent's start line (`agent`), latency percentiles (`p50_us`, `p95_us`, `p99_us`, `max_us`, `avg_us` over up to 2000 samples), cloud status, control state, `control_status` (set when a control write was refused for size), paths, and daemon version |
| `GET /api/control` | Current `ControlState` (`mode`, `algorithms`, `policy`, `revision`, `updated_at`) |
| `POST /api/control` | Update `mode` (`off`, `monitor`, `block`) and/or `algorithms` toggles (`{ "mode": "block", "algorithms": { "sqli": false } }`); `409` when the resulting document would be larger than the agents read |

## Contract with the Agent and File Permissions

Example files for both formats, tested by the agents and by this daemon, are in [`../java-agent/contracts/agent-daemon/`](../java-agent/contracts/agent-daemon/README.md).

**Events out (`events.jsonl`)**: one JSON object per line written by the agent's `JsonEventLogger`. The daemon reads this file without creating or modifying it, tolerates missing fields, and retains the raw JSON object. Recognized keys: `timestamp` (an RFC 3339 string, or epoch milliseconds as the backport agents write it), `kind` (`detection`, `telemetry` or `lifecycle`), `event` (read when there is no `kind`), `hook`, `algorithm`, `action`, `confidence`, `latency_us`, `message`, `request`, `details`. Only a detection is logged, counted and uploaded; how the daemon tells a detection from a start line or an unknown kind is in the [fixtures' README](../java-agent/contracts/agent-daemon/README.md#how-the-daemon-reads-a-line).

**Control in (`control.json`)**: written by `Controller` (`src/control.rs`) and polled by the agent:

```json
{ "mode": "monitor", "algorithms": { "sql_userinput": false }, "revision": 3, "updated_at": "..." }
```

- `mode`: `off` (detection disabled), `monitor` (detect and record without blocking), `block` (detect, record, and block active-request attacks).
- `algorithms`: per-algorithm enable flags; absent entries default to enabled.
- `policy`: optional raw policy JSON pulled from `/api/v1/agents/{id}/policy`.
- `revision`: monotonic counter incremented on state changes.

**Owner-only file permissions (`0600`)**: on Unix, `util::restrict_to_owner` sets mode `0600` on `<control>.json.tmp` before atomic `rename` to the control file path (`src/control.rs`) and on `<buffer.dir>/outbox.ndjson` when persisting pending detections (`src/uploader.rs`). Because both files may live under `/tmp` by default and carry policy documents or raw attack context, setting `0600` prevents other local users from reading them.

## Cloud Forwarding and Durability Trade-offs

When `cloud.usable()` is true (`enabled = true` with non-empty `backend_url`, `app_id`, `app_secret`, and `environment_id`), `Uploader` registers at `POST /api/v1/agents/register`, sends periodic heartbeats to `POST /api/v1/agents/{id}/heartbeat`, pulls assigned policies via `GET /api/v1/agents/{id}/policy`, and uploads enriched detection payloads to `POST /api/v1/events/attack`. Pure telemetry lines (`kind = "telemetry"`) remain local for the latency panel.

Current durability boundaries documented in `src/tailer.rs` and `src/uploader.rs`:

- **Graceful-shutdown outbox**: pending detections are held in a bounded in-memory queue (`buffer.max_pending`, evicting oldest entries and incrementing `dropped_total` when full) and flushed to `<buffer.dir>/outbox.ndjson` on `SIGINT`/`SIGTERM`. A hard crash (`SIGKILL` or power loss) loses events still in memory.
- **Non-persistent spool offset**: `tailer.rs` does not checkpoint its byte offset across restarts; restarting without `--from-start` resumes at current EOF, while `--from-start` replays the spool from byte 0.

## Module Map

| File | Responsibility |
|---|---|
| `src/main.rs` | Runtime wiring, signal handling (`SIGINT`/`SIGTERM`), graceful drain |
| `src/cli.rs` | `clap` CLI flag definitions |
| `src/config.rs` | Layered config (`Default` -> TOML -> env -> CLI) |
| `src/tailer.rs` | Polling NDJSON spool reader (partial-line UTF-8 reassembly, truncation/rotation reset) |
| `src/model.rs` | Agent NDJSON parsing, severity mapping, `/api/v1/events/attack` enrichment |
| `src/store.rs` | Bounded in-memory event ring, counters, and latency percentile reservoir |
| `src/control.rs` | `ControlState` controller and atomic `0600` temp-file + rename persistence |
| `src/cloud.rs` | `reqwest` HTTP client for `/api/v1` registration, heartbeat, policy pull, and attack upload |
| `src/uploader.rs` | Background uploader task, retry loop, policy refresh, and `0600` `outbox.ndjson` persistence |
| `src/console.rs` + `src/dashboard.html` | `axum` router (`/`, `/healthz`, `/metrics`, `/api/*`) and embedded console HTML |
| `src/util.rs` | RFC3339 timestamp helper and Unix `0600` `restrict_to_owner` helper |
