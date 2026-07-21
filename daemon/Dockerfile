# OhMyRASP host daemon — multi-stage build.
# rustls (no OpenSSL) keeps the runtime image minimal; ca-certificates are
# included only for the cloud HTTPS uplink.
FROM rust:1.97.1-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked && strip target/release/ohmyrasp-daemon || true

FROM debian:13-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/ohmyrasp-daemon /usr/local/bin/ohmyrasp-daemon
# Console default; override the bind with --console-bind.
EXPOSE 7070
ENTRYPOINT ["/usr/local/bin/ohmyrasp-daemon"]
