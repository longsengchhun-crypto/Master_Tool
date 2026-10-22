# The SENTRIX bot service as a container, for a server that is always on.
#   docker build -f deploy/Dockerfile -t sentrix-bot .
# CI builds and publishes it to ghcr.io on every change to the service.

FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY services ./services
# The workspace also lists the desktop app; cargo needs its manifest to load the workspace, not to build the bot.
COPY apps/desktop/src-tauri/Cargo.toml ./apps/desktop/src-tauri/Cargo.toml
RUN mkdir -p apps/desktop/src-tauri/src && echo "fn main() {}" > apps/desktop/src-tauri/src/main.rs && echo "" > apps/desktop/src-tauri/src/lib.rs \
 && cargo build --release --locked -p sentrix-core --bin sentrix-botd

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates clamav-daemon clamav-freshclam tini \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /opt/clamav /data \
 && ln -s /usr/sbin/clamd /opt/clamav/clamd \
 && ln -s /usr/bin/freshclam /opt/clamav/freshclam \
 && useradd --system --home /data --shell /usr/sbin/nologin sentrix \
 && chown sentrix /data
COPY --from=build /src/target/release/sentrix-botd /usr/local/bin/sentrix-botd
USER sentrix
ENV SENTRIX_DATA_DIR=/data \
    SENTRIX_CLAMAV_DIR=/opt/clamav \
    SENTRIX_RELAY_BIND=0.0.0.0:8787 \
    SENTRIX_TRUST_PROXY=1 \
    SENTRIX_BOT_UPDATE_URL=off
VOLUME /data
EXPOSE 8787
# tini passes signals on and cleans up the scan engine process. The container is replaced (not patched) to update.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/sentrix-botd"]
