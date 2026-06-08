# Container image for the open-source content-hashing OTLP forwarder.
#
# Customers run this in their own environment, in front of (or as a
# sidecar to) their OTel Collector. In hash mode, content fields
# (prompts, tool I/O, end-user IDs) are HMAC-SHA-256'd locally with a
# per-tenant salt before forwarding to api.provenex.ai. Provenex
# receives structural lineage metadata + content hashes only.
#
# Build & ship:
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -f deploy/ingest-proxy/Dockerfile \
#     -t ghcr.io/provenex/ingest-proxy:0.1.0 \
#     -t ghcr.io/provenex/ingest-proxy:latest \
#     --push .

FROM rust:1-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN cargo build --release --bin provenex-ingest

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin provenex

COPY --from=builder /build/target/release/provenex-ingest /usr/local/bin/provenex-ingest

USER provenex
WORKDIR /home/provenex

# Standard OTLP/HTTP listener port. Map customer-side as appropriate.
EXPOSE 4318

# Config via env (overridable):
#   PROVENEX_INGEST_BIND   default 0.0.0.0:4318
#   PROVENEX_UPSTREAM      default https://api.provenex.ai
#   PROVENEX_API_KEY       REQUIRED — your trial Bearer token
#   PROVENEX_HMAC_SALT     REQUIRED for PROVENEX_MODE=hash
#   PROVENEX_MODE          plain | hash (default plain)
#
# Or pass equivalent flags as args (CLI > env).
ENTRYPOINT ["/usr/local/bin/provenex-ingest"]
