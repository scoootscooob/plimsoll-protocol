# ============================================================
# Aegis RPC Proxy — Multi-stage Docker build
#
# Build:  docker build -t aegis-rpc .
# Run:    docker run -p 8545:8545 \
#           -e AEGIS_UPSTREAM_RPC="https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY" \
#           -e AEGIS_FEE_BPS=2 \
#           -e AEGIS_FEE_COLLECTOR="0xYourAddress" \
#           aegis-rpc
# ============================================================

# ── Stage 1: Build ────────────────────────────────────────────
FROM rust:1.80-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Cache dependencies by copying Cargo files first
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && \
    echo 'fn main() { println!("placeholder"); }' > src/main.rs && \
    cargo build --release 2>/dev/null || true && \
    rm -rf src

# Copy actual source and build
COPY src/ src/
RUN cargo build --release

# ── Stage 2: Runtime ──────────────────────────────────────────
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false aegis
USER aegis

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/aegis-rpc /app/aegis-rpc

# ── Environment defaults ──────────────────────────────────────
ENV AEGIS_HOST=0.0.0.0 \
    AEGIS_PORT=8545 \
    AEGIS_FEE_BPS=2 \
    AEGIS_MAX_LOSS_PCT=20.0 \
    AEGIS_BLOCK_APPROVALS=true \
    AEGIS_FLASHBOTS_ENABLED=false \
    AEGIS_FLASHBOTS_RELAY=https://relay.flashbots.net \
    AEGIS_FORK_BLOCK=0 \
    RUST_LOG=aegis_rpc=info,tower_http=debug

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -sf http://localhost:8545/health || exit 1

EXPOSE 8545

ENTRYPOINT ["/app/aegis-rpc"]
