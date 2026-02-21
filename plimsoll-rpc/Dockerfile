# ============================================================
# Plimsoll RPC Proxy — Multi-stage Docker build
#
# Build:  docker build -t plimsoll-rpc .
# Run:    docker run -p 8545:8545 \
#           -e PLIMSOLL_UPSTREAM_RPC="https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY" \
#           -e PLIMSOLL_FEE_BPS=2 \
#           -e PLIMSOLL_FEE_COLLECTOR="0xYourAddress" \
#           plimsoll-rpc
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
RUN useradd -r -s /bin/false plimsoll
USER plimsoll

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/plimsoll-rpc /app/plimsoll-rpc

# ── Environment defaults ──────────────────────────────────────
ENV PLIMSOLL_HOST=0.0.0.0 \
    PLIMSOLL_PORT=8545 \
    PLIMSOLL_FEE_BPS=2 \
    PLIMSOLL_MAX_LOSS_PCT=20.0 \
    PLIMSOLL_BLOCK_APPROVALS=true \
    PLIMSOLL_FLASHBOTS_ENABLED=false \
    PLIMSOLL_FLASHBOTS_RELAY=https://relay.flashbots.net \
    PLIMSOLL_FORK_BLOCK=0 \
    RUST_LOG=plimsoll_rpc=info,tower_http=debug

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -sf http://localhost:8545/health || exit 1

EXPOSE 8545

ENTRYPOINT ["/app/plimsoll-rpc"]
