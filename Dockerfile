# syntax=docker/dockerfile:1.4
# Multi-stage build for Vulnera Rust
# For production, consider pinning: rust:1.88-slim or rust:1-slim
FROM rust:slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libsqlite3-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy workspace member manifests first 
COPY vulnera-core/Cargo.toml ./vulnera-core/
COPY vulnera-deps/Cargo.toml ./vulnera-deps/
COPY vulnera-orchestrator/Cargo.toml ./vulnera-orchestrator/
COPY vulnera-sast/Cargo.toml ./vulnera-sast/
COPY vulnera-secrets/Cargo.toml ./vulnera-secrets/
COPY vulnera-api/Cargo.toml ./vulnera-api/

# Create dummy source files to build dependencies only (layer caching optimization)
RUN mkdir -p src vulnera-core/src vulnera-deps/src vulnera-orchestrator/src \
    vulnera-sast/src vulnera-secrets/src vulnera-api/src && \
    echo "fn main() {}" > src/main.rs && \
    echo "" > vulnera-core/src/lib.rs && \
    echo "" > vulnera-deps/src/lib.rs && \
    echo "" > vulnera-orchestrator/src/lib.rs && \
    echo "" > vulnera-sast/src/lib.rs && \
    echo "" > vulnera-secrets/src/lib.rs && \
    echo "" > vulnera-api/src/lib.rs

# Build dependencies only with BuildKit cache mounts for faster builds
# Cache Cargo registry (downloaded crates)
# Cache Cargo git cache (git dependencies)
# Cache target directory (compiled artifacts)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release

# Copy actual source code
COPY src ./src
COPY config ./config
COPY docs ./docs
COPY vulnera-core ./vulnera-core
COPY vulnera-deps ./vulnera-deps
COPY vulnera-orchestrator ./vulnera-orchestrator
COPY vulnera-sast ./vulnera-sast
COPY vulnera-secrets ./vulnera-secrets
COPY vulnera-api ./vulnera-api
COPY migrations ./migrations

# Verify workspace structure and force rebuild of workspace members
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo metadata --format-version 1 > /dev/null && \
    test -f vulnera-core/src/lib.rs && \
    test -f vulnera-api/src/lib.rs && \
    test -d vulnera-core/src/application && \
    rm -rf /app/target/release/deps/libvulnera_* \
    /app/target/release/incremental/vulnera_* 2>/dev/null || true && \
    find vulnera-core/src vulnera-deps/src vulnera-orchestrator/src \
    vulnera-sast/src vulnera-secrets/src vulnera-api/src -type f -name "*.rs" \
    -exec touch {} \; 2>/dev/null || true

# Build workspace members first, then the main binary
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release --package vulnera-core --package vulnera-deps \
    --package vulnera-orchestrator --package vulnera-sast --package vulnera-secrets \
    --package vulnera-api && \
    cargo build --release --package vulnera-rust && \
    mkdir -p /app/bin && \
    cp /app/target/release/vulnera-rust /app/bin/vulnera-rust

# Install sqlx-cli in builder stage for migrations
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install sqlx-cli --no-default-features --features postgres --root /usr/local && \
    mkdir -p /app/bin && \
    cp /usr/local/bin/sqlx /app/bin/sqlx

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -r -s /bin/false vulnera

# Create app directory
WORKDIR /app

# Copy the binary and sqlx-cli from builder stage
COPY --from=builder /app/bin/vulnera-rust /usr/local/bin/vulnera-rust
COPY --from=builder /app/bin/sqlx /usr/local/bin/sqlx

# Copy configuration
COPY --from=builder /app/config ./config

# Copy migrations (for running migrations in-container if needed)
COPY --from=builder /app/migrations ./migrations

# Copy entrypoint script (optional, for running migrations before app starts)
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Create NVD data directory (for SQLite database)
RUN mkdir -p .vulnera_data && chown vulnera:vulnera .vulnera_data

# Switch to app user
USER vulnera

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Use entrypoint script (runs migrations by default, set RUN_MIGRATIONS=false to disable)
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["vulnera-rust"]
