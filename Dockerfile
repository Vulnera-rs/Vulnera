# syntax=docker/dockerfile:1.4
# Multi-stage build for Vulnera Rust uses cargo-chef.
# ===========================================================================
# Stage 1: Chef
# ===========================================================================
FROM rust:1.92-slim AS chef

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-chef

WORKDIR /app

# ===========================================================================
# Stage 2: Planner - Generate recipe.json from full source
# ===========================================================================
FROM chef AS planner

# Copy full source code
COPY . .

RUN cargo chef prepare --recipe-path recipe.json

# ===========================================================================
# Stage 3: Builder - Build dependencies and application
# ===========================================================================
FROM chef AS builder

# Install tools needed for build scripts (curl for utoipa-swagger-ui download)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy SQLx offline cache for compile-time query validation
COPY .sqlx ./.sqlx

# Copy the recipe from planner stage
COPY --from=planner /app/recipe.json recipe.json

# Build dependencies only - this layer is cached when recipe.json doesn't change
RUN cargo chef cook --release --recipe-path recipe.json

# Install sqlx-cli for runtime migrations
RUN cargo install sqlx-cli --no-default-features --features postgres --root /usr/local

# Copy source files
COPY src ./src
COPY config ./config
COPY vulnera-core ./vulnera-core
COPY vulnera-deps ./vulnera-deps
COPY vulnera-orchestrator ./vulnera-orchestrator
COPY vulnera-sast ./vulnera-sast
COPY vulnera-secrets ./vulnera-secrets
COPY vulnera-api ./vulnera-api
COPY vulnera-llm ./vulnera-llm
COPY vulnera-sandbox ./vulnera-sandbox
COPY migrations ./migrations

# Build the application
ENV SQLX_OFFLINE=true
RUN cargo build --release && \
    mkdir -p /app/bin && \
    cp /app/target/release/vulnera-rust /app/bin/vulnera-rust && \
    cp /usr/local/bin/sqlx /app/bin/sqlx

# ===========================================================================
# Stage 4: Runtime - Minimal production image
# Use debian:testing-slim to match glibc version with builder (rust:1.92-slim)
# ===========================================================================
FROM debian:testing-slim AS runtime

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create application user
RUN groupadd -r vulnera && useradd -r -g vulnera vulnera

WORKDIR /app

# Copy artifacts from builder stage
COPY --from=builder /app/bin/vulnera-rust /usr/local/bin/vulnera-rust
COPY --from=builder /app/bin/sqlx /usr/local/bin/sqlx
COPY --from=builder /app/config ./config
COPY --from=builder /app/migrations ./migrations
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Create data directory and set permissions
RUN mkdir -p .vulnera_data && chown vulnera:vulnera .vulnera_data

# Essential environment variable defaults
ENV PATH="/usr/local/bin:/usr/bin:/bin"
ENV VULNERA__SERVER__ADDRESS="0.0.0.0:3000"

# Switch to non-root user
USER vulnera

# Expose API port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["vulnera-rust"]
