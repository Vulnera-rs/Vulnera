# syntax=docker/dockerfile:1.4
# Multi-stage build for Vulnera Rust
FROM rust:slim as builder

# Install system build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy workspace metadata and SQLx offline cache
COPY Cargo.toml Cargo.lock ./
COPY .sqlx ./.sqlx

# Copy workspace member manifests only — sources are stubbed below
COPY vulnera-core/Cargo.toml ./vulnera-core/
COPY vulnera-deps/Cargo.toml ./vulnera-deps/
COPY vulnera-orchestrator/Cargo.toml ./vulnera-orchestrator/
COPY vulnera-sast/Cargo.toml ./vulnera-sast/
COPY vulnera-secrets/Cargo.toml ./vulnera-secrets/
COPY vulnera-api/Cargo.toml ./vulnera-api/
COPY vulnera-llm/Cargo.toml ./vulnera-llm/
COPY vulnera-sandbox/Cargo.toml ./vulnera-sandbox/

# Create minimal stub source files so cargo can resolve the workspace and
# compile all third-party dependencies without any real application code.
# This layer is cached and only invalidated when Cargo.toml/Cargo.lock change.
RUN mkdir -p src \
    vulnera-core/src \
    vulnera-deps/src \
    vulnera-orchestrator/src \
    vulnera-sast/src \
    vulnera-secrets/src \
    vulnera-api/src \
    vulnera-llm/src \
    vulnera-sandbox/src && \
    echo "fn main() {}" > src/main.rs && \
    touch vulnera-core/src/lib.rs \
          vulnera-deps/src/lib.rs \
          vulnera-orchestrator/src/lib.rs \
          vulnera-sast/src/lib.rs \
          vulnera-secrets/src/lib.rs \
          vulnera-api/src/lib.rs \
          vulnera-llm/src/lib.rs \
          vulnera-sandbox/src/lib.rs && \
    # Stub [[test]] entry-points declared in member Cargo.tomls so cargo can
    # parse the manifests without probing the real filesystem.
    # vulnera-sast: [[test]] name="datatest_sast_rules" harness=false
    mkdir -p vulnera-sast/tests && \
    echo "fn main() {}" > vulnera-sast/tests/datatest_sast_rules.rs && \
    # vulnera-api: [[test]] name="unit" path="tests/unit/mod.rs"
    mkdir -p vulnera-api/tests/unit && \
    touch vulnera-api/tests/unit/mod.rs

# Pre-compile all external dependencies using the stub sources.
# The registry and git caches are persisted across builds; the target cache
# holds the compiled dep artifacts that the final build will reuse.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release

# ---------------------------------------------------------------------------
# Copy real application sources, overwriting the stubs.
# ---------------------------------------------------------------------------
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

# Force cargo to recompile all workspace members by bumping the mtime of every
# crate entry-point that was previously compiled from an empty stub.  Without
# this, cargo's fingerprint cache sees identical content hashes for the old
# empty artifacts and skips recompilation even though the real sources now
# contain public modules — causing unresolved import errors in the final build.
RUN touch src/main.rs \
          vulnera-core/src/lib.rs \
          vulnera-deps/src/lib.rs \
          vulnera-orchestrator/src/lib.rs \
          vulnera-sast/src/lib.rs \
          vulnera-secrets/src/lib.rs \
          vulnera-api/src/lib.rs \
          vulnera-llm/src/lib.rs \
          vulnera-sandbox/src/lib.rs

# Install sqlx-cli for runtime migrations (registry cache only, no target mount
# needed — the tool is installed directly to /usr/local).
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install sqlx-cli --no-default-features --features postgres --root /usr/local

# Final application build.  Uses SQLx offline mode so no live database is
# required.  The target cache supplies pre-built dep artifacts; workspace
# members are recompiled from real sources due to the touch step above.
ENV SQLX_OFFLINE=true
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release && \
    mkdir -p /app/bin && \
    cp /app/target/release/vulnera-rust /app/bin/vulnera-rust && \
    cp /usr/local/bin/sqlx /app/bin/sqlx

# ===========================================================================
# Runtime stage — minimal image containing only the compiled binary
# ===========================================================================
FROM debian:sid-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libpq5 \
    pipx \
    python3 \
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

ENV PATH="/usr/local/bin:/usr/bin:/bin"

# ===========================================
# Environment Variables (Defaults)
# ===========================================

# LLM Provider Configuration
ENV VULNERA__LLM__PROVIDER="google_ai"
ENV VULNERA__LLM__DEFAULT_MODEL="gemini-flash-latest"
ENV VULNERA__LLM__TEMPERATURE="0.3"
ENV VULNERA__LLM__MAX_TOKENS="8192"
ENV VULNERA__LLM__TIMEOUT_SECONDS="60"
ENV VULNERA__LLM__ENABLE_STREAMING="true"

# LLM Resilience
ENV VULNERA__LLM__RESILIENCE__ENABLED="true"
ENV VULNERA__LLM__RESILIENCE__MAX_RETRIES="3"
ENV VULNERA__LLM__RESILIENCE__INITIAL_BACKOFF_MS="500"
ENV VULNERA__LLM__RESILIENCE__MAX_BACKOFF_MS="30000"
ENV VULNERA__LLM__RESILIENCE__CIRCUIT_BREAKER_THRESHOLD="5"
ENV VULNERA__LLM__RESILIENCE__CIRCUIT_BREAKER_TIMEOUT_SECS="60"

# LLM Enrichment
ENV VULNERA__LLM__ENRICHMENT__MAX_FINDINGS_TO_ENRICH="10"
ENV VULNERA__LLM__ENRICHMENT__MAX_CONCURRENT_ENRICHMENTS="3"
ENV VULNERA__LLM__ENRICHMENT__INCLUDE_CODE_CONTEXT="true"

# Sandbox Configuration
ENV VULNERA__SANDBOX__ENABLED="true"
ENV VULNERA__SANDBOX__BACKEND="landlock"
ENV VULNERA__SANDBOX__EXECUTION_TIMEOUT_SECS="30"
ENV VULNERA__SANDBOX__MEMORY_LIMIT_MB="256"

# Server Configuration
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
