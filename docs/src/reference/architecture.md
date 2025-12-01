# System Architecture (Advanced Reference)

This section provides technical details about Vulnera's architecture for developers, integrators, and operators who need deeper understanding.

## Overview

Vulnera is a **modular, async Rust platform** using domain-driven design (DDD) principles with a composition root wiring pattern.

```
┌─────────────────────────────────────────────────────────────┐
│                        HTTP Server                           │
│                   (Axum Web Framework)                       │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────┴──────────────────────────────────┐
│                    Orchestrator                              │
│        (Async Job Queue + Module Registry)                   │
├───────────────┬──────────────┬─────────────┬────────────────┤
│               │              │             │                │
▼               ▼              ▼             ▼                ▼
Dependencies  SAST         Secrets        API            LLM
Analysis      Analysis     Detection     Analysis       Explanations
(Node deps)   (AST rules)  (ML models)   (OpenAPI)      (Pangu)
```

## Layered Architecture

Vulnera follows **domain-driven design** with four layers:

### 1. Domain Layer

**Pure types, entities, traits—zero side effects**

- `module.rs` — `AnalysisModule` trait (all modules implement)
- `errors.rs` — Domain error types
- `findings.rs` — Finding entity and value objects
- `config.rs` — Configuration value objects
- `repository.rs` — Repository trait definitions

**Key traits:**

- `AnalysisModule` — All modules (deps, SAST, secrets, API, LLM) implement this
- `IRepository` — Abstract data access
- `ICache` — Cache abstraction (Dragonfly/Redis only)
- `IAuthenticator` — Authentication logic

### 2. Application Layer

**Use cases orchestrating domain logic**

- `create_analysis_job.rs` — Initialize analysis job
- `execute_analysis_job.rs` — Run analysis modules
- `enrich_findings_with_llm.rs` — Add LLM explanations
- Repository implementations for data access

**Key characteristics:**

- Specific use cases (business logic)
- Coordinates between domain and infrastructure
- Returns domain entities (not DTOs)

### 3. Infrastructure Layer

**HTTP clients, database queries, file I/O, parsers**

- `database/` — SQLx compile-time validated SQL queries
- `parsers/` — AST parsing, manifest parsers
- `api_clients/` — NVD, GHSA, GitHub, Pangu LLM clients
- `cache/` — Dragonfly/Redis caching, compression
- `auth/` — JWT and API key handling

**Key characteristics:**

- All external communication
- Wrapped with circuit breakers and retry logic
- Configurable via `Config` struct

### 4. Presentation Layer

**Controllers, routes, DTOs**

- `controllers/` — HTTP handlers
- `models.rs` — Request/response DTOs with OpenAPI annotations
- `routes.rs` — Route registration

## Module System

### The Five Analysis Modules

Each implements `AnalysisModule` trait:

1. **Dependencies** — Package registry lookups (OSV, NVD, GHSA)
2. **SAST** — AST-based code analysis (tree-sitter)
3. **Secrets** — ML pattern + entropy detection
4. **API** — OpenAPI 3.x specification analysis
5. **LLM** — Huawei Pangu API for explanations/fixes

### Module Selection (Rule-Based)

```
Input: /path/to/project
  ├─ package.json found → Run Dependencies
  ├─ .py/.js files found → Run SAST (language-specific)
  ├─ All files scanned → Run Secrets
  ├─ openapi.yaml found → Run API
  └─ All findings → Optionally enrich with LLM
```

## Data Flow: Full Analysis Job

```
HTTP POST /api/v1/analyze/job
  │
  ├─→ [Auth middleware] ← Validate API key or JWT
  │
  ├─→ [Rate limiter] ← Check quota (token-based)
  │
  ├─→ [Create job use case]
  │   ├─ Validate input
  │   ├─ Create Job in database
  │   └─ Push to Dragonfly job queue
  │
  ├─→ [Worker pool] (async, configurable max_job_workers)
  │   ├─ Dequeue job
  │   ├─ Download/access source (git, S3, local)
  │   ├─ Detect project type → Module selector
  │   ├─ Run selected modules in parallel
  │   │   ├─ Dependencies: concurrent registry lookups
  │   │   ├─ SAST: concurrent file analysis
  │   │   ├─ Secrets: concurrent file scanning
  │   │   └─ API: parse OpenAPI spec
  │   ├─ Aggregate findings
  │   └─ Persist to database
  │
  └─→ Return: Job ID + status (or stream if still processing)
```

## Concurrency Model

**Tokio async runtime** with configurable thread pools:

```toml
[analysis]
max_job_workers = 8              # Worker pool size
max_concurrent_packages = 8       # Per-job package lookups
max_concurrent_registry_queries = 10
max_concurrent_api_calls = 12
```

**Concurrency impact:**

- Without concurrency: 50 packages → 50 × 2s = 100 seconds
- With 8 concurrent workers: 50 packages → 6-12 seconds
- With caching: 50 packages (50% cached) → 3-6 seconds

## Cache Architecture

**Two-level caching with Dragonfly/Redis:**

```
L1: In-Memory (100MB, 5-min TTL, optional compression)
      ↓ (miss)
L2: Dragonfly/Redis (24-hour TTL, 10KB compression threshold)
      ↓ (miss)
External: OSV, NVD, GHSA, GitHub, Pangu LLM APIs
```

**Configuration:**

```toml
[cache]
ttl_hours = 24
l1_cache_size_mb = 100
l1_cache_ttl_seconds = 300
enable_cache_compression = true
compression_threshold_bytes = 10240
dragonfly_url = "redis://127.0.0.1:6379"
```

## Rate Limiting & Quota System

**Token-based quota with Dragonfly backend:**

```
GET request:          1 token
POST request:         2 tokens
Analysis operation:   3 tokens
LLM operation:        6 tokens
```

**Tiers:**

- Unauthenticated: 10 tokens/day
- API Key: 40 tokens/day
- Organization: 48 tokens/day (shared)

**Daily reset:** UTC midnight

## Database Schema

**PostgreSQL 12+** with SQLx compile-time validation:

**Key tables:**

- `users` — User accounts, authentication
- `organizations` — Team/organization grouping
- `organization_members` — Role-based membership
- `persisted_job_results` — Analysis findings (JSONB)
- `api_keys` — SHA256-hashed API keys
- `subscription_limits` — Quota tracking

## Authentication & Authorization

### JWT Flow

1. User registers/logs in → JWT issued (httpOnly cookie)
2. Middleware extracts JWT on each request
3. Validates signature + expiry
4. Injects user context into request

### API Key Flow

1. User creates API key → Returns one-time (never shown again)
2. Stored as SHA256 hash in database
3. Each request: Lookup hash, verify, use associated user

### RBAC (Role-Based Access Control)

- **Owner:** Full access, billing, member management
- **Admin:** Create jobs, manage members, view analytics
- **Analyst:** Create jobs, view results, comment
- **Viewer:** View-only access

## Security Model

**Defense in depth:**

1. HTTPS + HSTS
2. CORS (configurable allowed_origins)
3. CSRF tokens (POST/PUT/DELETE)
4. Rate limiting (stricter for auth endpoints)
5. Input validation (SQLx prevents SQL injection)
6. Output encoding (JSON serialization)
7. No secrets in logs (sensitive fields marked)

## Configuration System

**Strongly-typed with environment overrides:**

```
config/default.toml (defaults)
         ↓
Environment variables (override)
         ↓
Config struct (passed to services)

Pattern: VULNERA__SECTION__KEY=value
Example: VULNERA__AUTH__JWT_SECRET=mysecret
```

## Composition Root

**Single entry point: `src/app.rs`**

All services instantiated and wired:

```
1. Load config
2. Connect to external services (DB, cache, APIs)
3. Instantiate analysis modules
4. Register modules in ModuleRegistry
5. Spawn worker pool
6. Return OrchestratorState (passed to handlers)
```

**Key principle:** Never instantiate services inside module internals. Everything flows through OrchestratorState.

## Performance Characteristics

**Analysis speed (typical):**

| Module | Time | Depends On |
|--------|------|-----------|
| Secrets | 100ms/file | File size |
| SAST | 500ms/file | File complexity |
| API | 50ms/spec | Spec size |
| Dependencies | 1-10s/package | Registry latency |
| LLM | 1-5s/request | Pangu API latency |

## Deployment Models

### Docker

```dockerfile
FROM rust:1.82 AS builder
# Build Vulnera binary...

FROM debian:bookworm
COPY --from=builder /vulnera /usr/bin/
EXPOSE 3000
CMD ["vulnera"]
```

### Kubernetes

- Stateless API servers (replicate horizontally)
- Shared PostgreSQL database
- Shared Dragonfly cache
- Shared job queue (Dragonfly)

## Scaling Considerations

**Horizontal:** Add API server instances behind load balancer (all stateless)

**Vertical:** Tune `max_job_workers` and `max_concurrent_*` settings

**Resource limits:**

- Memory: ~500MB base + job-dependent (~100MB per concurrent job)
- CPU: Event-driven, peaks during concurrent analysis
- Disk: Cache compression reduces storage

## For More Information

- [Analysis Capabilities](../analysis/overview.md) — What each module does
- [API Specification](api-spec.md) — Endpoint reference
- [Configuration Guide](../user-guide/configuration.md) — Tuning parameters
