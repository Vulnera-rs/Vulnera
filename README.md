# Vulnera Rust – High-Performance Vulnerability Analysis API

[![CI](https://github.com/k5602/Vulnera/actions/workflows/main-azure-web.yml/badge.svg?branch=main)](https://github.com/k5602/Vulnera/actions/workflows/main-azure-web.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.82%2B-orange.svg)](https://www.rust-lang.org/tools/install)

Vulnera is a fast, scalable, multi-ecosystem vulnerability analysis toolkit and testing platform built in Rust. While it excels at analyzing dependency manifests, Vulnera is intended as a comprehensive vulnerability analysis and testing toolkit—supporting not only dependency scanning, but also future features like codebase auditing, security testing, and integration with CI/CD workflows. It aggregates results from OSV, NVD, and GHSA, and exposes a robust HTTP API with OpenAPI docs. Designed for cloud-native workflows, Vulnera leverages async Rust, domain-driven design, and smart caching for reliability and speed.

---

## 🚀 Key Features

- **Comprehensive Analysis Modules:**
  - **Dependency Analysis:** Multi-ecosystem support (npm, PyPI, Maven/Gradle, Cargo, Go, Packagist, and more)
  - **SAST (Static Application Security Testing):** Static code analysis for Python, JavaScript, and Rust
  - **Secrets Detection:** Regex-based "soon migration to ml" and entropy-based detection of exposed credentials and API keys
  - **API Security:** OpenAPI 3.x specification analysis for security vulnerabilities
- **Aggregated Vulnerability Data:** Combines OSV, NVD, and GitHub Security Advisories
- **Unified Orchestration:** Modular architecture with orchestrator pattern for multi-module analysis
- **Authentication & Authorization:** JWT tokens and API keys with PostgreSQL-backed user management
- **Async & Concurrent:** Built with Tokio for high throughput and bounded concurrency
- **Smart Caching & Recommendations:** Dragonfly DB-based, TTL-configurable cache for reduced API calls; safe version recommendations (nearest and most up-to-date), upgrade impact classification (major/minor/patch), and next safe minor within current major, with a prerelease exclusion toggle
- **Domain-Driven Design:** Clean separation of domain, application, infrastructure, and presentation layers
- **OpenAPI Documentation:** Auto-generated Swagger UI for easy API exploration
- **Secure by Default:** Input validation, rate limiting, secure API handling, bcrypt password hashing
- **Container Ready:** Docker and Kubernetes support for production deployments
- **Developer Friendly:** Comprehensive tooling, linting, and CI/CD integration

---

## ⚡ Quick Start

### Prerequisites

- **Rust 1.82+**
- **PostgreSQL 12+** (or Docker for quick setup)
- **SQLx CLI** (for migrations): `cargo install sqlx-cli --no-default-features --features postgres`

### Installation

#### From Source

```bash
git clone https://github.com/vulnera/vulnera.git
cd vulnera

# Install Rust (stable) if needed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# System deps (Ubuntu/Debian)
sudo apt-get install -y pkg-config libssl-dev

# Setup database
# Local PostgreSQL
export DATABASE_URL='postgresql://user:password@localhost:5432/vulnera'
sqlx migrate run --source migrations

# Build and run
cargo build --release
cargo run
```

#### Using Docker

**Build with BuildKit (recommended for faster builds):**

```bash
# Enable BuildKit for cache mounts (faster builds)
DOCKER_BUILDKIT=1 docker build -t vulnera-rust .

# Or set it permanently
export DOCKER_BUILDKIT=1
docker build -t vulnera-rust .
```

**Run the container:**

```bash
# Basic run
docker run -p 3000:3000 \
  -e DATABASE_URL='postgresql://user:password@host:5432/vulnera' \
  vulnera-rust

# With migrations (if sqlx-cli is installed in image)
docker run -p 3000:3000 \
  -e DATABASE_URL='postgresql://user:password@host:5432/vulnera' \
  -e RUN_MIGRATIONS=true \
  vulnera-rust

# Run migrations separately (recommended for production)
docker run --rm \
  -e DATABASE_URL='postgresql://user:password@host:5432/vulnera' \
  vulnera-rust sqlx migrate run --source /app/migrations
```

**Note:** The Dockerfile includes BuildKit cache mounts for significantly faster rebuilds. Migrations are included in the image but should typically be run as a separate init container or job in production.

---

## 🛠️ Usage

- **API Docs:** [http://localhost:3000/docs](http://localhost:3000/docs)
- **Health Check:** [http://localhost:3000/health](http://localhost:3000/health)

### Example: Analyze a Dependency File

```bash
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"file_content": "django==3.2.0\nrequests>=2.25.0", "ecosystem": "PyPI", "filename": "requirements.txt"}'
```

### Example: Analyze a GitHub Repository

```bash
curl -X POST http://localhost:3000/api/v1/analyze/repository \
  -H "Content-Type: application/json" \
  -d '{"repository_url": "https://github.com/rust-lang/cargo", "ref": "main"}'
```

### Example: Unified Multi-Module Analysis

The orchestrator endpoint (`/api/v1/analyze/job`) enables comprehensive analysis across multiple security modules:

**Analyze a Git Repository (Full Analysis):**

```bash
curl -X POST http://localhost:3000/api/v1/analyze/job \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{
    "source_type": "git",
    "source_uri": "https://github.com/my-org/my-project.git",
    "analysis_depth": "full"
  }'
```

This will automatically execute:

- Dependency Analysis (if dependency files are detected)
- SAST (static code analysis for supported languages)
- Secrets Detection (regex and entropy-based scanning)
- API Security (if OpenAPI specifications are found)

**Analyze a Local Directory (Standard Analysis):**

```bash
curl -X POST http://localhost:3000/api/v1/analyze/job \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{
    "source_type": "directory",
    "source_uri": "/path/to/project",
    "analysis_depth": "standard"
  }'
```

**Analysis Depth Levels:**

- `minimal`: Fast analysis with essential checks only
- `standard`: Balanced analysis with comprehensive checks (default)
- `full`: Deep analysis including optional checks and extended scanning

**Response Format:**
The unified analysis response includes:

- `job_id`: Unique identifier for the analysis job
- `status`: Job execution status
- `summary`: Aggregated summary of findings across all modules
- `findings`: Array of findings from all executed modules, each tagged with module type

---

## 🔍 Analysis Modules

Vulnera provides a modular architecture with specialized analysis modules that can be executed individually or in combination through the unified orchestrator API.

### Dependency Analysis Module

Analyzes dependency manifests across multiple package ecosystems to identify known vulnerabilities.

**Supported Ecosystems:**

- **Python:** `requirements.txt`, `Pipfile`, `pyproject.toml`
- **Node.js:** `package.json`, `package-lock.json`, `yarn.lock`
- **Java:** `pom.xml`, `build.gradle`
- **Rust:** `Cargo.toml`, `Cargo.lock`
- **Go:** `go.mod`, `go.sum`
- **PHP:** `composer.json`, `composer.lock`
- **Ruby:** `Gemfile`, `Gemfile.lock`
- **.NET (NuGet):** `packages.config`, `*.csproj` (PackageReference), `*.props`/`*.targets` (central management)

**Features:**

- Concurrent package processing with configurable parallelism
- Aggregated vulnerability data from OSV, NVD, and GHSA
- Safe version recommendations with upgrade impact classification
- Registry version resolution with caching

### SAST (Static Application Security Testing) Module

Performs static code analysis to detect security vulnerabilities in source code using Abstract Syntax Tree (AST) parsing.

**Supported Languages:**

- **Python:** AST parsing via `tree-sitter-python`
- **JavaScript/TypeScript:** AST parsing via `tree-sitter-javascript`
- **Rust:** AST parsing via `syn` crate (proc-macro-based)

**Capabilities:**

- Configurable rule repository (TOML/JSON file loading)
- Default rule set for common vulnerabilities (SQL injection, command injection, unsafe deserialization, etc.)
- Pattern-based detection with multiple matcher types:
  - AST node type matching
  - Function call name matching
  - Regular expression patterns
- Automatic confidence scoring based on pattern specificity
- Configurable scan depth and exclude patterns

**Rule Configuration:**
Rules can be defined in TOML or JSON format with support for severity levels (Critical, High, Medium, Low, Info) and language-specific patterns.

### Secrets Detection Module

Identifies exposed secrets, credentials, API keys, and other sensitive information in source code and repositories.

**Detection Methods:**

- **Regex-based Detection:** Pattern matching for known secret formats (AWS keys, API keys, tokens, private keys, etc.)
- **Entropy-based Detection:** Statistical analysis of high-entropy strings:
  - Base64 strings (default threshold: 4.5)
  - Hexadecimal strings (default threshold: 3.0)
- **Git History Scanning:** Optional analysis of commit history for secrets (configurable depth and date ranges)

**Supported Secret Types:**

- AWS credentials (access keys, secret keys, session tokens)
- API keys (generic, Stripe, Twilio, etc.)
- OAuth tokens and JWT tokens
- Database credentials and connection strings
- Private keys (SSH, RSA, EC, PGP)
- Cloud provider credentials (Azure, GCP)
- Version control tokens (GitHub, GitLab)
- High-entropy strings (Base64, hex)

**Features:**

- Configurable entropy thresholds
- Optional secret verification service integration
- Baseline file support for tracking known secrets
- File size limits and timeout controls
- Comprehensive exclude patterns for build artifacts and dependencies

### API Security Module

Analyzes OpenAPI 3.x specifications to identify security vulnerabilities in API designs.

**Analysis Categories:**

- **Authentication:** Missing or weak authentication mechanisms, JWT expiration issues
- **Authorization:** Missing authorization checks, overly permissive access, RBAC gaps
- **Input Validation:** Missing request validation, SQL injection risks, file upload size limits
- **Data Exposure:** Sensitive data in URLs/headers, missing encryption, PII handling
- **Security Headers:** Missing security headers, insecure CORS configuration
- **API Design:** Versioning issues, error handling, information disclosure, pagination
- **OAuth/OIDC:** Insecure OAuth flows, missing token validation, redirect URI issues

**Features:**

- OpenAPI 3.x specification parsing via `oas3` crate
- Configurable analyzer enablement (selective analysis)
- Severity overrides for specific vulnerability types
- Path exclusion support
- Strict mode for more aggressive security checks

---

## 🔐 Authentication & Authorization

Vulnera includes a complete authentication system with support for both JWT tokens and API keys.

### Quick Setup

### User Registration

```bash
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123"
  }'
```

Returns access and refresh tokens immediately.

### Login

```bash
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123"
  }'
```

### Authentication Methods

#### Method 1: JWT Bearer Token (Interactive Sessions)

```bash
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"ecosystem": "npm", "content": "express@4.17.1"}'
```

**Best for:**

- Web applications
- Interactive API clients
- Short-lived sessions (default 24 hours)

#### Method 2: API Keys (Service Integration)

First, create an API key:

```bash
curl -X POST http://localhost:3000/api/v1/auth/api-keys \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "CI/CD Integration"}'
```

Then use it:

```bash
# Option A: X-API-Key header
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "X-API-Key: vuln_abc123..." \
  -H "Content-Type: application/json" \
  -d '{"ecosystem": "npm", "content": "express@4.17.1"}'

# Option B: Authorization header
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Authorization: ApiKey vuln_abc123..." \
  -H "Content-Type: application/json" \
  -d '{"ecosystem": "npm", "content": "express@4.17.1"}'
```

**Best for:**

- CI/CD pipelines
- Automated scripts
- Service-to-service communication
- Long-lived integrations

### API Endpoints

| Endpoint                     | Method | Auth          | Description                  |
| ---------------------------- | ------ | ------------- | ---------------------------- |
| `/api/v1/auth/register`      | POST   | None          | Create new user account      |
| `/api/v1/auth/login`         | POST   | None          | Login with email/password    |
| `/api/v1/auth/refresh`       | POST   | None          | Refresh expired access token |
| `/api/v1/auth/api-keys`      | POST   | Bearer        | Create new API key           |
| `/api/v1/auth/api-keys`      | GET    | Bearer/ApiKey | List your API keys           |
| `/api/v1/auth/api-keys/{id}` | DELETE | Bearer        | Revoke an API key            |

### Configuration

```bash
# Required
DATABASE_URL='postgresql://user:password@localhost:5432/vulnera'

# Authentication settings
VULNERA__AUTH__JWT_SECRET='your-secret-minimum-32-characters'
VULNERA__AUTH__TOKEN_TTL_HOURS=24
VULNERA__AUTH__REFRESH_TOKEN_TTL_HOURS=720  # 30 days
VULNERA__AUTH__API_KEY_LENGTH=32
```

### Security Features

- ✅ Bcrypt password hashing (cost factor 12)
- ✅ API keys hashed before storage (never retrievable)
- ✅ JWT tokens with HMAC-SHA256 signing
- ✅ Configurable token expiration
- ✅ API key masking in list operations
- ✅ Role-based access control support

### Documentation

- **Detailed Testing Guide:** [docs/API_TESTING.md](docs/API_TESTING.md)
- **Database Setup:** [docs/SQLX_SETUP.md](docs/SQLX_SETUP.md)
- **Quick Start:** [QUICK_START.md](QUICK_START.md)

---

## 📦 Supported Ecosystems & File Formats

- Example environment overrides:

  ```bash
  VULNERA__SERVER__PORT=8080
  VULNERA__CACHE__TTL_HOURS=24
  VULNERA__ANALYSIS__MAX_CONCURRENT_PACKAGES=3
  VULNERA__RECOMMENDATIONS__EXCLUDE_PRERELEASES=false
  VULNERA__RECOMMENDATIONS__MAX_VERSION_QUERIES_PER_REQUEST=50
  VULNERA__APIS__NVD__API_KEY=your_nvd_api_key
  VULNERA__APIS__GHSA__TOKEN=your_github_token
  VULNERA__APIS__GITHUB__TOKEN=your_github_token
  VULNERA__APIS__GITHUB__REUSE_GHSA_TOKEN=true
  ```

- **Python:** `requirements.txt`, `Pipfile`, `pyproject.toml`
- **Node.js:** `package.json`, `package-lock.json`, `yarn.lock`
- **Java:** `pom.xml`, `build.gradle`
- **Rust:** `Cargo.toml`, `Cargo.lock`
- **Go:** `go.mod`, `go.sum`
- **PHP:** `composer.json`, `composer.lock`
- **Ruby:** `Gemfile`, `Gemfile.lock`
- **.NET (NuGet):** `packages.config`, `*.csproj` (PackageReference), `*.props`/`*.targets` (central management)

---

## ⚙️ Configuration

- Configurable via TOML files in `config/` and environment variables (prefix `VULNERA__`)

- Profiles: `development`, `production` (set via `ENV`)

- Example environment overrides:

  ```bash
  # Server
  VULNERA__SERVER__PORT=8080
  VULNERA__SERVER__ALLOWED_ORIGINS='["*"]'  # Use specific origins in production

  # Database (Required)
  DATABASE_URL='postgresql://user:password@localhost:5432/vulnera'

  # Authentication (Required for production)
  VULNERA__AUTH__JWT_SECRET='your-secret-minimum-32-characters'
  VULNERA__AUTH__TOKEN_TTL_HOURS=24
  VULNERA__AUTH__REFRESH_TOKEN_TTL_HOURS=720
  VULNERA__AUTH__API_KEY_LENGTH=32
  VULNERA__AUTH__API_KEY_TTL_DAYS=365

  # Analysis & Caching
  VULNERA__CACHE__TTL_HOURS=24
  VULNERA__ANALYSIS__MAX_CONCURRENT_PACKAGES=3

  # Recommendations
  VULNERA__RECOMMENDATIONS__EXCLUDE_PRERELEASES=false
  VULNERA__RECOMMENDATIONS__MAX_VERSION_QUERIES_PER_REQUEST=50

  # External APIs
  VULNERA__APIS__NVD__API_KEY=your_nvd_api_key
  VULNERA__APIS__GHSA__TOKEN=your_github_token
  VULNERA__APIS__GITHUB__TOKEN=your_github_token
  VULNERA__APIS__GITHUB__REUSE_GHSA_TOKEN=true

  # SAST Configuration
  VULNERA__SAST__MAX_SCAN_DEPTH=10
  VULNERA__SAST__EXCLUDE_PATTERNS='["node_modules", ".git", "target", "__pycache__"]'
  VULNERA__SAST__RULE_FILE_PATH=/path/to/custom-rules.toml  # Optional
  VULNERA__SAST__ENABLE_LOGGING=true

  # Secrets Detection Configuration
  VULNERA__SECRET_DETECTION__MAX_SCAN_DEPTH=10
  VULNERA__SECRET_DETECTION__EXCLUDE_PATTERNS='["node_modules", ".git", "*.lock"]'
  VULNERA__SECRET_DETECTION__BASE64_ENTROPY_THRESHOLD=4.5
  VULNERA__SECRET_DETECTION__HEX_ENTROPY_THRESHOLD=3.0
  VULNERA__SECRET_DETECTION__ENABLE_ENTROPY_DETECTION=true
  VULNERA__SECRET_DETECTION__MAX_FILE_SIZE_BYTES=10485760  # 10MB
  VULNERA__SECRET_DETECTION__ENABLE_VERIFICATION=false
  VULNERA__SECRET_DETECTION__SCAN_GIT_HISTORY=false
  VULNERA__SECRET_DETECTION__MAX_COMMITS_TO_SCAN=null  # null = unlimited

  # API Security Configuration
  VULNERA__API_SECURITY__ENABLED_ANALYZERS='[]'  # Empty = all enabled
  VULNERA__API_SECURITY__STRICT_MODE=false
  VULNERA__API_SECURITY__EXCLUDE_PATHS='[]'
  ```

### Module-Specific Configuration

**SAST Module:**

- `max_scan_depth`: Maximum directory depth for scanning (default: 10)
- `exclude_patterns`: List of directory/file patterns to exclude
- `rule_file_path`: Optional path to custom rule configuration file (TOML/JSON)
- `enable_logging`: Enable logging for SAST operations (default: true)

**Secrets Detection Module:**

- `max_scan_depth`: Maximum directory depth for scanning (default: 10)
- `exclude_patterns`: List of patterns to exclude from scanning
- `base64_entropy_threshold`: Entropy threshold for Base64 strings (default: 4.5)
- `hex_entropy_threshold`: Entropy threshold for hex strings (default: 3.0)
- `enable_entropy_detection`: Enable entropy-based detection (default: true)
- `max_file_size_bytes`: Maximum file size to scan in bytes (default: 10MB)
- `enable_verification`: Enable secret verification service (default: false)
- `scan_git_history`: Scan git commit history for secrets (default: false)
- `max_commits_to_scan`: Maximum commits to scan (null = unlimited)

**API Security Module:**

- `enabled_analyzers`: List of analyzer names to enable (empty = all enabled)
  - Available analyzers: `authentication`, `authorization`, `input_validation`, `data_exposure`, `design`, `security_headers`, `oauth`
- `strict_mode`: Enable strict mode for more aggressive checks (default: false)
- `exclude_paths`: List of API paths to exclude from analysis
- `severity_overrides`: Map of vulnerability type to severity override

---

## 🏗️ Architecture & Design

Vulnera is built with **Domain-Driven Design (DDD)** and a layered architecture:

- **Domain Layer:** Pure business logic, entities, value objects
- **Application Layer:** Use cases, orchestration, error mapping
- **Infrastructure Layer:** API clients, parsers, caching, repositories
- **Presentation Layer:** HTTP API, DTOs, OpenAPI, middleware

### Modular Architecture & Orchestrator Pattern

Vulnera employs a modular architecture with an orchestrator pattern that enables unified analysis across multiple security analysis modules.

**Module Registry:**

- Centralized registry (`ModuleRegistry`) manages all analysis modules
- Modules implement the `AnalysisModule` trait with standardized interface
- Rule-based module selection (`RuleBasedModuleSelector`) determines which modules to execute based on source type and analysis depth
- Supported module types: Dependency Analysis, SAST, Secrets Detection, API Security

**Orchestrator Flow:**

1. **Job Creation:** `CreateAnalysisJobUseCase` analyzes source type and creates analysis job with appropriate module selection
2. **Module Execution:** `ExecuteAnalysisJobUseCase` executes selected modules in parallel or sequentially based on configuration
3. **Result Aggregation:** `AggregateResultsUseCase` merges findings from all modules into unified report
4. **Response Generation:** Final report includes findings from all executed modules with metadata

**Unified Analysis API:**
The `/api/v1/analyze/job` endpoint accepts:

- Source type (git, file_upload, directory, s3_bucket)
- Source URI (repository URL, file path, etc.)
- Analysis depth (minimal, standard, full)

The orchestrator automatically selects and executes appropriate modules based on the source type and depth configuration.

**Dependency Analysis Flow:**
Dependency file → Parser → Concurrent package processing (default: 3 packages in parallel) → AggregatingVulnerabilityRepository (parallel API calls per package, merge results) → AnalysisReport → Optional reporting/caching.

**Caching:**

Vulnera uses Dragonfly DB as the default cache backend, providing high-performance, Redis-compatible caching:

- **Dragonfly DB Cache:** High-performance, multi-threaded in-memory data store
- Replaces traditional file-based caching for better performance and scalability
- Built-in persistence, replication, and horizontal scaling support
- TTL configurable, optional compression for large entries
- Cache keys follow standardized helpers for consistency

**Dragonfly DB Setup:**

1. **Install Dragonfly DB:**

   ```bash
   # Using Docker (recommended)
   docker run -d --name dragonfly -p 6379:6379 docker.dragonflydb.io/dragonflydb/dragonfly

   # Or using Homebrew (macOS)
   brew tap dragonflydb/dragonfly
   brew install dragonfly
   dragonfly

   # Or download from https://www.dragonflydb.io/download
   ```

2. **Configure Vulnera:**

   ```toml
   [cache]
   dragonfly_url = "redis://127.0.0.1:6379"
   dragonfly_connection_timeout_seconds = 5
   ```

   Or via environment variable:

   ```bash
   export VULNERA__CACHE__DRAGONFLY_URL="redis://127.0.0.1:6379"
   ```

**Note:** Dragonfly DB is the default and only cache backend. The file-based cache system has been replaced. Ensure Dragonfly DB is running before starting Vulnera.

**Error Handling:**
Early mapping to domain/application errors, graceful degradation, and clear API responses. Module execution errors are isolated and reported without affecting other modules.

---

## ⚡ Performance Tuning

Vulnera supports several configuration options to optimize performance for your specific use case:

### Concurrent Package Processing

Control how many packages are analyzed simultaneously:

```bash
# Default: 3 packages processed in parallel
VULNERA__ANALYSIS__MAX_CONCURRENT_PACKAGES=3

# For larger systems with better resources
VULNERA__ANALYSIS__MAX_CONCURRENT_PACKAGES=8

# For systems with API rate limits or resource constraints
VULNERA__ANALYSIS__MAX_CONCURRENT_PACKAGES=1
```

**Performance Impact:**

- **3 packages (default)**: ~3x faster than sequential processing, balanced for API rate limits
- **Higher values**: Better performance for large dependency files, but may hit API rate limits
- **Lower values**: Safer for constrained environments or strict rate limits

### Other Performance Settings

```bash
# Vulnerability data caching (reduces API calls)
VULNERA__CACHE__TTL_HOURS=24

# File fetching concurrency for repository analysis
VULNERA__APIS__GITHUB__MAX_CONCURRENT_FILE_FETCHES=8

# Version query limits for recommendations
VULNERA__RECOMMENDATIONS__MAX_VERSION_QUERIES_PER_REQUEST=50
```

---

## 🧑‍💻 Development & Contribution

- **Dev Setup:**

  ```bash
  make -C scripts/build_workflow install-deps
  pre-commit install
  make dev
  ```

- **Testing:**
  `make test` (unit/integration), `make ci-check` (lint, format, audit)

- **Contribution:**
  Fork, branch, code, test, document, PR. Follow DDD, Rust best practices, and update OpenAPI docs for API changes.

### Testing guidance

- Run all checks locally:
  - `make -C scripts/build_workflow ci-check`
  - or `cargo test`
- Run only parser tests (substring filter):
  - `cargo test parsers`
- Mock HTTP clients:
  - Use the `mockito` crate. Start a mock server, stub endpoints, point the client base URL to the mock, assert responses.

See tests under `src/infrastructure/parsers/` and `tests/` for patterns.

### Contribution docs

Please read `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md` before opening PRs. We welcome issues and feature requests—use the provided templates.

---

- **Production:**
  Harden config, disable docs, restrict CORS, provide API keys.

---

## 🛡️ Security Considerations

- HTTPS for all external API calls
- Input validation and sanitization
- Rate limiting and abuse protection
- Runs as non-root in containers
- Secure API key management

---

## 🐞 Troubleshooting

- **Build errors:** Update Rust, install system dependencies

- **API rate limits:** Provide API keys for OSV/NVD/GHSA
- **Token sharing:** GitHub token automatically shared with GHSA client when enabled (default: enabled)

- **Cache issues:** Check Dragonfly DB connection and adjust TTL

- **Debugging:**

  ```bash
  VULNERA__LOGGING__LEVEL=debug cargo run
  ```

---

## 📜 Changelog

- See CHANGELOG.md for the latest updates, including safe version recommendations, extended registry support (Packagist, Go proxy, Maven Central), upgrade impact metadata, next safe minor hints, prerelease exclusion toggle, and request-level caps on version queries.
- Planned items are tracked in “Roadmap: Next Features” at the end of this file.

---

## 🦀 Why Rust? (vs Python)

- **Performance:** Rust is compiled and memory-safe, enabling much faster analysis and lower latency than Python’s interpreter.
- **Concurrency:** Tokio async runtime allows true parallelism and efficient IO, while Python’s async is limited by the GIL.
- **Reliability:** Rust’s strict type system and error handling prevent many runtime bugs common in Python.
- **Security:** Rust eliminates entire classes of memory safety vulnerabilities (buffer overflows, use-after-free) that can affect Python extensions.
- **Scalability:** Rust’s async and concurrency model scales to thousands of requests with minimal resources.
- **Ecosystem:** Rust’s package ecosystem (crates.io) and tooling (cargo, clippy, rustfmt) support modern development practices.

---

## 🌐 Azure Cloud Architecture

![Azure Architecture](./docs/Azure_Arch.png)

**Summary:**
Vulnera is designed for cloud-native deployment on Microsoft Azure.

- Edge: Azure Front Door for global entry, TLS, and WAF
- Identity: Entra Managed Identities for workload identity (no secrets in code)
- API Gateway: Azure API Management for routing, throttling, policies, and versioning
- Compute: Azure App Service or Azure Container Apps for running the Rust API
- Images: Azure Container Registry (ACR) for container images
- Secrets: Azure Key Vault for API keys and configuration
- Observability: Application Insights + Azure Monitor dashboards and logs
- CI/CD: GitHub Actions builds the app and container, pushes to ACR, and deploys to App Service/Container Apps; APIM can be updated as part of the pipeline

This architecture provides global reach, strong identity and secret management, and first-class observability while keeping operations streamlined.

---

## 👥 Team

- Khaled Mahmoud — Project Manager, Main Developer, Rust Backend Developer
- Abd El-Rahman Mossad — Frontend Developer - Extension , LSP Server Developer and Maintainer
- Amr Medhat — Cloud Engineer
- Gasser Mohammed — Frontend Developer

---

## 📝 License

Affero GPL v3.0 or later — see [LICENSE](./LICENSE).

---

## 🌐 Vulnera Frontend

Looking for the web UI?
Find the official Vulnera Frontend at: [https://github.com/k5602/Vulnera-Frontend](https://github.com/k5602/Vulnera-Frontend)

---

## 🗺️ Roadmap: Next Features

This section outlines concrete, near-term work we plan to deliver across the toolkit, editor integrations, and platform.

### Toolkit expansions

- More scanners and utilities integrated under a single CLI/API:
  - SBOM generation and ingestion (CycloneDX/SPDX), dependency graph, license compliance
  - Container image scanning (e.g., Trivy-like capabilities) and base image advisory mapping
  - IaC scanning: Terraform/Kubernetes manifests with policy violations surfaced
  - SARIF export for CI/CD and code-host integrations
- Policy-as-code: fail-the-build thresholds, rules engine, and optional OPA/Rego integration

### Platform and backend

- Dragonfly DB cache backend with TTLs and compression support
- Resilience: centralized backoff/retry budgets and per-provider rate limiting
- Observability: OpenTelemetry traces/metrics, enriched Application Insights dashboards
- Security: API keys/OAuth, RBAC roles, audit logs, and secret-less auth via Entra Managed Identities on Azure
- Offline/air-gapped mode with mirrored OSV/NVD snapshots and scheduled refresh

If you want a dedicated tracking issue and milestone plan, open an issue and we’ll convert this roadmap into tasks with timelines.

---

## 🔐 Security Policy

- Responsible disclosure: Please use GitHub Security Advisories (Report a vulnerability) for private coordination. Avoid public issues for security reports.
- Secret management: On Azure, prefer Entra Managed Identities and Key Vault; avoid committing secrets or storing long‑lived tokens in plaintext env vars.
- Target response time: within 72 hours.

---

## 🔁 Versioning & Releases

- Semantic Versioning (SemVer): MAJOR.MINOR.PATCH.
- Release notes and changelogs are published in GitHub Releases for this repo.
- Every release is tagged; breaking changes are highlighted in notes.
