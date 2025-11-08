# Changelog

All notable changes to this project will be documented in this file.
The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

## [0.3.0] - 2025-11-08

### Added

- **SAST (Static Application Security Testing) Module:**
  - Multi-language static code analysis support:
    - Python: AST parsing via `tree-sitter-python` crate
    - JavaScript/TypeScript: AST parsing via `tree-sitter-javascript` crate
    - Rust: AST parsing via `syn` crate (proc-macro-based)
  - Configurable rule repository with TOML/JSON file loading
  - Default rule set for common vulnerabilities:
    - SQL injection detection
    - Command injection detection
    - Unsafe deserialization patterns
    - Additional security anti-patterns
  - Pattern-based detection with multiple matcher types:
    - AST node type matching
    - Function call name matching
    - Regular expression pattern matching
  - Automatic confidence scoring based on pattern specificity (High/Medium/Low)
  - Configurable scan depth and exclude patterns
  - Severity classification: Critical, High, Medium, Low, Info
  - File counting and comprehensive logging integration

- **Secrets Detection Module:**
  - Multi-method secret detection:
    - Regex-based pattern matching for known secret formats
    - Entropy-based statistical analysis for high-entropy strings
    - Git history scanning for secrets in commit history
  - Supported secret types:
    - AWS credentials (access keys, secret keys, session tokens)
    - API keys (generic, Stripe, Twilio, and more)
    - OAuth tokens and JWT tokens
    - Database credentials and connection strings
    - Private keys (SSH, RSA, EC, PGP)
    - Cloud provider credentials (Azure, GCP)
    - Version control tokens (GitHub, GitLab)
    - High-entropy strings (Base64, hex)
  - Configurable entropy thresholds:
    - Base64 strings (default: 4.5)
    - Hexadecimal strings (default: 3.0)
  - Optional secret verification service integration
  - Baseline file support for tracking known secrets
  - File size limits and timeout controls
  - Comprehensive exclude patterns for build artifacts and dependencies
  - Git history scanning with configurable depth and date ranges

- **API Security Module:**
  - OpenAPI 3.x specification analysis via `oas3` crate
  - Comprehensive security analyzer suite:
    - Authentication analyzer: Missing/weak authentication, JWT expiration issues
    - Authorization analyzer: Missing authorization checks, RBAC gaps, overly permissive access
    - Input validation analyzer: Missing request validation, SQL injection risks, file upload limits
    - Data exposure analyzer: Sensitive data in URLs/headers, missing encryption, PII handling
    - Security headers analyzer: Missing security headers, insecure CORS configuration
    - Design analyzer: Versioning issues, error handling, information disclosure, pagination
    - OAuth analyzer: Insecure OAuth flows, missing token validation, redirect URI issues
  - Configurable analyzer enablement (selective analysis)
  - Severity overrides for specific vulnerability types
  - Path exclusion support
  - Strict mode for more aggressive security checks

- **Orchestrator Pattern & Module Registry:**
  - Unified analysis architecture with orchestrator pattern
  - Centralized `ModuleRegistry` for managing all analysis modules
  - Standardized `AnalysisModule` trait interface for module implementation
  - Rule-based module selection (`RuleBasedModuleSelector`) based on source type and analysis depth
  - Orchestrator use cases:
    - `CreateAnalysisJobUseCase`: Job creation with automatic module selection
    - `ExecuteAnalysisJobUseCase`: Parallel/sequential module execution
    - `AggregateResultsUseCase`: Unified result aggregation from all modules
  - Project detector (`FileSystemProjectDetector`) for automatic source type detection
  - Analysis depth levels: minimal, standard, full

- **Unified Analysis API:**
  - New endpoint: `POST /api/v1/analyze/job`
    - Accepts source type (git, file_upload, directory, s3_bucket)
    - Accepts source URI (repository URL, file path, etc.)
    - Accepts analysis depth (minimal, standard, full)
    - Automatically selects and executes appropriate modules
    - Returns unified report with findings from all executed modules
  - Response includes:
    - Job ID for tracking
    - Execution status
    - Aggregated summary across all modules
    - Findings array with module type tagging

- **Module-Specific Configuration:**
  - SAST configuration section:
    - `VULNERA__SAST__MAX_SCAN_DEPTH`: Maximum directory depth (default: 10)
    - `VULNERA__SAST__EXCLUDE_PATTERNS`: Exclude patterns array
    - `VULNERA__SAST__RULE_FILE_PATH`: Optional custom rule file path
    - `VULNERA__SAST__ENABLE_LOGGING`: Enable logging (default: true)
  - Secrets detection configuration section:
    - `VULNERA__SECRET_DETECTION__MAX_SCAN_DEPTH`: Maximum directory depth (default: 10)
    - `VULNERA__SECRET_DETECTION__EXCLUDE_PATTERNS`: Exclude patterns array
    - `VULNERA__SECRET_DETECTION__BASE64_ENTROPY_THRESHOLD`: Base64 entropy threshold (default: 4.5)
    - `VULNERA__SECRET_DETECTION__HEX_ENTROPY_THRESHOLD`: Hex entropy threshold (default: 3.0)
    - `VULNERA__SECRET_DETECTION__ENABLE_ENTROPY_DETECTION`: Enable entropy detection (default: true)
    - `VULNERA__SECRET_DETECTION__MAX_FILE_SIZE_BYTES`: Maximum file size (default: 10MB)
    - `VULNERA__SECRET_DETECTION__ENABLE_VERIFICATION`: Enable verification (default: false)
    - `VULNERA__SECRET_DETECTION__SCAN_GIT_HISTORY`: Scan git history (default: false)
    - `VULNERA__SECRET_DETECTION__MAX_COMMITS_TO_SCAN`: Maximum commits to scan (null = unlimited)
  - API security configuration section:
    - `VULNERA__API_SECURITY__ENABLED_ANALYZERS`: List of enabled analyzers (empty = all)
    - `VULNERA__API_SECURITY__STRICT_MODE`: Strict mode flag (default: false)
    - `VULNERA__API_SECURITY__EXCLUDE_PATHS`: Path exclusion list
    - `VULNERA__API_SECURITY__SEVERITY_OVERRIDES`: Severity override map

### Changed

- **Architecture Evolution:**
  - Migrated from single-purpose dependency analysis to modular architecture
  - Introduced orchestrator pattern for unified multi-module analysis
  - Module registry enables extensible analysis capabilities
  - Standardized module interface allows for easy addition of new analysis types
  - Analysis results now include module type metadata for proper categorization

- **Multi-Level Caching:**
  - Enhanced caching system with L1 (in-memory) and L2 (filesystem) layers
  - L1 cache uses Moka with configurable size and TTL
  - L2 cache maintains filesystem-based storage with optional compression
  - Cache key standardization across all modules

### Configuration

New environment variables for module configuration:

```bash
# SAST Module
VULNERA__SAST__MAX_SCAN_DEPTH=10
VULNERA__SAST__EXCLUDE_PATTERNS='["node_modules", ".git", "target"]'
VULNERA__SAST__RULE_FILE_PATH=/path/to/rules.toml
VULNERA__SAST__ENABLE_LOGGING=true

# Secrets Detection Module
VULNERA__SECRET_DETECTION__MAX_SCAN_DEPTH=10
VULNERA__SECRET_DETECTION__BASE64_ENTROPY_THRESHOLD=4.5
VULNERA__SECRET_DETECTION__HEX_ENTROPY_THRESHOLD=3.0
VULNERA__SECRET_DETECTION__ENABLE_ENTROPY_DETECTION=true
VULNERA__SECRET_DETECTION__MAX_FILE_SIZE_BYTES=10485760
VULNERA__SECRET_DETECTION__SCAN_GIT_HISTORY=false

# API Security Module
VULNERA__API_SECURITY__ENABLED_ANALYZERS='[]'
VULNERA__API_SECURITY__STRICT_MODE=false
VULNERA__API_SECURITY__EXCLUDE_PATHS='[]'
```

### Technical Details

- **SAST Implementation:**
  - Tree-sitter parsers for Python and JavaScript provide robust AST parsing
  - Syn crate enables proc-macro-based Rust AST analysis
  - Rule repository supports both TOML and JSON formats
  - Confidence calculation based on pattern specificity and context

- **Secrets Detection Implementation:**
  - Regex detector with comprehensive pattern library
  - Entropy detector using Shannon entropy calculation
  - Git history scanning via `git2` crate
  - Verification service integration for secret validation

- **API Security Implementation:**
  - OpenAPI 3.x parsing via `oas3` crate
  - Analyzer pattern enables modular security checks
  - Configurable analyzer enablement for performance optimization

- **Orchestrator Implementation:**
  - Domain-driven design with clear separation of concerns
  - Module registry pattern for extensibility
  - Rule-based selection for intelligent module execution
  - Parallel module execution where applicable

### Breaking Changes

- None. All changes are additive. Existing dependency analysis endpoints remain unchanged.

---

## [0.2.0] - 2025-11-03

### Added

- **Complete Authentication & Authorization System:**
  - User registration endpoint: `POST /api/v1/auth/register`
    - Email validation with uniqueness checks
    - Password strength validation (minimum 8 characters)
    - Automatic token generation after signup
    - Support for optional role assignment (defaults to "user")
  - User login endpoint: `POST /api/v1/auth/login`
    - Email/password authentication
    - Returns JWT access and refresh tokens
  - Token refresh endpoint: `POST /api/v1/auth/refresh`
    - Extends sessions without re-authentication
  - API key management:
    - Create API keys: `POST /api/v1/auth/api-keys`
    - List user's API keys: `GET /api/v1/auth/api-keys`
    - Revoke API keys: `DELETE /api/v1/auth/api-keys/{id}`
  - PostgreSQL-backed persistence:
    - User table with bcrypt password hashing
    - API key table with secure hash storage
    - Database migrations included (`migrations/`)
  - JWT-based authentication:
    - Configurable token TTL (default: 24 hours for access, 30 days for refresh)
    - HMAC-SHA256 signing with configurable secret
    - Role-based access control support
  - Dual authentication methods:
    - Bearer token authentication: `Authorization: Bearer <token>`
    - API key authentication: `Authorization: ApiKey <key>` or `X-API-Key: <key>`
  - Axum extractors for protected routes:
    - `AuthUser` - JWT token validation
    - `ApiKeyAuth` - API key validation
    - `Auth` - Accepts either JWT or API key
  - Security features:
    - API keys shown only once at creation
    - Masked key display in list endpoints
    - Secure password hashing with bcrypt
    - Configurable key expiration

- **Authentication Use Cases:**
  - `RegisterUserUseCase` - New user registration with validation
  - `LoginUseCase` - Email/password authentication
  - `ValidateTokenUseCase` - JWT token verification
  - `RefreshTokenUseCase` - Token renewal
  - `GenerateApiKeyUseCase` - API key creation
  - `ValidateApiKeyUseCase` - API key verification
  - `ListApiKeysUseCase` - User's API key management
  - `RevokeApiKeyUseCase` - API key revocation

- **Domain Models:**
  - `User` entity with email, password hash, and roles
  - `ApiKey` entity with hash, name, expiration, and usage tracking
  - Value objects: `UserId`, `ApiKeyId`, `Email`, `UserRole`, `ApiKeyHash`
  - Authentication error types with proper categorization

- **Infrastructure:**
  - `SqlxUserRepository` - PostgreSQL user persistence
  - `SqlxApiKeyRepository` - PostgreSQL API key persistence
  - `JwtService` - Token generation and validation
  - `PasswordHasher` - Bcrypt password hashing
  - `ApiKeyGenerator` - Secure API key generation with masking

- **Documentation:**
  - Complete API testing guide: `docs/API_TESTING.md`
  - Database setup guide: `docs/SQLX_SETUP.md`
  - Quick start guide: `QUICK_START.md`
  - Automated setup scripts:
    - `scripts/prepare-sqlx-docker.sh` - Docker-based setup
    - `scripts/prepare-sqlx.sh` - Local PostgreSQL setup

### Changed

- **OpenAPI/Swagger Documentation:**
  - Added all authentication endpoints to schema
  - Added authentication models: `LoginRequest`, `RegisterRequest`, `TokenResponse`, etc.
  - Added `UserRole` enum to OpenAPI components
  - All endpoints now visible in Swagger UI at `/docs`

- **CORS Configuration:**
  - Fixed CORS to properly support Swagger UI
  - Changed from `allow_origin(Any)` to `mirror_request()` for wildcard support
  - Properly echoes `Access-Control-Allow-Origin` header in responses
  - Production-ready configuration for specific origins
  - Configurable via `allowed_origins` in server config

- **Application State:**
  - Extended `AppState` with authentication components:
    - Database pool, user/API key repositories
    - JWT service, password hasher, API key generator
    - All authentication use cases

- **Rust Compatibility:**
  - Removed `async_trait` macro usage (axum 0.8+ uses native async traits)
  - Fixed deprecated `rand::thread_rng()` → `rand::rng()`
  - Updated to use native Rust async function in traits (AFIT)

### Fixed

- CORS headers now properly added for cross-origin requests
- Swagger UI can successfully make API calls
- SQLx compile-time query verification with offline mode support
- Proper error responses for authentication failures
- Security: API keys never stored in plaintext, only hashed

### Configuration

New environment variables:

```bash
# Required for runtime
DATABASE_URL='postgresql://user:password@localhost:5432/vulnera'

# Authentication (required for production)
VULNERA__AUTH__JWT_SECRET='your-secret-key-minimum-32-characters'
VULNERA__AUTH__TOKEN_TTL_HOURS=24
VULNERA__AUTH__REFRESH_TOKEN_TTL_HOURS=720  # 30 days
VULNERA__AUTH__API_KEY_LENGTH=32
VULNERA__AUTH__API_KEY_TTL_DAYS=365

# CORS (production)
VULNERA__SERVER__ALLOWED_ORIGINS='["https://your-frontend.com"]'
```

### Database Setup Required

```bash
# Quick setup with Docker
./scripts/prepare-sqlx-docker.sh

# Or with local PostgreSQL
export DATABASE_URL='postgresql://user:password@localhost:5432/vulnera'
sqlx migrate run --source migrations
```

### API Examples

**Register:**

```bash
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"SecurePass123"}'
```

**Login:**

```bash
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"SecurePass123"}'
```

**Use Token:**

```bash
curl -X GET http://localhost:3000/api/v1/analyze \
  -H "Authorization: Bearer <access_token>"
```

**Use API Key:**

```bash
curl -X GET http://localhost:3000/api/v1/analyze \
  -H "X-API-Key: vuln_abc123..."
```

### Breaking Changes

- **DATABASE_URL environment variable is now required** for application startup
- Server will exit with clear error message if DATABASE_URL is not set
- Migrations must be run before starting the application

### Security Notes

- Passwords hashed with bcrypt (cost factor 12)
- API keys hashed before storage (never retrievable after creation)
- JWT tokens signed with HMAC-SHA256
- Configurable token expiration
- API keys can be revoked at any time
- Production deployments should:
  - Use strong JWT secrets (min 32 characters)
  - Configure specific CORS origins
  - Enable HTTPS
  - Set appropriate token TTLs

---

## [0.1.1]

### Added

- Token sharing optimization between GitHub and GHSA clients:
  - New configuration option `reuse_ghsa_token` in `GitHubConfig` (default: `true`)
  - When enabled, the GitHub token is automatically shared with the GHSA client
  - Eliminates the need for separate GHSA token configuration in most cases
  - Graceful fallback to GHSA-specific token if GitHub token is unavailable
  - Benefits: Simplified configuration, reduced token management overhead, improved security

### Changed

- **Architectural improvements - converted workarounds to proper implementations:**
  - Error sanitization middleware now passes configuration through `AppState` instead of reading environment variables directly
  - GitHub repository client initialization now properly handles `None` cases instead of creating fallback clients
  - `AppState` now includes `config` field for proper configuration access throughout the application
  - Removed all temporary workarounds and converted them to production-ready architectural patterns

- **Legacy code removal:**
  - Removed legacy Gradle parser from production code (only Pest-based parser remains)
  - Legacy parser kept in tests only for backward compatibility verification
  - Removed "skeleton", "stub", and "initial scaffold" comments from production code
  - Cleaned up all `#[allow(dead_code)]` annotations with proper documentation

- **Performance optimizations:**
  - `ParserFactory` now uses `HashMap` for O(1) parser lookup instead of linear scan
  - Cache key generation optimized with pre-allocated capacity to reduce reallocations
  - NVD client query optimization: early return for empty CVE lists and pre-allocated vectors
  - Parallelized popular package vulnerability queries using `tokio::task::JoinSet` with bounded concurrency (10 concurrent queries)

- **Code quality improvements:**
  - Fixed all clippy warnings across the codebase
  - Improved error handling: `GhsaClient::new` now returns `Result` instead of panicking
  - Enhanced error logging with proper optional value handling
  - Removed redundant error conversions and closures
  - Improved type safety and removed unnecessary type conversions

### Documentation

- README.md: Added comprehensive "Token Sharing Optimization" section explaining the feature, configuration, and benefits
- CHANGELOG.md: Documented all architectural improvements, legacy code removal, performance optimizations, and code quality improvements
- Configuration examples updated to include token sharing environment variables

## [0.1.0]

### Added

- Configurable concurrent package processing:
  - New configuration option `VULNERA__ANALYSIS__MAX_CONCURRENT_PACKAGES` (default: `3`)
  - Allows tuning the number of packages processed simultaneously during vulnerability analysis
  - Improves performance for dependency files with multiple packages (~3x faster analysis)
  - Configurable via environment variables and TOML configuration files
- Safe version recommendations integrated across the API:
  - Analyze endpoint now returns `version_recommendations` per vulnerable dependency.
  - Repository analysis endpoint now returns `version_recommendations` for unique vulnerable packages across manifests.
- Version resolution algorithm and features:
  - Recommends both:
    - `nearest_safe_above_current` (the minimal safe version ≥ current)
    - `most_up_to_date_safe` (newest safe version available)
  - Adds `next_safe_minor_within_current_major` hint (next safe version within current major).
  - Upgrade impact classification for each recommendation:
    - `nearest_impact` and `most_up_to_date_impact` — values: `major`/`minor`/`patch`/`unknown`.
  - Prerelease exclusion switch via env:
    - `VULNERA__RECOMMENDATIONS__EXCLUDE_PRERELEASES` (default: `false`).
  - Cap the number of version queries per request:
    - `VULNERA__RECOMMENDATIONS__MAX_VERSION_QUERIES_PER_REQUEST` (default: `50`).
- Registry coverage extended and wired into the multiplexer:
  - Packagist (Composer): `https://repo.packagist.org/packages/{name}.json`
  - Go proxy: `https://proxy.golang.org/{module}/@v/list`
  - Maven Central: `https://repo1.maven.org/maven2/{groupPath}/{artifact}/maven-metadata.xml`
- Caching for registry version listings:
  - Cached via filesystem cache with TTL from `VULNERA__CACHE__TTL_HOURS` (default: 24).
  - Cache keys follow standard helpers to ensure consistent naming.
- OpenAPI/Swagger updates:
  - New DTO fields for recommendations and repository response documented and included in components.
- Tests:
  - Version resolution tests for normal flow, fallback flow (registry unavailable), and GHSA fixed events influence.
  - Ecosystem corner cases:
    - NuGet 4-segment version normalization (e.g., `4.2.11.1` → `4.2.11`)
    - PyPI prerelease-only safe versions and behavior under prerelease exclusion flag.

### Changed

- Package processing architecture updated from sequential to concurrent:
  - Default concurrent processing of 3 packages in parallel (configurable)
  - Maintains existing caching behavior and error handling
  - Preserves API rate limiting through bounded concurrency
- API responses now include optional `version_recommendations`:
  - AnalysisResponse: `version_recommendations?: VersionRecommendationDto[]`
  - RepositoryAnalysisResponse: `version_recommendations?: VersionRecommendationDto[]`
- VersionRecommendationDto now includes:
  - `nearest_safe_above_current`, `most_up_to_date_safe`
  - `next_safe_minor_within_current_major`
  - `nearest_impact`, `most_up_to_date_impact`
  - `prerelease_exclusion_applied`, `notes`
- Controllers deduplicate packages prior to computing recommendations to reduce redundant registry calls.
- Registry results add explanatory notes if:
  - Registry returns no versions
  - All available versions are yanked/unlisted
  - The nearest recommendation is a prerelease

### Documentation

- `scripts/.env.example`:
  - Added:
    - `VULNERA__ANALYSIS__MAX_CONCURRENT_PACKAGES=3`
    - `VULNERA__RECOMMENDATIONS__EXCLUDE_PRERELEASES=false`
    - `VULNERA__RECOMMENDATIONS__MAX_VERSION_QUERIES_PER_REQUEST=50`
    - `VULNERA__APIS__GITHUB__REUSE_GHSA_TOKEN=true` (token sharing optimization)

### Fixed

- Reduced duplicate recommendation computations via identifier-level deduplication in controllers.
- Notes emitted when registries provide empty/yanked version lists to improve operator diagnostics.

### Breaking Changes

- None. All changes are additive. Existing API fields are unchanged; new fields are optional.

### Environment Variables (recap)

- Analysis:
  - `VULNERA__ANALYSIS__MAX_CONCURRENT_PACKAGES` (default: `3`)
- Cache:
  - `VULNERA__CACHE__DIRECTORY` (default: `.vulnera_cache`)
  - `VULNERA__CACHE__TTL_HOURS` (default: `24`)
- Recommendations:
  - `VULNERA__RECOMMENDATIONS__EXCLUDE_PRERELEASES` (default: `false`)
  - `VULNERA__RECOMMENDATIONS__MAX_VERSION_QUERIES_PER_REQUEST` (default: `50`)

---
