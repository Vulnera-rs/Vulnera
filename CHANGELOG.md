# Changelog

All notable changes to this project will be documented in this file.
The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

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
