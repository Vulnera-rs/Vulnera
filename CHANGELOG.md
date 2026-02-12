# Changelog

All notable changes to this project will be documented in this file.
The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

## [0.5.1] - 2026-02-13

### Added
- **Dependency Analysis Improvements:**
  - Precise semver interval intersection in `VersionRange::overlaps_with` for better vulnerability matching.
  - Robust glob pattern matching for dependency ignore rules using `globset`.
  - Resolution of dependency edges to actual package versions in npm, Ruby, PHP, Python (uv), and Rust lockfile parsers.
  - Preserved dependency edges for git/path dependencies in Cargo parser for accurate graph analysis.
  - JavaScript framework detection from `package.json` dependencies.
  - Enhanced Gradle version parser to handle ranges, selectors, and property references.
- **OpenAPI Analysis Enhancements:**
  - Component reference resolution (parameter, request body, response, header) in OpenAPI parser.
  - Array item schema support in OpenAPI analyzers with recursive schema walkers.
  - Check for wildcard CORS origins in header schemas within `SecurityHeadersAnalyzer`.
- **Infrastructure & Cache:**
  - Integrated real-time Dragonfly cache metrics (`db_size`, `info_stats`).
  - Ecosystem-targeted cache invalidation using key patterns.
  - Enforced API key TTL > 0 in configuration validation.
- **Sandbox Security:**
  - Strongly-typed sandbox backend (`SandboxBackendPreference`) and failure modes (`best_effort`, `fail_closed`).
  - Strict fail-closed sandbox mode: worker aborts if sandbox setup fails.
  - `SandboxPolicyProfile` for module-specific isolation (read-only, dependency resolution).
- **SAST Refinements:**
  - Granular Rust unsafe rules: split into `unsafe_block`, `rust-unsafe-fn`, and `rust-unsafe-impl`.
  - Improved `SastEngine` robustness by logging metavariable errors and preventing silent failures.
  - Deterministic SARIF snapshots with redacted fingerprints.

### Changed
- **Orchestrator Refactor (Breaking Change):**
  - Refactored `OrchestratorState` to `OrchestratorServices` for clearer composition-root wiring.
  - Grouped sub-services (auth, llm, dependencies, etc.) for better modularity.
- **Sandbox Defaults:** Updated default sandbox backend to `landlock`.
- **CI Guardrails:**
  - Added SQLx query safety audit script and GitHub Action to block non-macro `query()` forms.
  - Added Rust guardrails workflow to fail on `panic!`, `unwrap()`, or `expect()` in production crates.
- **API Consistency:**
  - Replaced multiple primitive parameters with `FindingsSummary` in analytics events.
  - Introduced `AnalyzerFn` and `CallUpdate` type aliases for consistent signatures.
  - Renamed LLM helper functions and registry parser methods for consistency.
- **Refactored Analyzers:**
  - Simplified `InputValidationAnalyzer` logic to reduce nesting.
  - Improved data-flow taint checks using `is_none_or`.
  - Replaced `.map/.any` patterns with `.contains/.iter` where clearer.

### Fixed
- **Robustness:** Added resilient regex compilation in API analyzers with graceful error handling.
- **Error Handling:** Replaced unchecked `unwrap()` calls with explicit error propagation in `app.rs`.
- **Startup:** Added validation for loaded configuration at startup with clear diagnostics.
- **Observability:** Instrument `CreateAnalysisJobUseCase` and workflow tasks with `tracing`.
- **Test Stability:** Fixed file modes and non-deterministic fingerprints in test snapshots.

### Dependencies Added
- `globset` for robust glob pattern matching.

## [0.5.0] - 2026-02-11

### Added

- **SAST Engine Maturation (V4 Refactor):**
  - Migrated security rules from hand-coded Rust modules to declarative TOML format (embedded via `include_str!`).
  - Implemented unified `SastEngine` with consolidated parsing, pattern querying, and taint detection under a single async-friendly locking strategy (tokio::RwLock).
  - Added `SymbolTable` infrastructure for lexical scope-aware variable tracking, shadowing detection, and reassignment analysis.
  - Implemented interprocedural taint analysis with `FunctionTaintSummary`, `InterProceduralContext`, and cross-function data-flow propagation.
  - Integrated taint patterns into separate TOML files (vulnera-sast/taint-patterns/\*.toml) for maintainability.
  - Added `RulePackConfig` and Git-based rule pack loading via `RulePackLoader` and `CompositeRuleLoader`.
  - Introduced `SemanticRuleOptions` for type-aware rule constraints with lightweight `SemanticContext` inference.
  - Expanded Tree-sitter language support and improved query predicate evaluation (regex, text matching).
  - Added data-driven CVE fixtures and `datatest` harness for rule accuracy validation with CI gate assertions.
  - Implemented regex compilation caching and metavariable bindings extraction for improved performance.
  - Organized domain entities into focused modules (finding, pattern_types, rule, suppression, taint_types, call_graph).
  - Added comprehensive symbol table tests covering scope management, variable resolution, taint tracking, and shadowing.

- **JobWorkflow & Orchestration Enhancements:**
  - Formalized `JobStatus` state machine with transitions (`Pending` → `Queued` → `Running` → `Completed`/`Failed`/`Cancelled`).
  - Centralized job lifecycle management via `JobWorkflow` application service with transition validation and audit trails (`JobTransition`).
  - Introduced `IJobQueue` domain service trait for decoupled job orchestration.
  - Enhanced telemetry with cache hit tracking in orchestrator controllers.

- **LLM Code Fix Endpoint:**
  - Added automated code fix generation with language detection and contextual awareness.
  - Enhanced binary analysis with MIME type detection and file signature verification.
  - Integrated dynamic resilience wrapping in LLM provider registry.

- **Enterprise Licensing & Module Tiering:**
  - Introduced `ModuleTier` (Community/Enterprise) support for open-source vs. commercial feature gating.
  - Implemented `EnterpriseConfig` and entitlement-based module selection in `RuleBasedModuleSelector`.

- **Database Baseline Migration:**
  - Consolidated incremental migrations into a single `migrations/20260209000001_baseline.sql` file.
  - Baseline creates core schema, indexes, triggers, views, and default subscription limits.

### Changed

- **SAST Module Structure:** Reorganized domain surface into focused modules (domain/finding, domain/pattern_types, domain/rule, etc.). Updated internal imports to use explicit paths.
- **SAST Cache:** Replaced `std::sync::RwLock` with `tokio::sync::RwLock` in `InMemoryAstCache` for async-safe locking.
- **Rule Repository:** Removed PostgreSQL-backed SAST rule storage; now uses file/default loaders and in-memory/Dragonfly caches.
- **SAST Composition:** Updated composition root to no longer pass `PgPool` into `AnalysisModules::init`; decoupled database from SAST module.
- **Severity Default:** Derived `Default` for `Severity` with `Medium` as the default variant.
- **License:** Changed from AGPL-3.0-or-later to Proprietary in Cargo.toml.
- **MSRV:** Set Clippy MSRV to 1.85.0; increased too-many-arguments threshold to 8.

### Fixed

- **SAST Lock Ordering:** Documented and enforced lock ordering in `SastEngine` to prevent deadlocks and nested-lock issues.
- **Cache Management:** Fixed borrow checker issues in orchestrator controllers during analytics aggregation; standardized snapshot persistence.
- **Taint Analysis Precision:** Improved variable extraction in taint engine; prefer named captures over first capture text.
- **Symbol Table Package Extraction:** Fixed package extraction using `split('/').next_back()` for reliable last path segment resolution.
- **Rule Matching:** Tightened SAST rules across languages (Go HTTP client methods, Python YAML safe_load exclusion, Rust unsafe detection).

### Removed

- **Legacy Modules:** Removed per-language Rust rule modules and duplicated rule builders; deleted obsolete docs/assets.
- **SAST Exports:** Removed legacy `RuleEngine` wrapper; removed top-level domain re-exports (consumers must import from concrete modules).
- **Database:** Removed older incremental migrations; new deployments must use the baseline migration.
- **License File:** Removed AGPL LICENSE file.
- **Obsolete Rules & Fixtures:** Removed noisy SAST rules (go-ssrf, c-uninitialized-var) and corresponding CVE fixtures to reduce false positives.

### Breaking Changes

- **SAST Imports:**
  - `vulnera_sast::domain::entities::<Type>` paths were removed. Update to `vulnera_sast::domain::<Type>` or specific submodules.
  - `crate::domain::Rule` → `crate::domain::pattern_types::PatternRule`
  - `crate::domain::Pattern` → `crate::domain::pattern_types::Pattern`
  - `crate::domain::FileSuppressions` → `crate::domain::suppression::FileSuppressions`
  - `crate::domain::{Finding, Severity, Location}` → `crate::domain::finding::{Finding, Severity, Location}`

- **SAST Constructor:** Removed direct `SastModule::with_use_case` constructor. Migrate to `SastModule::builder().use_case(<Arc<ScanProjectUseCase>>)`.

- **Database Migration:** Older incremental migrations and the DB-backed SAST rule storage were removed. Existing databases created from the previous migration history are **not compatible** with this baseline. Initialize empty DBs with `sqlx migrate run` using the new baseline migration.

- **License Change:** License changed from AGPL-3.0-or-later to Proprietary. Review licensing and compliance with legal counsel before using or redistributing this codebase.

- **CLI Separation:** `vulnera-cli` is now a separate workspace and repository. CLI commands and integration points differ from the main server binary.

### Migration Guide

1. **SAST Rule Consumption:** If you depend on `vulnera-sast` as a library:
   - Update all imports to use `vulnera_sast::domain::<Type>` instead of `domain::entities::<Type>`.
   - If you used `Rule` directly, migrate to `PatternRule`.
   - Use `SastModule::builder()` for construction instead of `with_use_case()`.

2. **Database Setup:** If migrating from 0.4.x:
   - Backup your existing database.
   - Drop and recreate the database, then run `sqlx migrate run` against the new baseline.

3. **Enterprise Features:** If leveraging enterprise licensing:
   - not complete yet

### Dependencies Added

- `moka` (0.12, with "future" feature) for lock-free query caching in SAST engine.
- `git2` (0.20.3) for Git-based rule pack loading.
- `datatest-stable` (0.3.3) for CVE fixture harness and data-driven tests.
- `walkdir` (2.5) for filesystem traversal in rule and taint loading.

### Contributors

Special thanks to the authors of the book "Principles of Program Analysis" because it helped alot in the process of the SAST V4 maturation.

## [0.4.1] - 2026-02-08

### Added

- **Orchestrator Workflow & State Machine:**
  - Implemented a formal `JobStatus` state machine (`Pending` → `Queued` → `Running` → `Completed`/`Failed`/`Cancelled`).
  - Centralized job lifecycle management in a new `JobWorkflow` application service.
  - Added transition validation and a rich audit trail (`JobTransition`) persisted in snapshots.
  - Introduced `IJobQueue` domain service trait for decoupled orchestration.
- **Enterprise & Open Source Readiness:**
  - Added `ModuleTier` (Community/Enterprise) to support the open-source model.
  - Implemented `EnterpriseConfig` and entitlement-based module selection in `RuleBasedModuleSelector`.
  - Added `CLA.md`, `SECURITY.md`, `SUPPORT.md`, and updated `CONTRIBUTING.md` for community engagement.
  - Updated Github funding configuration (`FUNDING.yml`).
- **LLM-Powered Remediation & Analysis:**
  - Added automated code fix generation endpoint with language detection and contextual awareness.
  - Enhanced binary analysis with MIME type detection and file signature verification.
  - Integrated dynamic resilience wrapping in LLM provider registry.
- **Resilient Orchestration:**
  - Decoupled `ExecuteAnalysisJobUseCase` from job state mutation (now uses immutable references).
  - Improved job queue worker reliability with workflow-mediated state transitions.
  - Enhanced telemetry with cache hit tracking in orchestrator controllers.

### Fixed

- **CLI Decoupling:**
  - Successfully decoupled `vulnera-cli` into a separate repository/workspace.
  - Replaced internal dependency references with Git-based workspace overrides.
- **Cache Management:**
  - Fixed borrow checker issues in orchestrator controllers during analytics aggregation.
  - Standardized snapshot persistence during job lifecycle transitions.

## [0.4.0] - 2026-01-06

### Added

- **Advanced SAST Capabilities:**
  - Migrated call graph analysis to Tree-sitter AST for improved accuracy and language support.
  - Implemented cross-file call graph resolution and topological sorting for inter-procedural analysis.
  - Enhanced pattern translation for complex expressions including call arguments, member access, and binary operations.
  - Support for custom taint configuration loading and incremental analysis capabilities.
  - Detailed SAST metrics including skipped/failed files, scan duration, and resource limits.
- **Enhanced Dependency Analysis:**
  - Unified `VulneraRegistryAdapter` replacing multiple ecosystem-specific registry clients.
  - Recursive dependency resolution for manifest files without lockfiles.
  - Support for dependency graph export and richer edge relationship modeling.
  - Improved synchronization between graph nodes and analysis reports.
- **Secret Detection Improvements:**
  - Context-aware secret verification to reduce false positives.
  - Entropy-based detection for high-randomness credentials.
- **LLM Integration Updates:**
  - Migrated primary LLM provider from Huawei to Google Gemini for improved explanation quality and fix generation.
- **Security & Performance:**
  - Migrated password hashing from bcrypt to OWASP-recommended Argon2id.
  - Made password verification operations exclusively asynchronous to prevent blocking the async runtime.
- **Documentation:**
  - Comprehensive documentation for the Web Dashboard and team collaboration features.
  - Updated architectural guides reflecting the new Tree-sitter based SAST engine.

### Changed

- **MSRV Update:** Bumped Minimum Supported Rust Version (MSRV) to 1.82.0.
- **Orchestrator Refinement:** Centralized analysis module initialization and refined data models for better extensibility.
- **CLI Testing:** Added comprehensive integration tests for `vulnera-cli`.

### Fixed

- **Graph Consistency:** Resolved issues where root packages were inconsistently counted in dependency analysis reports.
- **Test Stability:** Extended test timeouts for integration suites to accommodate complex analysis tasks.

---

## [0.3.2] - 2025-11-26

### Added

- **VulneraAdvisor Integration for Vulnerability Management:**
  - Created new `vulnera-advisor` crate for unified vulnerability data management and opensourced it as a contribution to the community.
  - New `VulneraAdvisorRepository` wrapping the `vulnera-advisor` crate
  - Implementation of `IVulnerabilityRepository` trait for vulnerability data management
  - `VulneraAdvisorConfig` for managing external dependencies (Redis, API tokens)
  - Methods for syncing vulnerability sources and converting advisories to domain vulnerabilities
  - Enhanced error handling and logging throughout repository methods

- **LLM-Powered Code Analysis and Vulnerability Explanation:**
  - LLM controllers for code fix generation and vulnerability explanation
  - Token bucket rate limiting middleware for LLM request management
  - Request/response models: `GenerateCodeFixRequest`, `CodeFixResponse`, `ExplainVulnerabilityRequest`, `NaturalLanguageQueryRequest`
  - Finding enrichment use case with LLM-generated insights
  - Support for multiple LLM providers (HuaweiLlmProvider with wiremock testing)
  - Comprehensive unit and integration tests for LLM interactions using MockLlmProvider
  - Prompt builder and template system for generating context-aware AI queries

- **Organization and Team Management:**
  - Database migrations for organizations, organization members, job results, analysis events, and user stats
  - Organization CRUD operations: `CreateOrganization`, `ListOrganizations`, `UpdateOrganization`, `DeleteOrganization`
  - Organization member management: inviting, removing, and listing members
  - Organization statistics and analytics endpoints
  - `IOrganizationRepository` and `SqlxOrganizationRepository` for database persistence
  - `IOrganizationMemberRepository` with member operations
  - `Persisted Job Results` repository for tracking job results
  - `Subscription Limits` repository for managing subscription tiers

- **Personal Analytics and Usage Tracking:**
  - `PersonalStatsMonthly` struct for tracking user-level statistics
  - `IPersonalStatsMonthlyRepository` trait and `SqlxPersonalStatsMonthlyRepository` implementation
  - Analytics recording integrated in job processing for both user and organization contexts
  - Personal analytics endpoints: dashboard and usage statistics retrieval
  - Enhanced `JobInvocationContext` to include organization context for proper analytics attribution

- **Enhanced Rate Limiting Configuration:**
  - Additional excluded paths for rate limiting middleware
  - Improved route exclusions supporting more endpoints
  - Fine-grained control over rate limiting per endpoint

- **Security Enhancements with CSRF Protection:**
  - `CsrfService` for generating and validating CSRF tokens
  - CSRF token lifecycle integration with authentication (set during login/registration)
  - CSRF validation middleware protecting state-changing requests
  - Separation of public and protected authentication endpoints
  - Enhanced cookie-based authentication with CSRF tokens in responses
  - Updated CORS settings to support cookie-based authentication with credentials

### Changed

- **Development Configuration Improvements:**
  - Updated CORS configuration for development to specify allowed origins
  - Enhanced cookie handling for secure token transmission
  - Improved authentication controller response structures for CSRF support

- **Code Quality and Readability:**
  - Simplified function signatures across multiple modules for better maintainability
  - Improved code readability in authentication, orchestrator, and analysis modules
  - Refactored recommendation logic to use `sort_by_key` for better performance
  - Reformatted job controller summary initialization for consistency

- **Middleware Documentation:**
  - Clarified GHSA token middleware purpose and Git operation relationship
  - Improved documentation for GitHub token handling in middleware stack

### Technical Details

- **VulneraAdvisor Integration:**
  - Ecosystem and severity conversions with comprehensive test coverage
  - Mock repository trait updated to use `IVulnerabilityRepository`
  - Integration with existing vulnerability management pipeline

- **LLM Implementation:**
  - Uses Huawei LLM provider with configurable API endpoints
  - Prompt builder generates context-aware queries with vulnerability metadata
  - Rate limiting via token bucket with configurable limits per endpoint
  - Testing infrastructure with wiremock for API simulation

- **Analytics Implementation:**
  - Job invocation context tracks both user and organization for proper attribution
  - Personal statistics aggregation at monthly granularity
  - Subscription limits stored per organization for usage enforcement

- **CSRF Implementation:**
  - Token generation on login/registration endpoints
  - Token validation before state-modifying operations
  - Secure cookie transmission with HTTP-only flags
  - Compatible with both form-based and JSON-based requests

### Testing

- Added unit and integration tests for LLM provider interactions
- Integration tests for organization management endpoints
- Tests for CSRF token generation and validation
- MockLlmProvider for testing LLM use cases
- Wiremock integration for API provider simulation

### Configuration

New environment variables:

```bash
# LLM Configuration
VULNERA__LLM__ENABLED=true
VULNERA__LLM__PROVIDER=huawei
VULNERA__LLM__HUAWEI_API_KEY=<your-api-key>
VULNERA__LLM__HUAWEI_API_URL=https://api.huaweicloud.com/...

# Rate Limiting (LLM)
VULNERA__RATE_LIMITING__LLM_REQUESTS_PER_MINUTE=60
VULNERA__RATE_LIMITING__EXCLUDED_PATHS='["/health", "/docs"]'

# Analytics
VULNERA__ANALYTICS__ENABLED=true
VULNERA__ANALYTICS__GRANULARITY=monthly

# CSRF Protection
VULNERA__AUTH__CSRF_ENABLED=true
VULNERA__AUTH__CSRF_TOKEN_TTL_MINUTES=30
```

### Dependencies Added

- `vulnera-llm` crate for LLM-based analysis features
- Testing dependencies: `mockall`, `proptest`, `rstest`, `tokio-test`, `wiremock`

### Dockerfile

- Updated to include `vulnera-llm` module in dependency management and build stages

### Contributors

- Khaled Alam

---

## [0.3.1] - 2025-11-24

### Added

- **Asynchronous Job Processing with Persistent Queue:**
  - Implemented background job queue with Redis/Dragonfly persistence
  - `JobQueueHandle` for enqueuing analysis jobs asynchronously
  - `JobWorkerContext` for managing worker pool execution
  - Worker pool spawns with configurable concurrency via `VULNERA__ANALYSIS__MAX_JOB_WORKERS`
  - Jobs persist across service restarts (no data loss on crash)
  - Horizontal scalability support (multiple workers can poll same queue)
  - Job status tracking and snapshot persistence via `DragonflyJobStore`
  - Added `lpush` and `brpop` methods to `DragonflyCache` for queue operations
  - Queue key: `vulnera:orchestrator:job_queue` with 5-second blocking timeout
  - Job serialization/deserialization support via serde

- **Enhanced Project Detection:**
  - Expanded framework detection (Django, React, Docker)
  - Added `frameworks` field to `ProjectMetadata` for storing detected frameworks
  - Added `detected_config_files` field to `ProjectMetadata` for tracking configuration files
  - Increased directory traversal depth from 3 to 5 levels
  - Intelligent directory filtering (skips `node_modules`, `target`, `vendor`, `venv`, `__pycache__`, hidden dirs)
  - Enhanced language detection for JavaScript, TypeScript, Python, Rust, Go, Java, PHP
  - Framework-specific file detection:
    - Django: `manage.py` detection
    - React: Filename-based detection
    - Docker: `Dockerfile`, `docker-compose.yml`, `docker-compose.yaml`
  - Configuration file tracking for package managers: `package.json`, `pyproject.toml`, `Cargo.toml`, `go.mod`, `pom.xml`, `build.gradle`, `composer.json`

- **Intelligent Module Selection:**
  - Rule-based module selector now leverages framework metadata
  - API Security module activated conditionally for Django, FastAPI, Spring frameworks
  - IaC (Infrastructure as Code) module activated for Docker configurations
  - Context-aware security scanning based on detected project characteristics

- **Enhanced Parser Support:**
  - **Go Parser:** Improved `go.mod` parsing with better dependency extraction and graph building
  - **C/C++ Parser:** Added tree-sitter-based parsing for C and C++ with AST conversion
  - **Rust Parser:** Enhanced with detailed AST conversion via `syn` crate for comprehensive code analysis
  - **NPM Parser:** Improved `package-lock.json` handling for v2/v3 lockfiles, root package name extraction
  - **Dependency Graph Extraction:** All ecosystem parsers now extract dependency edges and relationships
  - Added `ParseResult` struct to capture both packages and their dependency graph
  - Integration with `petgraph` crate for advanced graph operations

- **OpenAPI Parser Enhancements:**
  - Schema reference resolver with circular reference detection
  - Schema caching for improved performance
  - Enhanced `ApiSchema` and `ApiProperty` with additional metadata fields
  - Support for both JSON and YAML OpenAPI specifications via `oas3` crate
  - Comprehensive unit tests for parser and analyzers

- **SAST Module Improvements:**
  - Added security rules for Go, C/C++, Python, JavaScript, and Rust
  - Comprehensive integration tests for multi-language SAST scanning
  - Improved pattern matching and confidence scoring
  - Language-specific security anti-patterns detection

- **Secrets Detection Enhancements:**
  - Improved entropy detection logic for high-entropy string identification
  - Enhanced GitHub and GitLab token verifiers with comprehensive testing
  - Added test fixtures for AWS, generic secrets, and various credential types
  - Property-based testing for entropy calculations using `proptest`

- **Comprehensive Test Coverage:**
  - OpenAPI parser unit tests with multiple test fixtures (circular refs, OAuth flows, schema refs)
  - Authentication/OAuth analyzer unit tests
  - Dependency resolution integration tests for NPM and Cargo ecosystems
  - Repository analysis integration tests with rate limiting and file size constraints
  - Version resolution service integration tests
  - SAST integration tests for all supported languages
  - Secret detection unit and property-based tests
  - Cache integration tests with improved assertions

### Changed

- **Job Processing Architecture:**
  - Migrated from in-memory `mpsc` channel to Dragonfly-backed persistent queue
  - Removed synchronous job execution in favor of asynchronous background processing
  - `QueuedAnalysisJob` now includes `AnalysisJob`, `Project`, `callback_url`, and `invocation_context`
  - Job workers continuously poll queue with semaphore-based concurrency control
  - Application wiring in `app.rs` updated to initialize new job queue architecture

- **Dependency Analysis:**
  - `BacktrackingResolver` improved to handle cases with no available versions
  - Added appropriate conflict messages for dependency resolution failures
  - Manifest and lockfile graph building enhanced for NPM and Cargo

- **Code Quality and Formatting:**
  - Cleaned up code formatting across test files and modules
  - Fixed import statement formatting in `extractors.rs`
  - Removed unused `excluded_count` variable in `DirectoryScanner`
  - Removed mutable reference for job creation in analyze function
  - Simplified `RequestBody` parsing to accept `Option` parameter

- **Configuration:**
  - Migrated from `serde_yaml` to `serde_yml` for consistency
  - Updated OpenAPI parser configuration to use `oas3` crate
  - Enhanced cache configuration with additional validation

### Removed

- **HTML Report Generation:**
  - Removed HTML report generation code and related module (`formats/html.rs`)
  - Cleaned up HTML-specific dependencies and report service methods
  - Focus shifted to JSON/SARIF formats for programmatic consumption

### Fixed

- Import statement formatting issues in authentication extractors
- Unused variable warnings in directory scanner
- Mutable reference issues in job creation flow
- NPM parser root package name handling in lockfile v2/v3
- Cache integration test assertions and reliability

### Configuration

New environment variables for job queue and enhanced detection:

```bash
# Job Queue Configuration
VULNERA__ANALYSIS__MAX_JOB_WORKERS=4  # Maximum concurrent job workers

# Queue is stored in Dragonfly/Redis at key: vulnera:orchestrator:job_queue
# Ensure Dragonfly is running and configured via:
VULNERA__CACHE__DRAGONFLY_URL="redis://127.0.0.1:6379"
```

### Testing

Added comprehensive test suites:

- 95 files changed, 6858 insertions, 803 deletions
- New test fixtures for OpenAPI validation scenarios
- Integration tests for dependency resolution across ecosystems
- Property-based tests for entropy detection
- Multi-language SAST integration tests
- Secret detection verifier tests

### Technical Details

- **Job Queue Implementation:**
  - Uses Redis `LPUSH` for enqueuing (left push to queue)
  - Uses Redis `BRPOP` with 5-second timeout for dequeuing (blocking right pop)
  - Serializes job payloads to JSON via `serde_json`
  - Worker pool respects `max_concurrent_jobs` configuration via `tokio::sync::Semaphore`
  - Job snapshots persist to Dragonfly with 1-hour TTL for replay/debugging

- **Project Detection Implementation:**
  - `FileSystemProjectDetector` uses `walkdir` with depth-first traversal
  - Filter function allows root directory (depth 0) for temp directory handling
  - Comprehensive file extension and filename pattern matching
  - Framework detection via heuristics (e.g., `manage.py` → Django)

- **Parser Enhancements:**
  - Dependency graph extraction uses `petgraph` for relationship modeling
  - Tree-sitter integration for C/C++ provides robust AST parsing
  - Syn crate integration for Rust enables proc-macro-based analysis

### Performance Improvements

- Schema caching in OpenAPI parser reduces redundant parsing
- Dependency graph pre-allocation optimizes memory usage
- Concurrent job processing via worker pool improves throughput
- Persistent queue eliminates job re-processing on restart

### Breaking Changes

- **Job API Behavior Change:** Jobs are now processed asynchronously in background workers
  - `POST /api/v1/analyze/job` immediately returns job ID without waiting for completion
  - Clients must poll job status or use webhooks (via `callback_url`) for completion notification
  - Previous synchronous behavior removed in favor of scalable async architecture

### Migration Guide

For upgrading from 0.3.0 to 0.3.1:

1. **Ensure Dragonfly/Redis is running:**

   ```bash
   # Docker example
   docker run -p 6379:6379 docker.dragonflydb.io/dragonflydb/dragonfly
   ```

2. **Update environment variables:**

   ```bash
   VULNERA__CACHE__DRAGONFLY_URL="redis://127.0.0.1:6379"
   VULNERA__ANALYSIS__MAX_JOB_WORKERS=4
   ```

3. **Update API client code:**
   - Job submission now returns immediately with `job_id`
   - Implement job status polling or webhook handling
   - Example:

     ```bash
     # Submit job (returns immediately)
     JOB_ID=$(curl -X POST .../analyze/job ... | jq -r .job_id)

     # Poll for completion
     curl -X GET .../jobs/$JOB_ID
     ```

4. **No database migrations required** - all changes are in-memory or cache-based

### Contributors

- Only and the only one Khaled Alam

---

## [0.3.0] - 2025-11-09

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

- **Caching System Migration to Dragonfly DB:**
  - Migrated from file-based caching to Dragonfly DB as the primary cache backend
  - Dragonfly DB provides high-performance, Redis-compatible in-memory data store
  - Multi-threaded architecture for better performance and scalability
  - Built-in persistence, replication, and horizontal scaling support
  - TTL-configurable cache entries with optional compression for large entries
  - Redis-compatible protocol allows easy migration and tool compatibility
  - Configuration via `VULNERA__CACHE__DRAGONFLY_URL` environment variable
  - Connection timeout configuration via `VULNERA__CACHE__DRAGONFLY_CONNECTION_TIMEOUT_SECONDS`
  - File-based cache system has been replaced (L1/L2 multi-level caching removed)
  - Cache key standardization maintained across all modules
  - Improved cache performance and reduced latency for vulnerability data lookups

### Configuration

New environment variables for caching and module configuration:

```bash
# Cache Configuration (Dragonfly DB)
VULNERA__CACHE__DRAGONFLY_URL="redis://127.0.0.1:6379"
VULNERA__CACHE__DRAGONFLY_CONNECTION_TIMEOUT_SECONDS=5
VULNERA__CACHE__TTL_HOURS=24
VULNERA__CACHE__ENABLE_CACHE_COMPRESSION=true
VULNERA__CACHE__COMPRESSION_THRESHOLD_BYTES=10240
```

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
  - Cached via file-based caching with TTL from `VULNERA__CACHE__TTL_HOURS` (default: 24).
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
  - `VULNERA__NVD__DATA_DIRECTORY` (default: `.vulnera_data`) - Directory for NVD SQLite database
  - `VULNERA__CACHE__TTL_HOURS` (default: `24`)
- Recommendations:
  - `VULNERA__RECOMMENDATIONS__EXCLUDE_PRERELEASES` (default: `false`)
  - `VULNERA__RECOMMENDATIONS__MAX_VERSION_QUERIES_PER_REQUEST` (default: `50`)

---
