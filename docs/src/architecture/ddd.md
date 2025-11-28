# Domain-Driven Design

Vulnera follows Domain-Driven Design (DDD) principles to create a maintainable, testable codebase with clear boundaries between concerns.

## Layer Structure

Each crate in the Vulnera workspace follows a consistent layered structure:

```
vulnera-{crate}/
├── src/
│   ├── domain/           # Pure business logic
│   │   ├── entities/     # Core business objects
│   │   ├── value_objects/# Immutable values
│   │   └── traits/       # Domain interfaces
│   ├── application/      # Use cases
│   │   ├── services/     # Application services
│   │   └── dtos/         # Data transfer objects
│   ├── infrastructure/   # External integrations
│   │   ├── repositories/ # Data access
│   │   ├── api_clients/  # HTTP clients
│   │   └── parsers/      # File parsing
│   └── presentation/     # HTTP layer (orchestrator only)
│       ├── controllers/  # Request handlers
│       └── middleware/   # Cross-cutting concerns
```

## Domain Layer

The domain layer contains pure business logic with zero external dependencies.

### Entities

Core business objects with identity:

```rust
pub struct Vulnerability {
    pub id: VulnerabilityId,
    pub cve_id: Option<String>,
    pub severity: Severity,
    pub affected_packages: Vec<AffectedPackage>,
    pub description: String,
    pub published_at: DateTime<Utc>,
}
```

### Value Objects

Immutable values without identity:

```rust
pub struct Version(semver::Version);

impl Version {
    pub fn major(&self) -> u64 { self.0.major }
    pub fn minor(&self) -> u64 { self.0.minor }
    pub fn patch(&self) -> u64 { self.0.patch }
}
```

### Domain Traits

Interfaces defining capabilities:

```rust
pub trait AnalysisModule: Send + Sync {
    fn module_type(&self) -> ModuleType;
    fn supported_ecosystems(&self) -> &[Ecosystem];
    async fn analyze(&self, input: AnalysisInput) -> Result<AnalysisOutput>;
}

pub trait VulnerabilitySource: Send + Sync {
    async fn query(&self, package: &Package) -> Result<Vec<Vulnerability>>;
}
```

## Application Layer

Orchestrates domain logic to fulfill use cases.

### Use Cases

```rust
pub struct AnalyzeRepositoryUseCase {
    module_registry: Arc<ModuleRegistry>,
    module_selector: Arc<dyn ModuleSelector>,
}

impl AnalyzeRepositoryUseCase {
    pub async fn execute(&self, request: AnalysisRequest) -> Result<AnalysisResult> {
        let modules = self.module_selector.select(&request)?;
        let results = self.execute_modules(modules, &request).await?;
        Ok(self.aggregate_results(results))
    }
}
```

### Application Services

Coordinate multiple use cases:

```rust
pub struct AnalysisOrchestrator {
    analyze_use_case: Arc<AnalyzeRepositoryUseCase>,
    job_store: Arc<dyn JobStore>,
}
```

## Infrastructure Layer

Implements domain interfaces with concrete technologies.

### Repositories

```rust
pub struct PostgresUserRepository {
    pool: PgPool,
}

impl UserRepository for PostgresUserRepository {
    async fn find_by_id(&self, id: UserId) -> Result<Option<User>> {
        sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", id)
            .fetch_optional(&self.pool)
            .await
    }
}
```

### API Clients

```rust
pub struct OsvClient {
    http_client: reqwest::Client,
    base_url: String,
}

impl VulnerabilitySource for OsvClient {
    async fn query(&self, package: &Package) -> Result<Vec<Vulnerability>> {
        // HTTP request to OSV API
    }
}
```

### Parsers

```rust
pub trait DependencyParser: Send + Sync {
    fn supported_files(&self) -> &[&str];
    fn parse(&self, content: &str) -> Result<Vec<Dependency>>;
}

pub struct RequirementsTxtParser;
pub struct PackageJsonParser;
pub struct CargoTomlParser;
```

## Presentation Layer

HTTP API handlers (only in `vulnera-orchestrator`).

### Controllers

```rust
#[utoipa::path(
    post,
    path = "/api/v1/analyze/job",
    request_body = AnalysisRequest,
    responses(
        (status = 202, body = JobAcceptedResponse),
        (status = 400, body = ErrorResponse),
    )
)]
pub async fn create_analysis_job(
    State(state): State<OrchestratorState>,
    Json(request): Json<AnalysisRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Handle request
}
```

## Composition Root

All dependencies are wired in `src/app.rs`:

```rust
pub async fn create_app() -> Router {
    // Infrastructure
    let db_pool = create_db_pool().await;
    let cache = create_cache().await;
    
    // Domain services
    let osv_client = Arc::new(OsvClient::new());
    let nvd_client = Arc::new(NvdClient::new());
    
    // Application services
    let module_registry = create_module_registry(osv_client, nvd_client);
    let orchestrator = Arc::new(AnalysisOrchestrator::new(module_registry));
    
    // State
    let state = OrchestratorState { orchestrator, db_pool, cache };
    
    // Router
    Router::new()
        .route("/api/v1/analyze/job", post(create_analysis_job))
        .with_state(state)
}
```

## Benefits

### Testability

Each layer can be tested in isolation:

```rust
#[tokio::test]
async fn test_analyze_use_case() {
    let mock_registry = MockModuleRegistry::new();
    let mock_selector = MockModuleSelector::new();
    
    let use_case = AnalyzeRepositoryUseCase::new(mock_registry, mock_selector);
    let result = use_case.execute(test_request()).await;
    
    assert!(result.is_ok());
}
```

### Maintainability

- Clear boundaries between concerns
- Domain logic independent of frameworks
- Easy to swap infrastructure implementations

### Scalability

- Modules can be developed independently
- Infrastructure can scale horizontally
- Cache layer reduces external API pressure
