# Vulnera SAST

**Static Application Security Testing (SAST) module** for the Vulnera security analysis platform.

High-performance, multi-language vulnerability detection via tree-sitter AST analysis with inter-procedural taint tracking and data-flow analysis.

## Overview

`vulnera-sast` performs deep static security analysis across **7+ programming languages** using native AST queries and sophisticated data-flow tracking. It detects vulnerabilities by combining:

- **Pattern Matching**: Tree-sitter S-expression queries and metavariable patterns
- **Taint Analysis**: Inter-procedural tracking of untrusted data from sources → sinks with sanitizer recognition
- **Call Graph Analysis**: Cross-function vulnerability detection and data-flow propagation
- **SARIF Export**: Standard-compliant reporting (SARIF v2.1.0)

Zero-config by design, composable via the builder pattern, and lock-free concurrent for Dragonfly-backed AST caching.

## Supported Languages

| Language       | Parser                 | Features                     |
| -------------- | ---------------------- | ---------------------------- |
| **Python**     | tree-sitter-python     | Full AST, taint, call graphs |
| **JavaScript** | tree-sitter-javascript | Full AST, taint, call graphs |
| **TypeScript** | tree-sitter-typescript | Full AST, taint, call graphs |
| **Rust**       | tree-sitter-rust       | Full AST, taint, call graphs |
| **Go**         | tree-sitter-go         | Full AST, taint, call graphs |
| **C**          | tree-sitter-c          | Full AST, pattern matching   |
| **C++**        | tree-sitter-cpp        | Full AST, pattern matching   |

## Architecture

### Layered Design (DDD)

```
┌──────────────────────────────────────┐
│ Presentation Layer                   │
│ (AnalysisModule trait impl)          │
└──────────────────────────────────────┘
           ↓
┌──────────────────────────────────────┐
│ Application Layer                    │
│ • ScanProjectUseCase                 │
│ • AnalysisConfig orchestration       │
│ • Job lifecycle management           │
└──────────────────────────────────────┘
           ↓
┌──────────────────────────────────────┐
│ Domain Layer                         │
│ • Rule (PatternRule, DataFlowRule)   │
│ • Finding, Location                  │
│ • Pattern, Taint types               │
│ • Severity, Confidence enums         │
└──────────────────────────────────────┘
           ↓
┌──────────────────────────────────────┐
│ Infrastructure Layer                 │
│ • SastEngine (pattern + taint)       │
│ • TreeSitterParser                   │
│ • TaintQueryEngine (data-flow)       │
│ • CallGraphBuilder                   │
│ • DirectoryScanner (concurrent)      │
│ • RuleRepository (TOML/YAML/JSON)    │
│ • AstCacheService (Dragonfly)        │
└──────────────────────────────────────┘
```

### Thread-Safe Design

- **Lock-Free Query Cache** (`moka::Cache`): Compiled tree-sitter queries cached without contention
- **RwLock for Parser State**: Minimal held during parsing, released before analysis
- **Lock Ordering**: Parser → Taint Engine (never reverse) prevents deadlocks
- **Streaming Iterators**: Memory-efficient AST traversal without intermediate allocations

## Quick Start

### Zero-Config (Sensible Defaults)

```rust
use vulnera_sast::SastModule;

// No configuration needed — auto-detects depth, uses default rules
let module = SastModule::new();

// Execute within the orchestrator's AnalysisModule interface
```

### With Custom SastConfig

```rust
use vulnera_sast::SastModule;
use vulnera_core::config::SastConfig;

let config = SastConfig {
    max_scan_depth: 5,
    exclude_patterns: vec!["node_modules".to_string(), "target".to_string()],
    rule_file_path: Some("rules.toml".into()),
    enable_logging: true,
};

let module = SastModule::with_config(&config);
```

### Builder Pattern (Full Control)

```rust
use vulnera_sast::SastModule;
use vulnera_core::config::SastConfig;

let module = SastModule::builder()
    .sast_config(&custom_config)
    .analysis_config(custom_analysis)
    .ast_cache(Arc::new(my_dragonfly_cache))
    .build();
```

### Custom Use Case (Composition Root)

```rust
use vulnera_sast::ScanProjectUseCase;
use std::sync::Arc;

// In your composition root (src/app.rs or src/modules/mod.rs)
let use_case = Arc::new(ScanProjectUseCase::with_config(&sast_config, analysis_config));
let module = SastModule::builder()
    .use_case(use_case)
    .build();
```

## Configuration

### `SastConfig` Options

```rust
pub struct SastConfig {
    /// Maximum directory traversal depth (default: 10)
    pub max_scan_depth: usize,

    /// Patterns to skip (e.g., "node_modules", ".git", "target")
    pub exclude_patterns: Vec<String>,

    /// Optional custom rules file (TOML, YAML, or JSON)
    /// If not provided, only default rules are loaded
    pub rule_file_path: Option<PathBuf>,

    /// Enable tracing instrumentation (default: true)
    pub enable_logging: bool,
}
```

### `AnalysisConfig` Options

Controls concurrency, caching, and timeouts:

```rust
pub struct AnalysisConfig {
    /// Max concurrent file parsing tasks
    pub max_concurrent_tasks: usize,

    /// Parse timeout per file (seconds)
    pub parse_timeout_secs: u64,

    /// Taint analysis timeout (seconds)
    pub taint_timeout_secs: u64,

    /// Enable AST caching via Dragonfly
    pub enable_ast_cache: bool,

    /// Query cache capacity (default: 512)
    pub query_cache_capacity: u64,
}
```

If you provide only `SastConfig`, `AnalysisConfig::from(&sast_config)` derives sensible defaults.

## Rule System

### Two Rule Types

#### 1. **PatternRule** — Direct Pattern Matching

Detect code patterns using tree-sitter queries or metavariable syntax.

```yaml
# rules.toml or rules.yaml
[[pattern_rules]]
id = "python-eval-injection"
name = "Unsafe eval() Usage"
description = "Detects eval() calls with untrusted input"
severity = "High"
languages = ["Python"]
pattern = { type = "TreeSitterQuery", value = "(call function: (identifier) @fn (#eq? @fn \"eval\"))" }
cwe_ids = ["CWE-95", "CWE-94"]
owasp_categories = ["A06:2021 - Vulnerable and Outdated Components"]
tags = ["injection", "dangerous-function"]
message = "Unsafe eval() detected: {{@fn}} called with untrusted data"
```

#### 2. **DataFlowRule** — Taint Tracking

Track untrusted data from sources → sinks, recognizing sanitizers.

```yaml
[[data_flow_rules]]
id = "sql-injection"
name = "SQL Injection via Taint"
description = "Untrusted data flows to SQL query without sanitization"
severity = "Critical"
languages = ["Python"]

# Where taint enters (sources)
[[data_flow_rules.sources]]
pattern = { type = "TreeSitterQuery", value = "(call function: (identifier) @fn (#eq? @fn \"request.args.get\"))" }

# Where taint is dangerous (sinks)
[[data_flow_rules.sinks]]
pattern = { type = "TreeSitterQuery", value = "(call function: (identifier) @fn (#eq? @fn \"cursor.execute\"))" }

# Functions that clean taint (sanitizers)
[[data_flow_rules.sanitizers]]
pattern = { type = "TreeSitterQuery", value = "(call function: (identifier) @fn (#eq? @fn \"escape_sql\"))" }

cwe_ids = ["CWE-89"]
owasp_categories = ["A03:2021 - Injection"]
```

### Pattern Types

| Type                | Example                                               | Use Case                                    |
| ------------------- | ----------------------------------------------------- | ------------------------------------------- |
| **TreeSitterQuery** | `(call function: (identifier) @fn (#eq? @fn "eval"))` | Native AST queries, most powerful           |
| **Metavariable**    | `$DB.execute($QUERY)`                                 | Metavariable syntax (execution planned)     |
| **AnyOf**           | `[pattern1, pattern2, ...]`                           | Match any pattern in list                   |
| **AllOf**           | `[pattern1, pattern2, ...]`                           | Match all patterns in sequence              |
| **Not**             | `{not: pattern}`                                      | Exclude pattern                             |

### Confidence Calculation

Automatically assigned based on pattern specificity:

| Level      | Criteria                                                    |
| ---------- | ----------------------------------------------------------- |
| **High**   | Exact function call + context, or regex with high precision |
| **Medium** | Function call without context, AST node + basic context     |
| **Low**    | AST node type alone, generic patterns                       |

### Severity Levels

- `Critical` — Immediate exploit risk
- `High` — Likely exploitable
- `Medium` — Potential impact
- `Low` — Minor risk
- `Info` — Informational

## Advanced Features

### 1. **AST Caching with Dragonfly**

Cache parsed ASTs across analysis runs to avoid re-parsing:

```rust
use vulnera_sast::SastModule;

let dragonfly_cache = Arc::new(DragonflyAstCache::new(redis_url));

let module = SastModule::builder()
    .ast_cache(dragonfly_cache)
    .build();
```

Cache keys: `sast:ast:{hash(file_path, file_content)}`

### 2. **Incremental Analysis**

Only analyze files that changed since the last scan:

```rust
use crate::infrastructure::incremental::IncrementalTracker;

// First run: full analysis
let result = use_case.execute(project_path).await?;

// Second run: only changed files
let result = use_case.execute_incremental(project_path).await?;
```

Tracks file hashes and modification times.

### 3. **SARIF v2.1.0 Export**

Generate standard compliance reports:

```rust
use crate::infrastructure::sarif::SarifExporter;

let exporter = SarifExporter::new(SarifExporterConfig::default());
let sarif_report = exporter.export(&findings)?;

// Output to file
std::fs::write("report.sarif", sarif_report)?;
```

### 4. **Call Graph Analysis**

Detect vulnerabilities across function boundaries:

```rust
use crate::infrastructure::call_graph::CallGraphBuilder;

let builder = CallGraphBuilder::new();
let call_graph = builder.build(&syntax_tree)?;

// Propagate taint through call chains
```

### 5. **Inter-Procedural Context**

Track data flow through function parameters and returns:

```rust
use crate::infrastructure::data_flow::InterProceduralContext;

let ctx = InterProceduralContext::new(call_graph, source_files);
let taint_paths = ctx.trace_taint(source_location, sink_location)?;
```

## Usage in Orchestrator Context

The `SastModule` implements the `AnalysisModule` trait from `vulnera-core`:

```rust
// In src/app.rs or src/modules/mod.rs
use vulnera_sast::SastModule;
use vulnera_core::domain::module::AnalysisModule;

// Register as a module in the orchestrator
let sast = SastModule::new();

// Execute within the analysis pipeline
let config = ModuleConfig {
    source_uri: "/path/to/project".to_string(),
    analysis_depth: AnalysisDepth::Deep,
    job_id: job_uuid,
};

let result = sast.execute(&config).await?;

// Results are automatically converted to orchestrator Finding types
// and stored via the job persistence layer
```

## Rule Loading

### Load from File

```rust
use vulnera_sast::infrastructure::rules::RuleRepository;

// Load both file rules and defaults
let repo = RuleRepository::with_file_and_defaults("rules.toml");

// Load only file rules (fail if missing)
let repo = RuleRepository::from_file("rules.toml")?;

// Use only built-in defaults
let repo = RuleRepository::new();
```

### Supported Formats

- **TOML** (recommended): `rules.toml`
- **YAML**: `rules.yaml` or `rules.yml`
- **JSON**: `rules.json`

Example `rules.toml`:

```toml
[analysis]
depth = "Deep"
concurrency_level = 4

[[pattern_rules]]
id = "custom-rule-1"
name = "Custom Detection"
languages = ["Python", "JavaScript"]
severity = "High"
pattern = { type = "TreeSitterQuery", value = "..." }

[[data_flow_rules]]
id = "custom-taint-1"
name = "Custom Taint Rule"
severity = "Critical"
languages = ["Python"]
```

## Testing

### Run All Tests

```bash
cargo test -p vulnera-sast
```

### Data-Driven SAST Tests

Test rules against code samples:

```bash
cargo test --test datatest_sast_rules
```

Test data in `tests/sast_rules/` directory. Each file is a test case:

```python
# tests/sast_rules/python_sql_injection.py
import sqlite3
query = "SELECT * FROM users WHERE id = " + user_input  # Vulnerable
conn.execute(query)  # Finding expected here
```

### Review Snapshot Changes

```bash
cargo insta review
```

## Performance Considerations

### Lock-Free Design

- **Query Cache**: `moka::Cache` provides lock-free concurrent access to compiled tree-sitter queries
- **No Blocking Waits**: Parse timeout and taint timeout prevent indefinite hangs
- **Streaming Iterators**: Memory-O(1) AST traversal

### Scalability

- **File-Level Parallelism**: `tokio::task::JoinSet` processes files concurrently
- **Per-Language Parser Reuse**: Single `TreeSitterParser` instance per language, serialized via `RwLock`
- **Incremental Scans**: Skip unchanged files; only reanalyze modified code

### Benchmarking

Enable `tracing` to profile analysis phases:

```rust
// Logs include file parse time, pattern matching time, taint analysis time
RUST_LOG=vulnera_sast=debug cargo run
```

## Composition Root Integration

In `src/modules/mod.rs`:

```rust
pub fn init_sast_module(
    config: &Config,
    dragonfly_cache: Arc<dyn AstCacheService>,
) -> Arc<SastModule> {
    Arc::new(
        SastModule::builder()
            .sast_config(&config.sast)
            .ast_cache(dragonfly_cache)
            .build()
    )
}
```

Then wire into the module registry:

```rust
pub fn setup_modules(
    config: &Config,
    cache: Arc<dyn AstCacheService>,
) -> ModuleRegistry {
    let mut registry = ModuleRegistry::new();
    registry.register(ModuleType::SAST, init_sast_module(config, cache));
    // ... other modules
    registry
}
```

## Limitations & Future Work

1. **Rust Parser**: Tree-sitter-rust covers most cases; advanced macro expansion not yet supported
2. **Custom Patterns**: Reserved for future extensibility; currently Pattern::Custom is a no-op
3. **Context Sensitivity**: Confidence based on pattern structure, not full abstract interpretation
4. **Metavariable Execution**: Patterns are parsed but not yet executed (planned)

## Contributing

When adding new rules:

1. Add rule definition to `src/infrastructure/rules/default_rules/` or custom rules file
2. Create test data in `tests/sast_rules/{language}/`
3. Run `cargo test --test datatest_sast_rules` to verify
4. Update this README with rule documentation if significant

## License

See the main project LICENSE file.
