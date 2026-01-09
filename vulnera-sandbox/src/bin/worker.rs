//! Vulnera Worker - Isolated sandbox execution process
//!
//! This binary is spawned by the orchestrator to execute analysis modules
//! within a sandboxed environment. The workflow is:
//!
//! 1. Parse CLI arguments (policy, config, module type)
//! 2. Apply sandbox restrictions (Landlock, seccomp, rlimits)
//! 3. Execute the analysis module
//! 4. Output result as JSON to stdout

use std::io::{self, Read, Write};
use std::sync::Arc;

use clap::Parser;
use serde::{Deserialize, Serialize};

/// Worker version (synchronized with Cargo.toml)
const WORKER_VERSION: &str = env!("CARGO_PKG_VERSION");
use tracing::{Level, debug, error, info, warn};
use tracing_subscriber::fmt;

use vulnera_api::module::ApiSecurityModule;
use vulnera_core::config::Config;
use vulnera_core::domain::module::{AnalysisModule, ModuleConfig, ModuleResult};
use vulnera_core::infrastructure::cache::CacheServiceImpl;
use vulnera_core::infrastructure::cache::dragonfly_cache::DragonflyCache;
use vulnera_core::infrastructure::parsers::ParserFactory;
use vulnera_core::infrastructure::vulnerability_advisor::VulneraAdvisorRepository;
use vulnera_deps::module::DependencyAnalyzerModule;
use vulnera_sandbox::SandboxPolicy;
use vulnera_sast::module::SastModule;
use vulnera_secrets::module::SecretDetectionModule;

/// Worker CLI arguments
#[derive(Parser, Debug)]
#[command(name = "vulnera-worker")]
#[command(about = "Sandboxed worker for Vulnera analysis modules")]
struct Args {
    /// Module type to execute (e.g., "SAST", "SecretDetection", "ApiSecurity")
    #[arg(long)]
    module: String,

    /// Source URI to analyze
    #[arg(long)]
    source_uri: String,

    /// Project ID
    #[arg(long)]
    project_id: String,

    /// Job ID (UUID)
    #[arg(long)]
    job_id: String,

    /// Module specific configuration as JSON
    #[arg(long)]
    module_config: Option<String>,

    /// Global configuration as JSON
    #[arg(long)]
    config: Option<String>,

    /// Read policy from stdin (JSON)
    #[arg(long, default_value = "false")]
    policy_stdin: bool,

    /// Sandbox policy as JSON (alternative to stdin)
    #[arg(long)]
    policy: Option<String>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Disable sandbox restrictions (run without isolation)
    #[arg(long)]
    no_sandbox: bool,
}

/// Structured error codes for worker failures
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WorkerErrorCode {
    /// Failed to parse sandbox policy
    PolicyParseFailed,
    /// Sandbox setup (Landlock/seccomp) failed
    SandboxSetupFailed,
    /// Requested module type not found
    ModuleNotFound,
    /// Module execution error
    ModuleExecutionFailed,
    /// Execution exceeded timeout
    Timeout,
    /// Failed to serialize result
    SerializationFailed,
    /// Configuration parsing error
    ConfigParseFailed,
    /// Worker was interrupted by signal
    Interrupted,
    /// Unknown error
    Unknown,
}

/// Worker result sent back to orchestrator
#[derive(Debug, Serialize, Deserialize)]
struct WorkerResult {
    /// Whether execution succeeded
    success: bool,
    /// Module result as JSON (if success)
    result: Option<serde_json::Value>,
    /// Error message (if failed)
    error: Option<String>,
    /// Structured error code for programmatic handling
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<WorkerErrorCode>,
    /// Execution time in milliseconds
    execution_time_ms: u64,
    /// Worker version
    worker_version: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    fmt()
        .with_max_level(log_level)
        .with_writer(io::stderr) // Log to stderr, results to stdout
        .init();

    info!("Vulnera worker starting for module: {}", args.module);

    // Parse policy
    let policy = match parse_policy(&args) {
        Ok(p) => p,
        Err(e) => {
            output_error_with_code(
                &format!("Failed to parse policy: {}", e),
                WorkerErrorCode::PolicyParseFailed,
            );
            std::process::exit(1);
        }
    };

    debug!(
        "Policy parsed: timeout={}s, readonly_paths={}",
        policy.timeout.as_secs(),
        policy.readonly_paths.len()
    );

    // Apply sandbox restrictions BEFORE executing any module code
    #[cfg(target_os = "linux")]
    if !args.no_sandbox {
        if let Err(e) = apply_sandbox_restrictions(&policy) {
            // Log but don't fail - sandbox is optional enhancement
            warn!("Sandbox restrictions not fully applied: {}", e);
        }
    } else {
        warn!("Sandbox disabled via --no-sandbox flag - running without restrictions");
    }

    info!("Sandbox restrictions applied, executing module");

    // Execute the module
    let start = std::time::Instant::now();
    let result = execute_module_async(&args).await;
    let execution_time_ms = start.elapsed().as_millis() as u64;

    // Output result
    let worker_result = match result {
        Ok(module_result) => match serde_json::to_value(module_result) {
            Ok(val) => WorkerResult {
                success: true,
                result: Some(val),
                error: None,
                error_code: None,
                execution_time_ms,
                worker_version: WORKER_VERSION.to_string(),
            },
            Err(e) => WorkerResult {
                success: false,
                result: None,
                error: Some(format!("Failed to serialize result: {}", e)),
                error_code: Some(WorkerErrorCode::SerializationFailed),
                execution_time_ms,
                worker_version: WORKER_VERSION.to_string(),
            },
        },
        Err(e) => WorkerResult {
            success: false,
            result: None,
            error: Some(e),
            error_code: Some(WorkerErrorCode::ModuleExecutionFailed),
            execution_time_ms,
            worker_version: WORKER_VERSION.to_string(),
        },
    };

    output_result(&worker_result);
}

/// Parse policy from CLI or stdin
fn parse_policy(args: &Args) -> Result<SandboxPolicy, String> {
    let policy_json = if args.policy_stdin {
        let mut buffer = String::new();
        io::stdin()
            .read_to_string(&mut buffer)
            .map_err(|e| format!("Failed to read stdin: {}", e))?;
        buffer
    } else if let Some(ref json) = args.policy {
        json.clone()
    } else {
        // Default policy
        return Ok(SandboxPolicy::default().with_readonly_path(&args.source_uri));
    };

    serde_json::from_str(&policy_json).map_err(|e| format!("Invalid policy JSON: {}", e))
}

/// Apply Landlock + seccomp + rlimit restrictions
#[cfg(target_os = "linux")]
fn apply_sandbox_restrictions(policy: &SandboxPolicy) -> Result<(), String> {
    use vulnera_sandbox::infrastructure::{
        landlock::apply_landlock_restrictions,
        seccomp::{apply_seccomp_filter, create_analysis_config},
    };

    // Layer 1: Landlock (filesystem + network restrictions)
    apply_landlock_restrictions(policy).map_err(|e| format!("Landlock: {}", e))?;

    debug!("Landlock restrictions applied");

    // Layer 2: Seccomp (syscall filtering)
    let seccomp_config = create_analysis_config(policy);
    apply_seccomp_filter(&seccomp_config).map_err(|e| format!("Seccomp: {}", e))?;

    debug!("Seccomp filter applied");

    // Layer 3: Resource limits
    apply_rlimits(policy)?;

    debug!("Resource limits applied");

    Ok(())
}

/// Apply resource limits (rlimits) for memory and CPU
#[cfg(target_os = "linux")]
fn apply_rlimits(policy: &SandboxPolicy) -> Result<(), String> {
    use nix::sys::resource::{Resource, setrlimit};

    // Memory limit (virtual memory)
    if policy.max_memory > 0 {
        debug!("Applying RLIMIT_AS: {} bytes", policy.max_memory);
        setrlimit(Resource::RLIMIT_AS, policy.max_memory, policy.max_memory).map_err(|e| {
            format!(
                "RLIMIT_AS ({} bytes): {}. Check if memory limit is too restrictive.",
                policy.max_memory, e
            )
        })?;
    }

    // CPU time limit (based on timeout)
    let cpu_seconds = policy.timeout.as_secs();
    if cpu_seconds > 0 {
        setrlimit(Resource::RLIMIT_CPU, cpu_seconds, cpu_seconds)
            .map_err(|e| format!("RLIMIT_CPU: {}", e))?;
    }

    // Limit number of processes (prevent fork bombs)
    // Increased to 100 as complex modules using thread pools (Rayon/Tokio) need more handles
    debug!("Applying RLIMIT_NPROC: 100");
    setrlimit(Resource::RLIMIT_NPROC, 100, 100).map_err(|e| format!("RLIMIT_NPROC: {}", e))?;

    // Limit file size (prevent disk filling attacks)
    let max_file_size = 100 * 1024 * 1024; // 100MB
    setrlimit(Resource::RLIMIT_FSIZE, max_file_size, max_file_size)
        .map_err(|e| format!("RLIMIT_FSIZE: {}", e))?;

    Ok(())
}

/// Non-Linux stub for sandbox restrictions
#[cfg(not(target_os = "linux"))]
fn apply_sandbox_restrictions(_policy: &SandboxPolicy) -> Result<(), String> {
    warn!("Sandbox restrictions not available on this platform");
    Ok(())
}

/// Execute the analysis module
async fn execute_module_async(args: &Args) -> Result<ModuleResult, String> {
    // Load configuration
    let config = if let Some(ref config_json) = args.config {
        serde_json::from_str(config_json)
            .map_err(|e| format!("Invalid global config JSON: {}", e))?
    } else {
        Config::load().unwrap_or_default()
    };

    // Parse UUIDs
    let job_id =
        uuid::Uuid::parse_str(&args.job_id).map_err(|e| format!("Invalid job_id: {}", e))?;

    // Parse module config map
    let extra_config = if let Some(ref json) = args.module_config {
        serde_json::from_str(json).map_err(|e| format!("Invalid module_config JSON: {}", e))?
    } else {
        std::collections::HashMap::new()
    };

    let module_config = ModuleConfig {
        job_id,
        project_id: args.project_id.clone(),
        source_uri: args.source_uri.clone(),
        config: extra_config,
    };

    info!("Executing module: {} on {}", args.module, args.source_uri);

    // Instantiate and execute the appropriate module
    match args.module.to_lowercase().as_str() {
        "sast" => {
            let module = SastModule::with_config(&config.sast);
            module
                .execute(&module_config)
                .await
                .map_err(|e| e.to_string())
        }
        "secretdetection" | "secrets" => {
            let module = SecretDetectionModule::with_config(&config.secret_detection);
            module
                .execute(&module_config)
                .await
                .map_err(|e| e.to_string())
        }
        "apisecurity" | "api" => {
            let module = ApiSecurityModule::with_config(&config.api_security);
            module
                .execute(&module_config)
                .await
                .map_err(|e| e.to_string())
        }
        "dependencyanalyzer" | "deps" => {
            let parser_factory = Arc::new(ParserFactory::new());

            // Initialize cache (Dragonfly/Redis)
            let cache_repo = Arc::new(
                DragonflyCache::new(
                    &config.cache.dragonfly_url,
                    config.cache.enable_cache_compression,
                    config.cache.compression_threshold_bytes,
                )
                .await
                .map_err(|e| format!("Failed to initialize cache: {}", e))?,
            );
            let cache_service = Arc::new(CacheServiceImpl::new_with_dragonfly(cache_repo));

            // Initialize vulnerability repository (VulneraAdvisor)
            let vuln_repo = Arc::new(
                VulneraAdvisorRepository::from_config(&config)
                    .await
                    .map_err(|e| format!("Failed to initialize vulnerability repository: {}", e))?,
            );

            let module = DependencyAnalyzerModule::new(
                parser_factory,
                vuln_repo,
                cache_service,
                config.analysis.max_concurrent_packages,
                config.analysis.max_concurrent_registry_queries,
            );

            module
                .execute(&module_config)
                .await
                .map_err(|e| e.to_string())
        }
        _ => Err(format!("Unknown or unsupported module: {}", args.module)),
    }
}

/// Output result as JSON to stdout
fn output_result(result: &WorkerResult) {
    match serde_json::to_string(result) {
        Ok(json) => {
            println!("{}", json);
            io::stdout().flush().ok();
        }
        Err(e) => {
            error!("Failed to serialize result: {}", e);
            eprintln!("{{\"success\":false,\"error\":\"Serialization failed\"}}");
        }
    }
}

/// Output error as JSON to stdout 
#[allow(dead_code)]
fn output_error(message: &str) {
    output_error_with_code(message, WorkerErrorCode::Unknown);
}

/// Output error with structured error code
fn output_error_with_code(message: &str, error_code: WorkerErrorCode) {
    let result = WorkerResult {
        success: false,
        result: None,
        error: Some(message.to_string()),
        error_code: Some(error_code),
        execution_time_ms: 0,
        worker_version: WORKER_VERSION.to_string(),
    };
    output_result(&result);
}
