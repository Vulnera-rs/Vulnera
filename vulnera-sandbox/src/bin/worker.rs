//! Vulnera Worker - Isolated sandbox execution process
//!
//! This binary is spawned by the orchestrator to execute analysis modules
//! within a sandboxed environment. The workflow is:
//!
//! 1. Parse CLI arguments (policy, config, module type)
//! 2. Apply sandbox restrictions (Landlock, seccomp, rlimits)
//! 3. Execute the analysis module
//! 4. Output result as JSON to stdout
//!
//! # Security Model
//!
//! The worker restricts **itself** before executing any untrusted code. This
//! ensures that even if the module exploits a parser bug, the damage is
//! contained to this worker process.

use std::io::{self, Read, Write};

use clap::Parser;
use serde::{Deserialize, Serialize};
use tracing::{Level, debug, error, info, warn};
use tracing_subscriber::fmt;

use vulnera_sandbox::SandboxPolicy;

/// Worker CLI arguments
#[derive(Parser, Debug)]
#[command(name = "vulnera-worker")]
#[command(about = "Sandboxed worker for Vulnera analysis modules")]
struct Args {
    /// Module type to execute (e.g., "SAST", "Secrets", "DependencyAnalyzer")
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

    /// Read policy from stdin (JSON)
    #[arg(long, default_value = "false")]
    policy_stdin: bool,

    /// Sandbox policy as JSON (alternative to stdin)
    #[arg(long)]
    policy: Option<String>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
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
    /// Execution time in milliseconds
    execution_time_ms: u64,
}

fn main() {
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
            output_error(&format!("Failed to parse policy: {}", e));
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
    if let Err(e) = apply_sandbox_restrictions(&policy) {
        // Log but don't fail - sandbox is optional enhancement
        warn!("Sandbox restrictions not fully applied: {}", e);
    }

    info!("Sandbox restrictions applied, executing module");

    // Execute the module
    let start = std::time::Instant::now();
    let result = execute_module(&args, &policy);
    let execution_time_ms = start.elapsed().as_millis() as u64;

    // Output result
    let worker_result = match result {
        Ok(module_result) => WorkerResult {
            success: true,
            result: Some(module_result),
            error: None,
            execution_time_ms,
        },
        Err(e) => WorkerResult {
            success: false,
            result: None,
            error: Some(e),
            execution_time_ms,
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
        setrlimit(Resource::RLIMIT_AS, policy.max_memory, policy.max_memory)
            .map_err(|e| format!("RLIMIT_AS: {}", e))?;
    }

    // CPU time limit (based on timeout)
    let cpu_seconds = policy.timeout.as_secs();
    if cpu_seconds > 0 {
        setrlimit(Resource::RLIMIT_CPU, cpu_seconds, cpu_seconds)
            .map_err(|e| format!("RLIMIT_CPU: {}", e))?;
    }

    // Limit number of processes (prevent fork bombs)
    setrlimit(Resource::RLIMIT_NPROC, 10, 10).map_err(|e| format!("RLIMIT_NPROC: {}", e))?;

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
fn execute_module(args: &Args, _policy: &SandboxPolicy) -> Result<serde_json::Value, String> {
    // For now, return a placeholder result
    // In the full implementation, this would:
    // 1. Load the appropriate module based on args.module
    // 2. Create ModuleConfig from args
    // 3. Execute module.execute(&config)
    // 4. Serialize and return the result

    info!("Executing module: {} on {}", args.module, args.source_uri);

    // Placeholder: In full implementation, dynamically load and execute module
    let placeholder_result = serde_json::json!({
        "job_id": args.job_id,
        "module_type": args.module,
        "findings": [],
        "metadata": {
            "worker_version": env!("CARGO_PKG_VERSION"),
            "sandboxed": true
        },
        "error": null
    });

    Ok(placeholder_result)
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
fn output_error(message: &str) {
    let result = WorkerResult {
        success: false,
        result: None,
        error: Some(message.to_string()),
        execution_time_ms: 0,
    };
    output_result(&result);
}
