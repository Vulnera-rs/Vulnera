use std::path::PathBuf;
use std::time::Instant;

use vulnera_core::config::{AnalysisDepth, SastConfig};
use vulnera_sast::application::use_cases::{AnalysisConfig, ScanProjectUseCase};

#[derive(Debug, Clone)]
struct BenchmarkMetrics {
    avg_ms: f64,
    p95_ms: u128,
    files_per_sec: f64,
    findings_per_sec: f64,
    avg_files_scanned: f64,
    avg_findings: f64,
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("benchmark failed: {err}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let target = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "usage: cargo run -p vulnera-sast --example scale_benchmark -- <path> [iterations] [depth: quick|standard|deep]".to_string())?;

    if !target.exists() {
        return Err(format!("target path does not exist: {}", target.display()));
    }

    let iterations = args
        .next()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(3)
        .max(1);

    let depth = args
        .next()
        .as_deref()
        .map(parse_depth)
        .transpose()?
        .unwrap_or(AnalysisDepth::Standard);

    let cpu_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let baseline_parallelism = 1usize;
    let tuned_parallelism = (cpu_threads * 2).clamp(2, 32);

    println!("== vulnera-sast scale benchmark ==");
    println!("target={}", target.display());
    println!("iterations={iterations}");
    println!("depth={depth:?}");
    println!("cpu_threads={cpu_threads}");
    println!("baseline_parallelism={baseline_parallelism}");
    println!("tuned_parallelism={tuned_parallelism}");

    let baseline = benchmark_profile(
        "baseline",
        &target,
        iterations,
        depth,
        baseline_parallelism,
    )
    .await?;

    let tuned = benchmark_profile("tuned", &target, iterations, depth, tuned_parallelism).await?;

    let speedup = if tuned.avg_ms > 0.0 {
        baseline.avg_ms / tuned.avg_ms
    } else {
        0.0
    };

    println!("\n== summary ==");
    print_metrics("baseline", &baseline);
    print_metrics("tuned", &tuned);
    println!("speedup={speedup:.2}x");

    Ok(())
}

fn parse_depth(input: &str) -> Result<AnalysisDepth, String> {
    match input.trim().to_ascii_lowercase().as_str() {
        "quick" => Ok(AnalysisDepth::Quick),
        "standard" => Ok(AnalysisDepth::Standard),
        "deep" => Ok(AnalysisDepth::Deep),
        other => Err(format!("invalid depth: {other}")),
    }
}

async fn benchmark_profile(
    profile_name: &str,
    target: &PathBuf,
    iterations: usize,
    depth: AnalysisDepth,
    max_concurrent_files: usize,
) -> Result<BenchmarkMetrics, String> {
    let mut sast_config = SastConfig {
        analysis_depth: depth,
        max_concurrent_files: Some(max_concurrent_files),
        dynamic_depth_enabled: Some(false),
        ..SastConfig::default()
    };

    if matches!(depth, AnalysisDepth::Quick) {
        sast_config.enable_data_flow = false;
        sast_config.enable_call_graph = false;
    }

    let analysis_config = AnalysisConfig::from(&sast_config);
    let use_case = ScanProjectUseCase::with_config(&sast_config, analysis_config);

    let mut durations: Vec<u128> = Vec::with_capacity(iterations);
    let mut total_files_scanned = 0usize;
    let mut total_findings = 0usize;

    println!("\n-- profile={profile_name} --");

    for i in 0..iterations {
        let start = Instant::now();
        let result = use_case
            .execute(target)
            .await
            .map_err(|e| format!("scan failed: {e}"))?;
        let elapsed = start.elapsed().as_millis();

        durations.push(elapsed);
        total_files_scanned += result.files_scanned;
        total_findings += result.findings.len();

        println!(
            "run={} duration_ms={} files_scanned={} findings={} files_failed={} errors={}",
            i + 1,
            elapsed,
            result.files_scanned,
            result.findings.len(),
            result.files_failed,
            result.errors.len()
        );
    }

    durations.sort_unstable();

    let avg_ms = durations.iter().copied().map(|v| v as f64).sum::<f64>() / iterations as f64;
    let p95_index = ((iterations as f64) * 0.95).ceil() as usize;
    let p95_ms = durations[p95_index.saturating_sub(1).min(durations.len().saturating_sub(1))];

    let avg_files_scanned = total_files_scanned as f64 / iterations as f64;
    let avg_findings = total_findings as f64 / iterations as f64;
    let files_per_sec = if avg_ms > 0.0 {
        (avg_files_scanned * 1000.0) / avg_ms
    } else {
        0.0
    };
    let findings_per_sec = if avg_ms > 0.0 {
        (avg_findings * 1000.0) / avg_ms
    } else {
        0.0
    };

    Ok(BenchmarkMetrics {
        avg_ms,
        p95_ms,
        files_per_sec,
        findings_per_sec,
        avg_files_scanned,
        avg_findings,
    })
}

fn print_metrics(name: &str, m: &BenchmarkMetrics) {
    println!(
        "profile={} avg_ms={:.2} p95_ms={} avg_files_scanned={:.2} avg_findings={:.2} files_per_sec={:.2} findings_per_sec={:.2}",
        name,
        m.avg_ms,
        m.p95_ms,
        m.avg_files_scanned,
        m.avg_findings,
        m.files_per_sec,
        m.findings_per_sec
    );
}
