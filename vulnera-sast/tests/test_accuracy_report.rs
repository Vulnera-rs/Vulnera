//! Accuracy Report Test
//!
//! Discovers all YAML fixtures, runs them through the fixture runner,
//! accumulates precision/recall/F1 metrics per language, and asserts CI gate thresholds.
//!
//! This test provides the Phase 4.4 accuracy visibility:
//! - Per-language breakdown (TP, TN, FP, FN, P, R, F1)
//! - Aggregate totals
//! - CI gate: aggregate precision ≥ 0.70, recall ≥ 0.50
//!   (thresholds intentionally lenient during initial ramp-up — tighten as rules mature)

mod common;

use common::accuracy::AccuracyReport;
use common::fixture_runner;
use common::fixture_types::CveFixture;
use std::path::PathBuf;
use vulnera_core::config::{AnalysisDepth, SastConfig};
use vulnera_sast::{AnalysisConfig, ScanProjectUseCase};

/// Discover all YAML fixture files under `tests/data/cve-fixtures/`.
fn discover_fixtures() -> Vec<PathBuf> {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/cve-fixtures");
    if !base.exists() {
        return Vec::new();
    }

    walkdir::WalkDir::new(&base)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_type().is_file()
                && e.path()
                    .extension()
                    .is_some_and(|ext| ext == "yaml" || ext == "yml")
        })
        .map(|e| e.into_path())
        .collect()
}

fn read_linux_status_value_kb(field_name: &str) -> Option<u64> {
    if !cfg!(target_os = "linux") {
        return None;
    }

    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        if !line.starts_with(field_name) {
            return None;
        }

        let value_kb = line
            .split_whitespace()
            .nth(1)
            .and_then(|v| v.parse::<u64>().ok());
        value_kb
    })
}

#[tokio::test]
async fn accuracy_report_all_fixtures() {
    let fixture_paths = discover_fixtures();
    if fixture_paths.is_empty() {
        eprintln!("⚠ No fixtures found — skipping accuracy report");
        return;
    }

    let quality_gates = SastConfig::default().quality_gates;
    let mut report = AccuracyReport::new();
    let mut fixture_failures: Vec<String> = Vec::new();
    let mut covered_cwes: std::collections::HashSet<String> = std::collections::HashSet::new();

    for path in &fixture_paths {
        let fixture = match CveFixture::from_file(path) {
            Ok(f) => f,
            Err(e) => {
                fixture_failures.push(format!("PARSE ERROR {}: {e}", path.display()));
                continue;
            }
        };

        for cwe in &fixture.cwe {
            covered_cwes.insert(cwe.trim().to_string());
        }

        let result = fixture_runner::run_fixture(&fixture).await;
        let metrics = report.metrics_for(&fixture.language);
        result.accumulate_metrics(metrics);

        // Collect individual case failures for diagnostic output
        for case in &result.case_results {
            if let Some(ref msg) = case.failure {
                fixture_failures.push(format!("[{}] {msg}", fixture.id));
            }
        }
    }

    // Print the report unconditionally for CI visibility
    eprintln!("\n{report}");

    // Print individual failures for debugging
    if !fixture_failures.is_empty() {
        eprintln!("─── Case-level failures ({}) ───", fixture_failures.len());
        for f in &fixture_failures {
            eprintln!("  • {f}");
        }
        eprintln!("────────────────────────────────");
    }

    // Aggregate metrics
    let agg = report.aggregate();
    let precision = agg.precision().unwrap_or(0.0);
    let recall = agg.recall().unwrap_or(0.0);
    let f1 = agg.f1().unwrap_or(0.0);

    eprintln!(
        "\nAggregate: Precision={precision:.3} Recall={recall:.3} F1={f1:.3} (TP={} TN={} FP={} FN={})",
        agg.true_positives, agg.true_negatives, agg.false_positives, agg.false_negatives
    );
    eprintln!("CWE coverage: {} unique IDs", covered_cwes.len());

    // CI Gate thresholds are centralized in SastConfig::quality_gates and can be
    // tightened over time without changing test logic.
    let min_precision = quality_gates.min_precision;
    let min_recall = quality_gates.min_recall;

    assert!(
        precision >= min_precision,
        "CI GATE: Aggregate precision {precision:.3} < {min_precision} threshold"
    );
    assert!(
        recall >= min_recall,
        "CI GATE: Aggregate recall {recall:.3} < {min_recall} threshold"
    );
    assert!(
        covered_cwes.len() >= quality_gates.min_cwe_coverage,
        "CI GATE: CWE coverage {} < {} threshold",
        covered_cwes.len(),
        quality_gates.min_cwe_coverage
    );

    if quality_gates.enforce_primary_language_gates {
        let python = report
            .per_language
            .get("python")
            .expect("CI GATE: missing Python fixtures/metrics in accuracy report");
        let python_precision = python.precision().unwrap_or(0.0);
        let python_recall = python.recall().unwrap_or(0.0);

        assert!(
            python_precision >= quality_gates.python_min_precision,
            "CI GATE: Python precision {python_precision:.3} < {:.3}",
            quality_gates.python_min_precision
        );
        assert!(
            python_recall >= quality_gates.python_min_recall,
            "CI GATE: Python recall {python_recall:.3} < {:.3}",
            quality_gates.python_min_recall
        );

        let js = report.per_language.get("javascript");
        let ts = report.per_language.get("typescript");

        let js_ts_tp =
            js.map_or(0usize, |m| m.true_positives) + ts.map_or(0usize, |m| m.true_positives);
        let js_ts_fp =
            js.map_or(0usize, |m| m.false_positives) + ts.map_or(0usize, |m| m.false_positives);
        let js_ts_fn =
            js.map_or(0usize, |m| m.false_negatives) + ts.map_or(0usize, |m| m.false_negatives);

        let js_ts_precision = if js_ts_tp + js_ts_fp == 0 {
            0.0
        } else {
            js_ts_tp as f64 / (js_ts_tp + js_ts_fp) as f64
        };
        let js_ts_recall = if js_ts_tp + js_ts_fn == 0 {
            0.0
        } else {
            js_ts_tp as f64 / (js_ts_tp + js_ts_fn) as f64
        };

        assert!(
            js_ts_tp + js_ts_fp + js_ts_fn > 0,
            "CI GATE: missing JavaScript/TypeScript fixtures for primary language gate"
        );

        eprintln!(
            "Primary language gates: python(P={:.3},R={:.3}) js_ts(P={:.3},R={:.3})",
            python_precision, python_recall, js_ts_precision, js_ts_recall
        );

        assert!(
            js_ts_precision >= quality_gates.js_ts_min_precision,
            "CI GATE: JS/TS precision {js_ts_precision:.3} < {:.3}",
            quality_gates.js_ts_min_precision
        );
        assert!(
            js_ts_recall >= quality_gates.js_ts_min_recall,
            "CI GATE: JS/TS recall {js_ts_recall:.3} < {:.3}",
            quality_gates.js_ts_min_recall
        );
    }

    // Soft check: warn (but don't fail) if any single language is below threshold
    for (lang, metrics) in &report.per_language {
        let p = metrics.precision().unwrap_or(0.0);
        let r = metrics.recall().unwrap_or(0.0);
        if p < min_precision || r < min_recall {
            eprintln!(
                "⚠ Language '{lang}' below threshold: P={p:.3} R={r:.3} (target P≥{min_precision} R≥{min_recall})"
            );
        }
    }
}

#[tokio::test]
async fn accuracy_report_has_minimum_fixture_coverage() {
    let fixture_paths = discover_fixtures();

    // We expect at least fixtures for the primary languages
    assert!(
        fixture_paths.len() >= 5,
        "Expected at least 5 fixture files, found {}. \
         Ensure tests/data/cve-fixtures/ is populated.",
        fixture_paths.len()
    );

    // Verify fixture diversity: at least 3 different languages represented
    let languages: std::collections::HashSet<String> = fixture_paths
        .iter()
        .filter_map(|p| {
            CveFixture::from_file(p)
                .ok()
                .map(|f| f.language.to_lowercase())
        })
        .collect();

    assert!(
        languages.len() >= 3,
        "Expected fixtures covering at least 3 languages, found {}: {:?}",
        languages.len(),
        languages
    );
}

#[test]
fn accuracy_metrics_unit_test_aggregation() {
    // Unit test for the AccuracyReport aggregation without running the full scanner
    let mut report = AccuracyReport::new();

    let py = report.metrics_for("python");
    py.true_positives = 10;
    py.true_negatives = 5;
    py.false_positives = 1;
    py.false_negatives = 2;

    let js = report.metrics_for("javascript");
    js.true_positives = 8;
    js.true_negatives = 6;
    js.false_positives = 0;
    js.false_negatives = 3;

    let agg = report.aggregate();
    assert_eq!(agg.true_positives, 18);
    assert_eq!(agg.true_negatives, 11);
    assert_eq!(agg.false_positives, 1);
    assert_eq!(agg.false_negatives, 5);

    // P = 18/(18+1) ≈ 0.947
    assert!((agg.precision().unwrap() - 18.0 / 19.0).abs() < 0.001);
    // R = 18/(18+5) ≈ 0.783
    assert!((agg.recall().unwrap() - 18.0 / 23.0).abs() < 0.001);
}

#[tokio::test]
async fn incremental_scan_latency_quality_gate() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let state_path = temp_dir.path().join("incremental-state.json");

    // Create a moderately-sized synthetic repo to exercise incremental skipping.
    for idx in 0..120usize {
        let file_path = temp_dir.path().join(format!("module_{idx}.py"));
        std::fs::write(
            &file_path,
            format!(
                "def fn_{idx}(x):\n    y = x + 1\n    return y\n\nvalue_{idx} = fn_{idx}(41)\n"
            ),
        )
        .expect("Failed to write synthetic source file");
    }

    let sast_config = SastConfig {
        analysis_depth: AnalysisDepth::Quick,
        enable_data_flow: false,
        enable_call_graph: false,
        enable_incremental: Some(true),
        incremental_state_path: Some(state_path),
        ..Default::default()
    };
    let quality_gates = sast_config.quality_gates.clone();

    let first_use_case =
        ScanProjectUseCase::with_config(&sast_config, AnalysisConfig::from(&sast_config));

    let first = first_use_case
        .execute(temp_dir.path())
        .await
        .expect("First scan should succeed");
    // Create a fresh use-case so incremental state is reloaded from disk and becomes
    // the previous-state baseline for the second run.
    let second_use_case =
        ScanProjectUseCase::with_config(&sast_config, AnalysisConfig::from(&sast_config));
    let second = second_use_case
        .execute(temp_dir.path())
        .await
        .expect("Second scan should succeed");

    let ratio = if first.duration_ms == 0 {
        0.0
    } else {
        second.duration_ms as f64 / first.duration_ms as f64
    };

    eprintln!(
        "Incremental timing: first={}ms second={}ms ratio={:.3}",
        first.duration_ms, second.duration_ms, ratio
    );

    assert!(
        second.files_skipped >= first.files_scanned.saturating_sub(1),
        "Expected second incremental scan to skip most files. first_scanned={}, second_skipped={}",
        first.files_scanned,
        second.files_skipped
    );

    assert!(
        ratio <= quality_gates.max_incremental_duration_ratio,
        "CI GATE: incremental scan ratio {:.3} exceeds threshold {:.3}",
        ratio,
        quality_gates.max_incremental_duration_ratio
    );
}

#[tokio::test]
async fn deep_scan_memory_budget_quality_gate() {
    if !cfg!(target_os = "linux") {
        eprintln!("⚠ deep_scan_memory_budget_quality_gate skipped: non-Linux target");
        return;
    }

    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");

    // Build a moderate synthetic project to exercise deep-scan memory behavior.
    for idx in 0..180usize {
        let file_path = temp_dir.path().join(format!("deep_{idx}.py"));
        std::fs::write(
            &file_path,
            format!(
                "import os\n\ndef source_{idx}():\n    return os.environ.get('USER_INPUT')\n\ndef sink_{idx}(v):\n    eval(v)\n\nx_{idx} = source_{idx}()\nsink_{idx}(x_{idx})\n"
            ),
        )
        .expect("Failed to write deep scan fixture file");
    }

    let sast_config = SastConfig {
        analysis_depth: AnalysisDepth::Deep,
        enable_data_flow: true,
        enable_call_graph: true,
        ..Default::default()
    };
    let quality_gates = sast_config.quality_gates.clone();

    let baseline_rss_kb = read_linux_status_value_kb("VmRSS:").unwrap_or(0);

    let use_case =
        ScanProjectUseCase::with_config(&sast_config, AnalysisConfig::from(&sast_config));
    let result = use_case
        .execute(temp_dir.path())
        .await
        .expect("Deep scan should succeed");

    let final_rss_kb = read_linux_status_value_kb("VmRSS:").unwrap_or(0);
    let peak_hwm_kb = read_linux_status_value_kb("VmHWM:").unwrap_or(final_rss_kb);

    let baseline_rss_mb = baseline_rss_kb as f64 / 1024.0;
    let final_rss_mb = final_rss_kb as f64 / 1024.0;
    let peak_hwm_mb = peak_hwm_kb as f64 / 1024.0;
    let delta_rss_mb = ((final_rss_kb.saturating_sub(baseline_rss_kb)) as f64) / 1024.0;

    eprintln!(
        "Deep memory gate: scanned={} findings={} baseline_rss={:.1}MB final_rss={:.1}MB delta={:.1}MB peak_hwm={:.1}MB budget={}MB",
        result.files_scanned,
        result.findings.len(),
        baseline_rss_mb,
        final_rss_mb,
        delta_rss_mb,
        peak_hwm_mb,
        quality_gates.max_resident_memory_mb
    );

    assert!(
        peak_hwm_mb <= quality_gates.max_resident_memory_mb as f64,
        "CI GATE: peak resident memory {:.1}MB exceeds threshold {}MB",
        peak_hwm_mb,
        quality_gates.max_resident_memory_mb
    );
}
