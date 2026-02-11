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

#[tokio::test]
async fn accuracy_report_all_fixtures() {
    let fixture_paths = discover_fixtures();
    if fixture_paths.is_empty() {
        eprintln!("⚠ No fixtures found — skipping accuracy report");
        return;
    }

    let mut report = AccuracyReport::new();
    let mut fixture_failures: Vec<String> = Vec::new();

    for path in &fixture_paths {
        let fixture = match CveFixture::from_file(path) {
            Ok(f) => f,
            Err(e) => {
                fixture_failures.push(format!("PARSE ERROR {}: {e}", path.display()));
                continue;
            }
        };

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

    // CI Gate thresholds — lenient during bootstrap, tighten over time:
    //   Phase 4 initial: P ≥ 0.70, R ≥ 0.50
    //   Phase 5 target:  P ≥ 0.85, R ≥ 0.70
    //   Phase 6 target:  P ≥ 0.90, R ≥ 0.80
    let min_precision = 0.70;
    let min_recall = 0.50;

    assert!(
        precision >= min_precision,
        "CI GATE: Aggregate precision {precision:.3} < {min_precision} threshold"
    );
    assert!(
        recall >= min_recall,
        "CI GATE: Aggregate recall {recall:.3} < {min_recall} threshold"
    );

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
