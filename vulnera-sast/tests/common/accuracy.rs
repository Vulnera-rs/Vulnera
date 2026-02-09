//! Precision / Recall / F1 computation for SAST accuracy measurement.

#![allow(dead_code)]

use std::collections::HashMap;
use std::fmt;

/// Outcome of a single test case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseOutcome {
    /// Vulnerable code correctly detected
    TruePositive,
    /// Safe code correctly passed (no findings)
    TrueNegative,
    /// Safe code incorrectly flagged
    FalsePositive,
    /// Vulnerable code missed
    FalseNegative,
}

/// Per-language accuracy counters.
#[derive(Debug, Default, Clone)]
pub struct LanguageMetrics {
    pub language: String,
    pub true_positives: usize,
    pub true_negatives: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
}

impl LanguageMetrics {
    pub fn new(language: &str) -> Self {
        Self {
            language: language.to_string(),
            ..Default::default()
        }
    }

    /// Total test cases.
    pub fn total(&self) -> usize {
        self.true_positives + self.true_negatives + self.false_positives + self.false_negatives
    }

    /// Precision = TP / (TP + FP). Returns None if denominator is zero.
    pub fn precision(&self) -> Option<f64> {
        let denom = self.true_positives + self.false_positives;
        if denom == 0 {
            None
        } else {
            Some(self.true_positives as f64 / denom as f64)
        }
    }

    /// Recall = TP / (TP + FN). Returns None if denominator is zero.
    pub fn recall(&self) -> Option<f64> {
        let denom = self.true_positives + self.false_negatives;
        if denom == 0 {
            None
        } else {
            Some(self.true_positives as f64 / denom as f64)
        }
    }

    /// F1 = 2 * (P * R) / (P + R). Returns None if P or R is undefined.
    pub fn f1(&self) -> Option<f64> {
        let p = self.precision()?;
        let r = self.recall()?;
        if p + r == 0.0 {
            Some(0.0)
        } else {
            Some(2.0 * p * r / (p + r))
        }
    }

    /// Check if metrics meet CI gate thresholds.
    pub fn meets_threshold(&self, min_precision: f64, min_recall: f64) -> bool {
        let p = self.precision().unwrap_or(0.0);
        let r = self.recall().unwrap_or(0.0);
        p >= min_precision && r >= min_recall
    }
}

impl fmt::Display for LanguageMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<12} | TP={:<3} TN={:<3} FP={:<3} FN={:<3} | P={:.2} R={:.2} F1={:.2}",
            self.language,
            self.true_positives,
            self.true_negatives,
            self.false_positives,
            self.false_negatives,
            self.precision().unwrap_or(0.0),
            self.recall().unwrap_or(0.0),
            self.f1().unwrap_or(0.0),
        )
    }
}

/// Aggregate accuracy report across all languages.
#[derive(Debug, Default)]
pub struct AccuracyReport {
    pub per_language: HashMap<String, LanguageMetrics>,
}

impl AccuracyReport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create metrics for a language.
    pub fn metrics_for(&mut self, language: &str) -> &mut LanguageMetrics {
        self.per_language
            .entry(language.to_lowercase())
            .or_insert_with(|| LanguageMetrics::new(language))
    }

    /// Aggregate totals across all languages.
    pub fn aggregate(&self) -> LanguageMetrics {
        let mut agg = LanguageMetrics::new("TOTAL");
        for m in self.per_language.values() {
            agg.true_positives += m.true_positives;
            agg.true_negatives += m.true_negatives;
            agg.false_positives += m.false_positives;
            agg.false_negatives += m.false_negatives;
        }
        agg
    }

    /// Check if ALL languages meet the CI gate thresholds.
    pub fn all_meet_threshold(&self, min_precision: f64, min_recall: f64) -> bool {
        self.per_language
            .values()
            .all(|m| m.meets_threshold(min_precision, min_recall))
    }
}

impl fmt::Display for AccuracyReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "╔══════════════════════════════════════════════════════════════════════╗")?;
        writeln!(f, "║                    SAST Accuracy Report                             ║")?;
        writeln!(f, "╠══════════════════════════════════════════════════════════════════════╣")?;
        writeln!(
            f,
            "║ {:<12} | {:<24} | {:<24} ║",
            "Language", "TP  TN  FP  FN", "P     R     F1"
        )?;
        writeln!(f, "╠══════════════════════════════════════════════════════════════════════╣")?;

        let mut languages: Vec<_> = self.per_language.keys().collect();
        languages.sort();

        for lang in languages {
            let m = &self.per_language[lang];
            writeln!(
                f,
                "║ {:<12} | TP={:<3} TN={:<3} FP={:<3} FN={:<3} | P={:.2} R={:.2} F1={:.2} ║",
                m.language,
                m.true_positives,
                m.true_negatives,
                m.false_positives,
                m.false_negatives,
                m.precision().unwrap_or(0.0),
                m.recall().unwrap_or(0.0),
                m.f1().unwrap_or(0.0),
            )?;
        }

        writeln!(f, "╠══════════════════════════════════════════════════════════════════════╣")?;
        let agg = self.aggregate();
        writeln!(
            f,
            "║ {:<12} | TP={:<3} TN={:<3} FP={:<3} FN={:<3} | P={:.2} R={:.2} F1={:.2} ║",
            "TOTAL",
            agg.true_positives,
            agg.true_negatives,
            agg.false_positives,
            agg.false_negatives,
            agg.precision().unwrap_or(0.0),
            agg.recall().unwrap_or(0.0),
            agg.f1().unwrap_or(0.0),
        )?;
        writeln!(f, "╚══════════════════════════════════════════════════════════════════════╝")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::LanguageMetrics;

    #[test]
    fn test_perfect_precision_recall() {
        let m = LanguageMetrics {
            language: "python".to_string(),
            true_positives: 10,
            true_negatives: 5,
            false_positives: 0,
            false_negatives: 0,
        };
        assert_eq!(m.precision(), Some(1.0));
        assert_eq!(m.recall(), Some(1.0));
        assert_eq!(m.f1(), Some(1.0));
    }

    #[test]
    fn test_zero_division() {
        let m = LanguageMetrics::default();
        assert_eq!(m.precision(), None);
        assert_eq!(m.recall(), None);
    }

    #[test]
    fn test_partial_metrics() {
        let m = LanguageMetrics {
            language: "js".to_string(),
            true_positives: 8,
            true_negatives: 4,
            false_positives: 2,
            false_negatives: 1,
        };
        assert!((m.precision().unwrap() - 0.8).abs() < 0.01);
        assert!((m.recall().unwrap() - 8.0 / 9.0).abs() < 0.01);
    }

    #[test]
    fn test_meets_threshold() {
        let m = LanguageMetrics {
            language: "rust".to_string(),
            true_positives: 9,
            true_negatives: 5,
            false_positives: 1,
            false_negatives: 2,
        };
        // P=0.9, R≈0.818
        assert!(m.meets_threshold(0.85, 0.70));
        assert!(!m.meets_threshold(0.95, 0.70));
    }
}
