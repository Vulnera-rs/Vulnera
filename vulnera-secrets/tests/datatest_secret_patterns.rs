//! Data-driven tests for secret patterns
// cspell:ignore datatest
use std::fs;
use std::path::Path;
use vulnera_secrets::infrastructure::detectors::RegexDetector;
use vulnera_secrets::infrastructure::rules::RuleRepository;

fn test_secret_pattern_with_file(path: &Path) -> datatest_stable::Result<()> {
    let content = fs::read_to_string(path)?;

    // Initialize detector with default rules
    let rule_repo = RuleRepository::new();
    let rules = rule_repo.get_all_rules().to_vec();
    let detector = RegexDetector::new(rules);

    let mut findings = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let matches = detector.detect_line(line, (i + 1) as u32);
        findings.extend(matches);
    }

    // Assert that we found at least one secret
    // This assumes all files in the data directory are positive test cases
    if findings.is_empty() {
        panic!("No secrets found in file: {}", path.display());
    }

    // Optional: Check specific rules based on filename
    let filename = path.file_name().unwrap().to_string_lossy();
    if filename.contains("aws") {
        assert!(
            findings.iter().any(|f| f.rule_id.contains("aws")),
            "Should find AWS secrets in {}",
            filename
        );
    } else if filename.contains("generic") {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.contains("api-key") || f.rule_id.contains("generic")),
            "Should find API keys in {}",
            filename
        );
    }

    Ok(())
}

#[test]
fn debug_paths() {
    let cwd = std::env::current_dir().unwrap();
    println!("Current directory: {:?}", cwd);
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    println!("CARGO_MANIFEST_DIR: {:?}", manifest_dir);

    let path = Path::new("tests/data/secrets");
    println!("Path exists: {}", path.exists());
    if path.exists() {
        for entry in fs::read_dir(path).unwrap() {
            println!("Entry: {:?}", entry.unwrap().path());
        }
    }
}

datatest_stable::harness! {
    { test = test_secret_pattern_with_file, root = "tests/data/secrets", pattern = r"^.*$" },
}
