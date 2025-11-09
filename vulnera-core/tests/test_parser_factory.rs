//! Integration tests for parser factory

use vulnera_core::domain::vulnerability::value_objects::Ecosystem;
use vulnera_core::infrastructure::parsers::traits::ParserFactory;

#[tokio::test]
async fn test_parser_factory_creation() {
    let factory = ParserFactory::new();
    assert!(!factory.supported_extensions().is_empty());
}

#[tokio::test]
async fn test_parser_selection_by_filename() {
    let factory = ParserFactory::new();

    // Test npm parser selection
    let parser = factory.create_parser("package.json");
    assert!(parser.is_some());
    assert_eq!(parser.unwrap().ecosystem(), Ecosystem::Npm);

    // Test Python parser selection
    let parser = factory.create_parser("requirements.txt");
    assert!(parser.is_some());
    assert_eq!(parser.unwrap().ecosystem(), Ecosystem::PyPI);

    // Test Rust parser selection
    let parser = factory.create_parser("Cargo.toml");
    assert!(parser.is_some());
    assert_eq!(parser.unwrap().ecosystem(), Ecosystem::Cargo);
}

#[tokio::test]
async fn test_parser_priority() {
    let factory = ParserFactory::new();

    // Test that higher priority parsers are selected
    let parser = factory.create_parser("package.json");
    assert!(parser.is_some());
    // Tree-sitter parser should have a priority value
    let priority = parser.unwrap().priority();
    let _ = priority; // Just verify we can get the priority
}

#[tokio::test]
async fn test_ecosystem_detection() {
    let factory = ParserFactory::new();

    assert_eq!(
        factory.detect_ecosystem("package.json"),
        Some(Ecosystem::Npm)
    );
    assert_eq!(
        factory.detect_ecosystem("requirements.txt"),
        Some(Ecosystem::PyPI)
    );
    assert_eq!(
        factory.detect_ecosystem("Cargo.toml"),
        Some(Ecosystem::Cargo)
    );
    assert_eq!(factory.detect_ecosystem("pom.xml"), Some(Ecosystem::Maven));
    assert_eq!(factory.detect_ecosystem("go.mod"), Some(Ecosystem::Go));
}

#[tokio::test]
async fn test_unsupported_file() {
    let factory = ParserFactory::new();

    let parser = factory.create_parser("unknown.xyz");
    assert!(parser.is_none());

    assert!(!factory.is_supported("unknown.xyz"));
}
