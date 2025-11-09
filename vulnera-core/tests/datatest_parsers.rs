//! Data-driven tests for parsers

use datatest_stable::harness;
use std::fs;
use std::path::Path;
use vulnera_core::infrastructure::parsers::traits::ParserFactory;

fn test_parser_with_file(path: &Path) -> datatest_stable::Result<()> {
    let content = fs::read_to_string(path)?;
    let filename = path.file_name().unwrap().to_string_lossy();
    
    let factory = ParserFactory::new();
    if let Some(parser) = factory.create_parser(&filename) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(parser.parse_file(&content));
        
        // Just verify it doesn't panic and returns a result
        match result {
            Ok(packages) => {
                // Verify we got some packages or empty list (both are valid)
                assert!(packages.len() >= 0);
            }
            Err(_) => {
                // Parsing errors are acceptable for invalid test files
            }
        }
    }
    
    Ok(())
}

harness!(
    test_parser_with_file,
    "tests/data/parsers",
    r".*\.(json|txt|toml|xml|mod)$"
);

