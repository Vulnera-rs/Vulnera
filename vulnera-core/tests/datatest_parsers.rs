//! Data-driven tests for parsers
// cspell:ignore datatest vulnera

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
            Ok(parse_result) => {
                // Verify we got a result (empty list is also valid)
                let _ = parse_result.packages.len();
            }
            Err(_) => {
                // Parsing errors are acceptable for invalid test files
            }
        }
    }

    Ok(())
}

datatest_stable::harness! {
    { test = test_parser_with_file, root = "tests/data/parsers", pattern = r".*\.(json|txt|toml|xml|mod)$" },
}
