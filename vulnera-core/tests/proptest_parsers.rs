//! Property-based tests for parsers

use proptest::prelude::*;
use vulnera_core::infrastructure::parsers::traits::ParserFactory;

proptest! {
    #[test]
    fn test_package_json_parsing_doesnt_crash(
        name in "[a-zA-Z0-9_-]+",
        version in r"[0-9]+\.[0-9]+\.[0-9]+",
        dep_name in "[a-zA-Z0-9_-]+",
        dep_version in r"[0-9]+\.[0-9]+\.[0-9]+"
    ) {
        let json = format!(
            r#"{{
  "name": "{}",
  "version": "{}",
  "dependencies": {{
    "{}": "{}"
  }}
}}"#,
            name, version, dep_name, dep_version
        );

        let factory = ParserFactory::new();
        if let Some(parser) = factory.create_parser("package.json") {
            let _ = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(parser.parse_file(&json));
            // We just check it doesn't panic
        }
    }

    #[test]
    fn test_requirements_txt_parsing_doesnt_crash(
        package in "[a-zA-Z0-9_-]+",
        version in r"[0-9]+\.[0-9]+(\.[0-9]+)?"
    ) {
        let content = format!("{}=={}\n", package, version);

        let factory = ParserFactory::new();
        if let Some(parser) = factory.create_parser("requirements.txt") {
            let _ = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(parser.parse_file(&content));
            // We just check it doesn't panic
        }
    }
}
