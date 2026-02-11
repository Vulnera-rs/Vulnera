//! Property-based tests for AST parsing
//!
//! Uses proptest to verify that:
//! 1. Parsing arbitrary strings never panics (crash resistance)
//! 2. Re-parsing the same code is deterministic (idempotency)
//! 3. Language detection is consistent

use proptest::prelude::*;
use vulnera_sast::domain::value_objects::Language;

/// Helper: parse source code with tree-sitter and return whether it succeeded.
fn try_parse(lang: Language, code: &str) -> bool {
    let grammar = lang.grammar();
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&grammar).is_err() {
        return false;
    }
    parser.parse(code, None).is_some()
}

// =========================================================================
// Crash resistance: fuzzing the parsers
// =========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn python_parsing_never_panics(
        code in "[a-zA-Z0-9_\\s=+\\-*/().,;:{}\\[\\]\"'#@\n]+"
    ) {
        let _ = try_parse(Language::Python, &code);
    }

    #[test]
    fn javascript_parsing_never_panics(
        code in "[a-zA-Z0-9_\\s=+\\-*/().,;:{}\\[\\]\"'`<>/!\n]+"
    ) {
        let _ = try_parse(Language::JavaScript, &code);
    }

    #[test]
    fn typescript_parsing_never_panics(
        code in "[a-zA-Z0-9_\\s=+\\-*/().,;:{}\\[\\]\"'`<>/!:\n]+"
    ) {
        let _ = try_parse(Language::TypeScript, &code);
    }

    #[test]
    fn rust_parsing_never_panics(
        code in "[a-zA-Z0-9_\\s=+\\-*/().,;:{}\\[\\]\"'!&|<>#?\n]+"
    ) {
        let _ = try_parse(Language::Rust, &code);
    }

    #[test]
    fn go_parsing_never_panics(
        code in "[a-zA-Z0-9_\\s=+\\-*/().,;:{}\\[\\]\"'`<>/!\n]+"
    ) {
        let _ = try_parse(Language::Go, &code);
    }

    #[test]
    fn c_parsing_never_panics(
        code in "[a-zA-Z0-9_\\s=+\\-*/().,;:{}\\[\\]\"'<>#!\n]+"
    ) {
        let _ = try_parse(Language::C, &code);
    }

    #[test]
    fn cpp_parsing_never_panics(
        code in "[a-zA-Z0-9_\\s=+\\-*/().,;:{}\\[\\]\"'<>#!:\n]+"
    ) {
        let _ = try_parse(Language::Cpp, &code);
    }
}

// =========================================================================
// Parsing determinism: same input → same tree structure
// =========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn python_parsing_is_deterministic(
        code in "def [a-z]{1,8}\\([a-z]{0,8}\\):\n    return [0-9]{1,3}"
    ) {
        let grammar = Language::Python.grammar();
        let mut p1 = tree_sitter::Parser::new();
        let mut p2 = tree_sitter::Parser::new();
        p1.set_language(&grammar).unwrap();
        p2.set_language(&grammar).unwrap();

        let t1 = p1.parse(&code, None);
        let t2 = p2.parse(&code, None);

        match (t1, t2) {
            (Some(tree1), Some(tree2)) => {
                // Root node S-expression should be identical
                prop_assert_eq!(
                    tree1.root_node().to_sexp(),
                    tree2.root_node().to_sexp(),
                    "Parsing the same Python code should produce identical ASTs"
                );
            }
            (None, None) => {} // Both failed — OK
            _ => prop_assert!(false, "Determinism violated: one parse succeeded, other failed"),
        }
    }

    #[test]
    fn javascript_parsing_is_deterministic(
        code in "function [a-z]{1,8}\\([a-z]{0,8}\\) \\{ return [0-9]{1,3}; \\}"
    ) {
        let grammar = Language::JavaScript.grammar();
        let mut p1 = tree_sitter::Parser::new();
        let mut p2 = tree_sitter::Parser::new();
        p1.set_language(&grammar).unwrap();
        p2.set_language(&grammar).unwrap();

        let t1 = p1.parse(&code, None);
        let t2 = p2.parse(&code, None);

        match (t1, t2) {
            (Some(tree1), Some(tree2)) => {
                prop_assert_eq!(
                    tree1.root_node().to_sexp(),
                    tree2.root_node().to_sexp(),
                    "Parsing the same JS code should produce identical ASTs"
                );
            }
            (None, None) => {}
            _ => prop_assert!(false, "Determinism violated"),
        }
    }
}

// =========================================================================
// Language detection properties
// =========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn language_detection_from_extension_is_pure(
        ext in "(py|js|ts|rs|go|c|cpp|h|mjs|cjs|mts|cts|hpp|cc|cxx|hxx)"
    ) {
        let result1 = Language::from_extension(&ext);
        let result2 = Language::from_extension(&ext);
        prop_assert_eq!(result1, result2, "Language detection should be deterministic");
        prop_assert!(result1.is_some(), "Known extension '{}' should be detected", ext);
    }

    #[test]
    fn unknown_extensions_return_none(
        ext in "(txt|md|toml|yaml|json|xml|html|css|sql|sh|bat|exe)"
    ) {
        prop_assert!(
            Language::from_extension(&ext).is_none(),
            "Extension '{}' should not be detected as a scannable language",
            ext
        );
    }
}

// =========================================================================
// Valid code round-trip: valid programs always parse successfully
// =========================================================================

#[test]
fn valid_python_programs_always_parse() {
    let programs = [
        "x = 1",
        "def foo(): pass",
        "class A:\n    def __init__(self): pass",
        "import os\nos.path.exists('.')",
        "for i in range(10):\n    print(i)",
        "try:\n    pass\nexcept Exception:\n    pass",
    ];
    for code in programs {
        assert!(
            try_parse(Language::Python, code),
            "Valid Python should parse: {code}"
        );
    }
}

#[test]
fn valid_javascript_programs_always_parse() {
    let programs = [
        "const x = 1;",
        "function foo() { return 42; }",
        "class A { constructor() {} }",
        "const arr = [1, 2, 3].map(x => x * 2);",
        "async function fetch() { await Promise.resolve(); }",
        "try { throw new Error(); } catch(e) {}",
    ];
    for code in programs {
        assert!(
            try_parse(Language::JavaScript, code),
            "Valid JS should parse: {code}"
        );
    }
}

#[test]
fn valid_rust_programs_always_parse() {
    let programs = [
        "fn main() {}",
        "let x: i32 = 42;",
        "struct Foo { bar: String }",
        "enum Choice { A, B(i32) }",
        "impl Foo { fn new() -> Self { Foo { bar: String::new() } } }",
        "match x { Some(v) => v, None => 0 }",
    ];
    for code in programs {
        assert!(
            try_parse(Language::Rust, code),
            "Valid Rust should parse: {code}"
        );
    }
}

#[test]
fn valid_go_programs_always_parse() {
    let programs = [
        "package main",
        "package main\nfunc main() {}",
        "package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"hi\") }",
        "package main\ntype Foo struct { X int }",
    ];
    for code in programs {
        assert!(
            try_parse(Language::Go, code),
            "Valid Go should parse: {code}"
        );
    }
}

#[test]
fn valid_c_programs_always_parse() {
    let programs = [
        "int main() { return 0; }",
        "#include <stdio.h>\nint main() { printf(\"hi\"); }",
        "typedef struct { int x; } Point;",
        "void foo(int *p) { *p = 42; }",
    ];
    for code in programs {
        assert!(
            try_parse(Language::C, code),
            "Valid C should parse: {code}"
        );
    }
}
