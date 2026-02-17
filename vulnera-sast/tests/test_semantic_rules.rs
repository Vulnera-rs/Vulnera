use vulnera_sast::domain::finding::Severity;
use vulnera_sast::domain::pattern_types::{Pattern, PatternRule, RuleOptions, SemanticRuleOptions};
use vulnera_sast::domain::value_objects::Language;
use vulnera_sast::infrastructure::sast_engine::SastEngine;
use vulnera_sast::infrastructure::semantic::SemanticContext;

#[tokio::test]
async fn test_semantic_constraints_pass_for_inferred_type() {
    let source = "client = Client()\n";
    let engine = SastEngine::new();
    let rule = PatternRule {
        id: "semantic-type-check".to_string(),
        name: "Semantic type constraint".to_string(),
        description: "Ensure $X is a Client".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            "(assignment left: (identifier) @mv_X right: (call function: (identifier) @type))"
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec![],
        owasp_categories: vec![],
        tags: vec![],
        message: None,
        fix: None,
        metavariable_constraints: vec![],
        semantic: Some(SemanticRuleOptions {
            required_types: [("$X".to_string(), vec!["Client".to_string()])]
                .into_iter()
                .collect(),
            allow_unknown_types: false,
        }),
    };

    let results = engine.query_batch(source, Language::Python, &[&rule]).await;
    let matches = results
        .into_iter()
        .find(|(rule_id, _)| rule_id == &rule.id)
        .map(|(_, m)| m)
        .unwrap_or_default();

    assert_eq!(matches.len(), 1);

    let tree = engine.parse(source, Language::Python).await.unwrap();
    let semantic_context = SemanticContext::from_tree(&tree, source, Language::Python);

    let allowed = engine
        .metavariable_constraints_pass(
            &rule,
            &matches[0],
            Language::Python,
            Some(&semantic_context),
        )
        .await;

    assert!(allowed, "semantic constraint should pass for inferred type");
}

#[tokio::test]
async fn test_semantic_constraints_fail_for_mismatched_type() {
    let source = "client = SomethingElse()\n";
    let engine = SastEngine::new();
    let rule = PatternRule {
        id: "semantic-type-check".to_string(),
        name: "Semantic type constraint".to_string(),
        description: "Ensure $X is a Client".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            "(assignment left: (identifier) @mv_X right: (call function: (identifier) @type))"
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec![],
        owasp_categories: vec![],
        tags: vec![],
        message: None,
        fix: None,
        metavariable_constraints: vec![],
        semantic: Some(SemanticRuleOptions {
            required_types: [("$X".to_string(), vec!["Client".to_string()])]
                .into_iter()
                .collect(),
            allow_unknown_types: false,
        }),
    };

    let results = engine.query_batch(source, Language::Python, &[&rule]).await;
    let matches = results
        .into_iter()
        .find(|(rule_id, _)| rule_id == &rule.id)
        .map(|(_, m)| m)
        .unwrap_or_default();

    assert_eq!(matches.len(), 1);

    let tree = engine.parse(source, Language::Python).await.unwrap();
    let semantic_context = SemanticContext::from_tree(&tree, source, Language::Python);

    let allowed = engine
        .metavariable_constraints_pass(
            &rule,
            &matches[0],
            Language::Python,
            Some(&semantic_context),
        )
        .await;

    assert!(
        !allowed,
        "semantic constraint should reject mismatched type"
    );
}

#[tokio::test]
async fn test_semantic_constraints_pass_for_python_alias_type() {
    let source = "client = Client()\nalias = client\n";
    let engine = SastEngine::new();
    let rule = PatternRule {
        id: "semantic-python-alias-check".to_string(),
        name: "Semantic alias type constraint".to_string(),
        description: "Ensure $X alias resolves to Client".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            "(assignment left: (identifier) @mv_X right: (identifier) @rhs)".to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec![],
        owasp_categories: vec![],
        tags: vec![],
        message: None,
        fix: None,
        metavariable_constraints: vec![],
        semantic: Some(SemanticRuleOptions {
            required_types: [("$X".to_string(), vec!["Client".to_string()])]
                .into_iter()
                .collect(),
            allow_unknown_types: false,
        }),
    };

    let results = engine.query_batch(source, Language::Python, &[&rule]).await;
    let matches = results
        .into_iter()
        .find(|(rule_id, _)| rule_id == &rule.id)
        .map(|(_, m)| m)
        .unwrap_or_default();

    assert_eq!(matches.len(), 1);

    let tree = engine.parse(source, Language::Python).await.unwrap();
    let semantic_context = SemanticContext::from_tree(&tree, source, Language::Python);

    let allowed = engine
        .metavariable_constraints_pass(
            &rule,
            &matches[0],
            Language::Python,
            Some(&semantic_context),
        )
        .await;

    assert!(allowed, "semantic constraint should pass for typed alias");
}

#[tokio::test]
async fn test_semantic_constraints_pass_for_typescript_annotation() {
    let source = "let client: Client = createClient();\n";
    let engine = SastEngine::new();
    let rule = PatternRule {
        id: "semantic-typescript-annotation-check".to_string(),
        name: "Semantic TS type constraint".to_string(),
        description: "Ensure $X has annotated type Client".to_string(),
        severity: Severity::High,
        languages: vec![Language::TypeScript],
        pattern: Pattern::TreeSitterQuery(
            "(variable_declarator name: (identifier) @mv_X)".to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec![],
        owasp_categories: vec![],
        tags: vec![],
        message: None,
        fix: None,
        metavariable_constraints: vec![],
        semantic: Some(SemanticRuleOptions {
            required_types: [("$X".to_string(), vec!["Client".to_string()])]
                .into_iter()
                .collect(),
            allow_unknown_types: false,
        }),
    };

    let results = engine
        .query_batch(source, Language::TypeScript, &[&rule])
        .await;
    let matches = results
        .into_iter()
        .find(|(rule_id, _)| rule_id == &rule.id)
        .map(|(_, m)| m)
        .unwrap_or_default();

    assert_eq!(matches.len(), 1);

    let tree = engine.parse(source, Language::TypeScript).await.unwrap();
    let semantic_context = SemanticContext::from_tree(&tree, source, Language::TypeScript);

    let allowed = engine
        .metavariable_constraints_pass(
            &rule,
            &matches[0],
            Language::TypeScript,
            Some(&semantic_context),
        )
        .await;

    assert!(
        allowed,
        "semantic constraint should pass for TypeScript type annotation"
    );
}
