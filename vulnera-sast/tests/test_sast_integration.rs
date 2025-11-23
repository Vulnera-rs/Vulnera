use uuid::Uuid;
use vulnera_core::config::SastConfig;
use vulnera_core::domain::module::AnalysisModule;
use vulnera_sast::SastModule;

#[tokio::test]
async fn test_sast_module_rust_scan() {
    // Create a temporary directory with a Rust file
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("unsafe.rs");
    std::fs::write(
        &file_path,
        r#"
        fn main() {
            let x = Some(1);
            x.unwrap(); // Should trigger null-pointer rule
            execute("DROP TABLE users"); // Should trigger sql-injection rule
        }
    "#,
    )
    .unwrap();

    let config = SastConfig {
        ..Default::default()
    };

    let module = SastModule::with_config(&config);
    let result = module
        .execute(&vulnera_core::domain::module::ModuleConfig {
            job_id: Uuid::new_v4(),
            project_id: "test-project".to_string(),
            source_uri: temp_dir.path().to_string_lossy().to_string(),
            config: std::collections::HashMap::new(),
        })
        .await
        .unwrap();

    assert!(!result.findings.is_empty(), "Should find vulnerabilities");

    let rule_ids: Vec<String> = result
        .findings
        .iter()
        .filter_map(|f| f.rule_id.clone())
        .collect();
    assert!(rule_ids.contains(&"null-pointer".to_string()));
    assert!(rule_ids.contains(&"sql-injection".to_string()));
}

#[tokio::test]
async fn test_sast_module_python_scan() {
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("unsafe.py");
    std::fs::write(
        &file_path,
        r#"
        import pickle
        def process(data):
            pickle.loads(data) # Should trigger unsafe-deserialization
            eval("print('hello')") # Should trigger unsafe-function-call
    "#,
    )
    .unwrap();

    let config = SastConfig {
        ..Default::default()
    };

    let module = SastModule::with_config(&config);
    let result = module
        .execute(&vulnera_core::domain::module::ModuleConfig {
            job_id: Uuid::new_v4(),
            project_id: "test-project".to_string(),
            source_uri: temp_dir.path().to_string_lossy().to_string(),
            config: std::collections::HashMap::new(),
        })
        .await
        .unwrap();

    assert!(!result.findings.is_empty());
    let rule_ids: Vec<String> = result
        .findings
        .iter()
        .filter_map(|f| f.rule_id.clone())
        .collect();
    assert!(rule_ids.contains(&"unsafe-deserialization".to_string()));
    assert!(rule_ids.contains(&"unsafe-function-call".to_string()));
}

#[tokio::test]
async fn test_sast_module_js_scan() {
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("unsafe.js");
    std::fs::write(
        &file_path,
        r#"
        function run() {
            eval("alert('hacked')"); // Should trigger unsafe-function-call
            exec("rm -rf /"); // Should trigger command-injection
        }
    "#,
    )
    .unwrap();

    let config = SastConfig {
        ..Default::default()
    };

    let module = SastModule::with_config(&config);
    let result = module
        .execute(&vulnera_core::domain::module::ModuleConfig {
            job_id: Uuid::new_v4(),
            project_id: "test-project".to_string(),
            source_uri: temp_dir.path().to_string_lossy().to_string(),
            config: std::collections::HashMap::new(),
        })
        .await
        .unwrap();

    assert!(!result.findings.is_empty());
    let rule_ids: Vec<String> = result
        .findings
        .iter()
        .filter_map(|f| f.rule_id.clone())
        .collect();
    assert!(rule_ids.contains(&"unsafe-function-call".to_string()));
    assert!(rule_ids.contains(&"command-injection".to_string()));
}
