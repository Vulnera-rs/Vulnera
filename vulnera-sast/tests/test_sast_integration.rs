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

#[tokio::test]
async fn test_sast_module_go_scan() {
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("main.go");
    let code = r#"
package main
import "os/exec"
func main() {
    cmd := exec.Command("ls", "-la")
    cmd.Run()
}
"#;
    std::fs::write(&file_path, code).unwrap();

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
    assert!(rule_ids.contains(&"go-command-injection".to_string()));
}

#[tokio::test]
async fn test_sast_module_c_scan() {
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("main.c");
    let code = r#"
#include <stdio.h>
#include <string.h>
int main() {
    char src[40];
    char dest[100];
    strcpy(dest, src);
    return 0;
}
"#;
    std::fs::write(&file_path, code).unwrap();

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
    assert!(rule_ids.contains(&"c-buffer-overflow".to_string()));
}

#[tokio::test]
async fn test_sast_module_cpp_scan() {
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("main.cpp");
    let code = r#"
#include <iostream>
#include <cstdlib>
int main() {
    system("ls -la");
    return 0;
}
"#;
    std::fs::write(&file_path, code).unwrap();

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
    assert!(rule_ids.contains(&"c-command-injection".to_string()));
}

#[tokio::test]
async fn test_sast_comprehensive_rules() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config = SastConfig {
        ..Default::default()
    };
    let module = SastModule::with_config(&config);

    // Python Tests
    let py_path = temp_dir.path().join("comprehensive.py");
    std::fs::write(
        &py_path,
        r#"
import subprocess
import yaml
from flask import render_template_string
subprocess.call("ls")
yaml.load(data)
render_template_string(template)
"#,
    )
    .unwrap();

    let result = module
        .execute(&vulnera_core::domain::module::ModuleConfig {
            job_id: Uuid::new_v4(),
            project_id: "test-project".to_string(),
            source_uri: temp_dir.path().to_string_lossy().to_string(),
            config: std::collections::HashMap::new(),
        })
        .await
        .unwrap();

    let rule_ids: Vec<String> = result
        .findings
        .iter()
        .filter_map(|f| f.rule_id.clone())
        .collect();
    assert!(rule_ids.contains(&"python-subprocess".to_string()));
    assert!(rule_ids.contains(&"python-yaml-load".to_string()));
    assert!(rule_ids.contains(&"python-ssti".to_string()));

    // JavaScript Tests
    let js_path = temp_dir.path().join("comprehensive.js");
    std::fs::write(
        &js_path,
        r#"
const child_process = require('child_process');
child_process.exec('ls');
dangerouslySetInnerHTML(createMarkup());
setTimeout("alert('hi')", 1000);
"#,
    )
    .unwrap();

    let result = module
        .execute(&vulnera_core::domain::module::ModuleConfig {
            job_id: Uuid::new_v4(),
            project_id: "test-project".to_string(),
            source_uri: temp_dir.path().to_string_lossy().to_string(),
            config: std::collections::HashMap::new(),
        })
        .await
        .unwrap();

    let rule_ids: Vec<String> = result
        .findings
        .iter()
        .filter_map(|f| f.rule_id.clone())
        .collect();
    assert!(rule_ids.contains(&"js-child-process".to_string()));
    assert!(rule_ids.contains(&"js-xss".to_string()));
    assert!(rule_ids.contains(&"js-eval-indirect".to_string()));

    // Rust Tests
    let rs_path = temp_dir.path().join("comprehensive.rs");
    std::fs::write(
        &rs_path,
        r#"
use std::process::Command;
fn main() {
    unsafe {
        // unsafe block
    }
    Command::new("ls").spawn();
}
"#,
    )
    .unwrap();

    let result = module
        .execute(&vulnera_core::domain::module::ModuleConfig {
            job_id: Uuid::new_v4(),
            project_id: "test-project".to_string(),
            source_uri: temp_dir.path().to_string_lossy().to_string(),
            config: std::collections::HashMap::new(),
        })
        .await
        .unwrap();

    let rule_ids: Vec<String> = result
        .findings
        .iter()
        .filter_map(|f| f.rule_id.clone())
        .collect();
    assert!(rule_ids.contains(&"rust-command".to_string()));
    assert!(rule_ids.contains(&"rust-unsafe".to_string()));

    // Go Tests
    let go_path = temp_dir.path().join("comprehensive.go");
    std::fs::write(
        &go_path,
        r#"
package main
import "database/sql"
import "unsafe"
func main() {
    var sql *sql.DB
    sql.Query("SELECT * FROM users")
    p := unsafe.Pointer(ptr)
}
"#,
    )
    .unwrap();

    let result = module
        .execute(&vulnera_core::domain::module::ModuleConfig {
            job_id: Uuid::new_v4(),
            project_id: "test-project".to_string(),
            source_uri: temp_dir.path().to_string_lossy().to_string(),
            config: std::collections::HashMap::new(),
        })
        .await
        .unwrap();

    let rule_ids: Vec<String> = result
        .findings
        .iter()
        .filter_map(|f| f.rule_id.clone())
        .collect();
    assert!(rule_ids.contains(&"go-sql-injection".to_string()));
    assert!(rule_ids.contains(&"go-unsafe".to_string()));

    // C/C++ Tests
    let c_path = temp_dir.path().join("comprehensive.c");
    std::fs::write(
        &c_path,
        r#"
#include <stdio.h>
#include <unistd.h>
int main() {
    char buf[10];
    gets(buf);
    sprintf(buf, "%s", "test");
    execl("/bin/ls", "ls", NULL);
    return 0;
}
"#,
    )
    .unwrap();

    let result = module
        .execute(&vulnera_core::domain::module::ModuleConfig {
            job_id: Uuid::new_v4(),
            project_id: "test-project".to_string(),
            source_uri: temp_dir.path().to_string_lossy().to_string(),
            config: std::collections::HashMap::new(),
        })
        .await
        .unwrap();

    let rule_ids: Vec<String> = result
        .findings
        .iter()
        .filter_map(|f| f.rule_id.clone())
        .collect();
    assert!(rule_ids.contains(&"c-gets".to_string()));
    assert!(rule_ids.contains(&"c-sprintf".to_string()));
    assert!(rule_ids.contains(&"c-exec".to_string()));
}
