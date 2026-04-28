use std::sync::Arc;
use vulnera_sandbox::infrastructure::noop::NoOpSandbox;
use vulnera_sandbox::{SandboxBackend, SandboxPolicy, SandboxSelector};

#[test]
fn test_auto_select_returns_available() {
    let backend = SandboxSelector::select();
    assert!(backend.is_available());
}

#[test]
fn test_select_by_name_auto_equivalent_to_select() {
    let auto_backend =
        SandboxSelector::select_by_name("auto").expect("auto should yield a backend");
    let select_backend = SandboxSelector::select();
    assert_eq!(auto_backend.name(), select_backend.name());
}

#[test]
fn test_select_by_name_noop_works() {
    let backend = SandboxSelector::select_by_name("noop").expect("noop should be available");
    assert_eq!(backend.name(), "noop");
}

#[test]
fn test_select_by_name_none_works() {
    let backend = SandboxSelector::select_by_name("none").expect("none should resolve to noop");
    assert_eq!(backend.name(), "noop");
}

#[test]
fn test_select_by_name_disabled_works() {
    let backend =
        SandboxSelector::select_by_name("disabled").expect("disabled should resolve to noop");
    assert_eq!(backend.name(), "noop");
}

#[test]
fn test_select_by_name_unknown() {
    assert!(SandboxSelector::select_by_name("potato").is_none());
}

#[test]
fn test_select_by_name_empty() {
    assert!(SandboxSelector::select_by_name("").is_none());
}

#[test]
fn test_select_by_name_case_insensitive() {
    let backend =
        SandboxSelector::select_by_name("NOOP").expect("NOOP (uppercase) should match noop");
    assert_eq!(backend.name(), "noop");
}

#[test]
fn test_best_available_not_empty() {
    let name = SandboxSelector::best_available();
    assert!(!name.is_empty());
}

#[test]
fn test_best_available_is_valid_backend_name() {
    let name = SandboxSelector::best_available();
    let valid = ["landlock", "process", "wasm", "noop"];
    assert!(
        valid.contains(&name),
        "best_available() returned '{name}', expected one of {valid:?}"
    );
}

#[test]
fn test_noop_backend_always_available() {
    let sandbox = NoOpSandbox::new();
    assert!(sandbox.is_available());
}

#[test]
fn test_noop_sandbox_name() {
    let sandbox = NoOpSandbox::new();
    assert_eq!(sandbox.name(), "noop");
}

#[tokio::test]
async fn test_noop_apply_restrictions_succeeds() {
    let sandbox = NoOpSandbox::new();
    let result = sandbox.apply_restrictions(&SandboxPolicy::default()).await;
    assert!(result.is_ok());
}

#[test]
fn test_backend_name_static_lifetime() {
    let name: &'static str = NoOpSandbox::new().name();
    assert!(!name.is_empty(), "static name should not be empty");
}

#[test]
fn test_backend_trait_object() {
    let backend: Arc<dyn SandboxBackend> = Arc::new(NoOpSandbox::new());
    assert!(backend.is_available());
    assert_eq!(backend.name(), "noop");
}
