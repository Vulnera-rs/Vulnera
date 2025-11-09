//! Test data fixtures for vulnera-core

use vulnera_core::domain::vulnerability::{
    entities::Package,
    value_objects::{Ecosystem, Version},
};

/// Create a test package with default values
pub fn test_package(name: impl Into<String>, version: impl Into<String>) -> Package {
    Package::new(
        name.into(),
        Version::parse(&version.into()).expect("Invalid version"),
        Ecosystem::Npm,
    )
}

/// Sample package.json content for testing
pub fn sample_package_json() -> &'static str {
    r#"{
  "name": "test-package",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "~4.17.21"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}"#
}

/// Sample requirements.txt content for testing
pub fn sample_requirements_txt() -> &'static str {
    r#"requests==2.28.0
flask>=2.0.0,<3.0.0
pytest~=7.0.0"#
}

/// Sample Cargo.toml content for testing
pub fn sample_cargo_toml() -> &'static str {
    r#"[package]
name = "test-crate"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
"#
}

/// Sample pom.xml content for testing
pub fn sample_pom_xml() -> &'static str {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>test-project</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.21</version>
    </dependency>
  </dependencies>
</project>"#
}

/// Sample go.mod content for testing
pub fn sample_go_mod() -> &'static str {
    r#"module github.com/example/test

go 1.19

require (
    github.com/gin-gonic/gin v1.9.0
    golang.org/x/crypto v0.5.0
)
"#
}

