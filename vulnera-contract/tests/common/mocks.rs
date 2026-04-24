//! Mock factories for vulnera-core tests

use std::sync::Arc;
use vulnera_contract::domain::vulnerability::repositories::IVulnerabilityRepository;
use vulnera_contract::domain::vulnerability::entities::{Package, Vulnerability};
use vulnera_contract::application::errors::VulnerabilityError;

/// Mock vulnerability repository for testing
#[cfg(test)]
pub struct MockVulnerabilityRepository {
    // Mock implementation would go here
    // This is a placeholder for mockall-generated mocks
}

#[cfg(test)]
impl MockVulnerabilityRepository {
    pub fn new() -> Self {
        Self {}
    }
}

// Note: Actual mocks should be generated using mockall's automock attribute
// on the trait definitions in the source code

