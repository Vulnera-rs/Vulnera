//! Configuration validation trait

use thiserror::Error;

/// Validation error for configuration
#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("Invalid configuration: {0}")]
    Invalid(String),
}

/// Trait for validating configuration structs
pub trait Validate {
    /// Validate the configuration
    fn validate(&self) -> Result<(), ValidationError>;
}

impl Validate for crate::Config {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.server.port == 0 {
            return Err(ValidationError::Invalid(
                "Server port cannot be 0".to_string(),
            ));
        }
        if self.database.url.is_empty() {
            return Err(ValidationError::Invalid(
                "Database URL cannot be empty".to_string(),
            ));
        }
        Ok(())
    }
}
