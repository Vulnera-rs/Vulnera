//! Secret detection domain entities

use serde::{Deserialize, Serialize};

use super::value_objects::Confidence;

/// Secret finding from detection analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub id: String,
    pub rule_id: String,
    pub secret_type: SecretType,
    pub location: Location,
    pub severity: Severity,
    pub confidence: Confidence,
    pub description: String,
    pub recommendation: Option<String>,
    pub matched_secret: String, // Partial/redacted secret for context
    pub entropy: Option<f64>,
}

/// Location of a finding in source code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub file_path: String,
    pub line: u32,
    pub column: Option<u32>,
    pub end_line: Option<u32>,
    pub end_column: Option<u32>,
}

/// Finding severity
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Secret type categories
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecretType {
    /// AWS credentials
    AwsAccessKey,
    AwsSecretKey,
    AwsSessionToken,
    /// API keys
    ApiKey,
    GenericApiKey,
    StripeApiKey,
    TwilioApiKey,
    /// OAuth and tokens
    OAuthToken,
    JwtToken,
    BearerToken,
    /// Database credentials
    DatabasePassword,
    DatabaseConnectionString,
    /// Private keys
    SshPrivateKey,
    RsaPrivateKey,
    EcPrivateKey,
    PgpPrivateKey,
    /// Cloud provider credentials
    AzureKey,
    GcpKey,
    /// Version control tokens
    GitHubToken,
    GitLabToken,
    /// High entropy strings
    HighEntropyBase64,
    HighEntropyHex,
    /// Other
    EnvironmentVariable,
    Other,
}

