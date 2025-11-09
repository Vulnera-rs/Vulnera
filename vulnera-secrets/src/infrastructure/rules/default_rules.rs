//! Default secret detection rules

use crate::domain::entities::SecretType;
use crate::domain::value_objects::{RulePattern, SecretRule};

/// Get all default secret detection rules
pub fn get_default_rules() -> Vec<SecretRule> {
    vec![
        // AWS credentials
        aws_access_key_rule(),
        aws_secret_key_rule(),
        aws_session_token_rule(),
        // API keys
        generic_api_key_rule(),
        stripe_api_key_rule(),
        twilio_api_key_rule(),
        // OAuth and tokens
        oauth_token_rule(),
        jwt_token_rule(),
        bearer_token_rule(),
        // Database credentials
        database_password_rule(),
        database_connection_string_rule(),
        // Private keys
        ssh_private_key_rule(),
        rsa_private_key_rule(),
        ec_private_key_rule(),
        pgp_private_key_rule(),
        // Cloud provider credentials
        azure_key_rule(),
        gcp_key_rule(),
        // Version control tokens
        github_token_rule(),
        gitlab_token_rule(),
        // Environment variables
        environment_variable_rule(),
    ]
}

/// AWS Access Key rule
pub fn aws_access_key_rule() -> SecretRule {
    SecretRule {
        id: "aws-access-key".to_string(),
        name: "AWS Access Key".to_string(),
        description: "AWS access key ID (AKIA...)".to_string(),
        secret_type: SecretType::AwsAccessKey,
        pattern: RulePattern::Regex(
            r#"(?i)(?:aws|amazon)[\s_-]*(?:access|account)[\s_-]*(?:key|id)[\s_-]*[:=]\s*(AKIA[0-9A-Z]{16})"#.to_string(),
        ),
        keywords: vec!["aws".to_string(), "access".to_string(), "key".to_string()],
        entropy_threshold: None,
        path_patterns: vec![],
    }
}

/// AWS Secret Key rule
pub fn aws_secret_key_rule() -> SecretRule {
    SecretRule {
        id: "aws-secret-key".to_string(),
        name: "AWS Secret Key".to_string(),
        description: "AWS secret access key".to_string(),
        secret_type: SecretType::AwsSecretKey,
        pattern: RulePattern::Regex(
            r#"(?i)(?:aws|amazon)[\s_-]*(?:secret|private)[\s_-]*(?:access)?[\s_-]*(?:key|token)?[\s_-]*[:=]\s*([A-Za-z0-9/+=]{40})"#.to_string(),
        ),
        keywords: vec!["aws".to_string(), "secret".to_string()],
        entropy_threshold: Some(4.5),
        path_patterns: vec![],
    }
}

/// AWS Session Token rule
pub fn aws_session_token_rule() -> SecretRule {
    SecretRule {
        id: "aws-session-token".to_string(),
        name: "AWS Session Token".to_string(),
        description: "AWS session token".to_string(),
        secret_type: SecretType::AwsSessionToken,
        pattern: RulePattern::Regex(
            r#"(?i)(?:aws|amazon)[\s_-]*(?:session)?[\s_-]*(?:token)[\s_-]*[:=]\s*([A-Za-z0-9/+=]{100,})"#.to_string(),
        ),
        keywords: vec!["aws".to_string(), "session".to_string(), "token".to_string()],
        entropy_threshold: Some(4.5),
        path_patterns: vec![],
    }
}

/// Generic API Key rule
pub fn generic_api_key_rule() -> SecretRule {
    SecretRule {
        id: "generic-api-key".to_string(),
        name: "Generic API Key".to_string(),
        description: "Generic API key pattern".to_string(),
        secret_type: SecretType::GenericApiKey,
        pattern: RulePattern::Regex(
            r#"(?i)(?:api|apikey|api_key|apikey)[\s_-]*(?:key|token|secret)?[\s_-]*[:=]\s*([A-Za-z0-9_\-]{20,})"#.to_string(),
        ),
        keywords: vec!["api".to_string(), "key".to_string()],
        entropy_threshold: Some(3.5),
        path_patterns: vec![],
    }
}

/// Stripe API Key rule
pub fn stripe_api_key_rule() -> SecretRule {
    SecretRule {
        id: "stripe-api-key".to_string(),
        name: "Stripe API Key".to_string(),
        description: "Stripe API key (sk_live_... or sk_test_...)".to_string(),
        secret_type: SecretType::StripeApiKey,
        pattern: RulePattern::Regex(
            r#"(?i)(?:stripe)[\s_-]*(?:api)?[\s_-]*(?:key|token|secret)?[\s_-]*[:=]\s*(sk_(?:live|test)_[A-Za-z0-9]{24,})"#.to_string(),
        ),
        keywords: vec!["stripe".to_string()],
        entropy_threshold: None,
        path_patterns: vec![],
    }
}

/// Twilio API Key rule
pub fn twilio_api_key_rule() -> SecretRule {
    SecretRule {
        id: "twilio-api-key".to_string(),
        name: "Twilio API Key".to_string(),
        description: "Twilio API key (SK...)".to_string(),
        secret_type: SecretType::TwilioApiKey,
        pattern: RulePattern::Regex(
            r#"(?i)(?:twilio)[\s_-]*(?:api)?[\s_-]*(?:key|token|secret|sid)?[\s_-]*[:=]\s*(SK[0-9a-fA-F]{32})"#.to_string(),
        ),
        keywords: vec!["twilio".to_string()],
        entropy_threshold: None,
        path_patterns: vec![],
    }
}

/// OAuth Token rule
pub fn oauth_token_rule() -> SecretRule {
    SecretRule {
        id: "oauth-token".to_string(),
        name: "OAuth Token".to_string(),
        description: "OAuth access token".to_string(),
        secret_type: SecretType::OAuthToken,
        pattern: RulePattern::Regex(
            r#"(?i)(?:oauth)[\s_-]*(?:token|access|secret)?[\s_-]*[:=]\s*([A-Za-z0-9_\-]{20,})"#
                .to_string(),
        ),
        keywords: vec!["oauth".to_string(), "token".to_string()],
        entropy_threshold: Some(3.5),
        path_patterns: vec![],
    }
}

/// JWT Token rule
pub fn jwt_token_rule() -> SecretRule {
    SecretRule {
        id: "jwt-token".to_string(),
        name: "JWT Token".to_string(),
        description: "JSON Web Token".to_string(),
        secret_type: SecretType::JwtToken,
        pattern: RulePattern::Regex(
            r#"(?:eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,})"#.to_string(),
        ),
        keywords: vec!["jwt".to_string(), "token".to_string()],
        entropy_threshold: None,
        path_patterns: vec![],
    }
}

/// Bearer Token rule
pub fn bearer_token_rule() -> SecretRule {
    SecretRule {
        id: "bearer-token".to_string(),
        name: "Bearer Token".to_string(),
        description: "Bearer authentication token".to_string(),
        secret_type: SecretType::BearerToken,
        pattern: RulePattern::Regex(
            r#"(?i)(?:bearer|authorization)[\s_-]*[:=]\s*([A-Za-z0-9_\-\.]{20,})"#.to_string(),
        ),
        keywords: vec!["bearer".to_string(), "authorization".to_string()],
        entropy_threshold: Some(3.5),
        path_patterns: vec![],
    }
}

/// Database Password rule
pub fn database_password_rule() -> SecretRule {
    SecretRule {
        id: "database-password".to_string(),
        name: "Database Password".to_string(),
        description: "Database password in connection string".to_string(),
        secret_type: SecretType::DatabasePassword,
        pattern: RulePattern::Regex(
            r#"(?i)(?:password|pwd|passwd)[\s_-]*[:=]\s*([^\s"'`]{8,})"#.to_string(),
        ),
        keywords: vec!["password".to_string(), "pwd".to_string()],
        entropy_threshold: Some(3.0),
        path_patterns: vec![],
    }
}

/// Database Connection String rule
pub fn database_connection_string_rule() -> SecretRule {
    SecretRule {
        id: "database-connection-string".to_string(),
        name: "Database Connection String".to_string(),
        description: "Database connection string with credentials".to_string(),
        secret_type: SecretType::DatabaseConnectionString,
        pattern: RulePattern::Regex(
            r#"(?i)(?:postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^\s"'`]+"#.to_string(),
        ),
        keywords: vec![
            "postgres".to_string(),
            "mysql".to_string(),
            "mongodb".to_string(),
        ],
        entropy_threshold: None,
        path_patterns: vec![],
    }
}

/// SSH Private Key rule
pub fn ssh_private_key_rule() -> SecretRule {
    SecretRule {
        id: "ssh-private-key".to_string(),
        name: "SSH Private Key".to_string(),
        description: "SSH private key".to_string(),
        secret_type: SecretType::SshPrivateKey,
        pattern: RulePattern::Regex(
            r#"(?m)(?:-----BEGIN (?:OPENSSH|RSA|DSA|EC|ED25519) PRIVATE KEY-----)"#.to_string(),
        ),
        keywords: vec!["private".to_string(), "key".to_string()],
        entropy_threshold: None,
        path_patterns: vec![],
    }
}

/// RSA Private Key rule
pub fn rsa_private_key_rule() -> SecretRule {
    SecretRule {
        id: "rsa-private-key".to_string(),
        name: "RSA Private Key".to_string(),
        description: "RSA private key".to_string(),
        secret_type: SecretType::RsaPrivateKey,
        pattern: RulePattern::Regex(r#"(?m)(?:-----BEGIN RSA PRIVATE KEY-----)"#.to_string()),
        keywords: vec!["rsa".to_string(), "private".to_string()],
        entropy_threshold: None,
        path_patterns: vec![],
    }
}

/// EC Private Key rule
pub fn ec_private_key_rule() -> SecretRule {
    SecretRule {
        id: "ec-private-key".to_string(),
        name: "EC Private Key".to_string(),
        description: "Elliptic Curve private key".to_string(),
        secret_type: SecretType::EcPrivateKey,
        pattern: RulePattern::Regex(r#"(?m)(?:-----BEGIN EC PRIVATE KEY-----)"#.to_string()),
        keywords: vec!["ec".to_string(), "private".to_string()],
        entropy_threshold: None,
        path_patterns: vec![],
    }
}

/// PGP Private Key rule
pub fn pgp_private_key_rule() -> SecretRule {
    SecretRule {
        id: "pgp-private-key".to_string(),
        name: "PGP Private Key".to_string(),
        description: "PGP private key".to_string(),
        secret_type: SecretType::PgpPrivateKey,
        pattern: RulePattern::Regex(r#"(?m)(?:-----BEGIN PGP PRIVATE KEY BLOCK-----)"#.to_string()),
        keywords: vec!["pgp".to_string(), "private".to_string()],
        entropy_threshold: None,
        path_patterns: vec![],
    }
}

/// Azure Key rule
pub fn azure_key_rule() -> SecretRule {
    SecretRule {
        id: "azure-key".to_string(),
        name: "Azure Key".to_string(),
        description: "Azure storage account key or access key".to_string(),
        secret_type: SecretType::AzureKey,
        pattern: RulePattern::Regex(
            r#"(?i)(?:azure|microsoft)[\s_-]*(?:storage|account)?[\s_-]*(?:key|access)?[\s_-]*[:=]\s*([A-Za-z0-9+/=]{88})"#.to_string(),
        ),
        keywords: vec!["azure".to_string()],
        entropy_threshold: Some(4.5),
        path_patterns: vec![],
    }
}

/// GCP Key rule
pub fn gcp_key_rule() -> SecretRule {
    SecretRule {
        id: "gcp-key".to_string(),
        name: "GCP Key".to_string(),
        description: "Google Cloud Platform service account key".to_string(),
        secret_type: SecretType::GcpKey,
        pattern: RulePattern::Regex(
            r#"(?i)(?:gcp|google|gcloud)[\s_-]*(?:service|account)?[\s_-]*(?:key|credentials)?[\s_-]*[:=]\s*([A-Za-z0-9_\-]{20,})"#.to_string(),
        ),
        keywords: vec!["gcp".to_string(), "google".to_string()],
        entropy_threshold: Some(3.5),
        path_patterns: vec![],
    }
}

/// GitHub Token rule
pub fn github_token_rule() -> SecretRule {
    SecretRule {
        id: "github-token".to_string(),
        name: "GitHub Token".to_string(),
        description: "GitHub personal access token or OAuth token".to_string(),
        secret_type: SecretType::GitHubToken,
        pattern: RulePattern::Regex(
            r#"(?i)(?:github|gh)[\s_-]*(?:token|key|secret|pat)?[\s_-]*[:=]\s*(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36})"#.to_string(),
        ),
        keywords: vec!["github".to_string(), "gh".to_string()],
        entropy_threshold: None,
        path_patterns: vec![],
    }
}

/// GitLab Token rule
pub fn gitlab_token_rule() -> SecretRule {
    SecretRule {
        id: "gitlab-token".to_string(),
        name: "GitLab Token".to_string(),
        description: "GitLab personal access token or API token".to_string(),
        secret_type: SecretType::GitLabToken,
        pattern: RulePattern::Regex(
            r#"(?i)(?:gitlab|gl)[\s_-]*(?:token|key|secret)?[\s_-]*[:=]\s*(glpat-[A-Za-z0-9_-]{20}|[A-Za-z0-9_-]{20,})"#.to_string(),
        ),
        keywords: vec!["gitlab".to_string(), "gl".to_string()],
        entropy_threshold: Some(3.5),
        path_patterns: vec![],
    }
}

/// Environment Variable rule
pub fn environment_variable_rule() -> SecretRule {
    SecretRule {
        id: "environment-variable".to_string(),
        name: "Environment Variable".to_string(),
        description: "Potential secret in environment variable".to_string(),
        secret_type: SecretType::EnvironmentVariable,
        pattern: RulePattern::Regex(
            r#"(?i)(?:export|env)[\s_-]*(?:SECRET|PASSWORD|KEY|TOKEN|API_KEY)[\s_-]*[:=]\s*([^\s"'`]{10,})"#.to_string(),
        ),
        keywords: vec!["export".to_string(), "env".to_string()],
        entropy_threshold: Some(3.0),
        path_patterns: vec![],
    }
}
