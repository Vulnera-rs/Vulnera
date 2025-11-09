//! Test data fixtures for vulnera-secrets

/// Sample file with AWS access key
pub fn sample_aws_key() -> &'static str {
    r#"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"#
}

/// Sample file with GitHub token
pub fn sample_github_token() -> &'static str {
    r#"GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz
"#
}

/// Sample file with high entropy string
pub fn sample_high_entropy() -> &'static str {
    r#"API_KEY=K8j3mN9pQ2rT5vX8zA1bC4dE7fG0hI3jK6mN9pQ2rT5v
"#
}

/// Sample file with no secrets
pub fn sample_no_secrets() -> &'static str {
    r#"# Configuration file
DATABASE_URL=postgresql://localhost:5432/mydb
PORT=8080
"#
}

