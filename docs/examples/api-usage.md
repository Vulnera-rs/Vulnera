# API Usage Examples

This document provides comprehensive examples for using the Vulnera API endpoints.

## Base URL

All examples assume the API is running at `http://localhost:3000`. Adjust the base URL for your deployment.

## Health Check

Check if the API is running:

```bash
curl http://localhost:3000/health
```

## Analyze a Dependency File

Analyze dependencies from a file content string:

```bash
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "file_content": "django==3.2.0\nrequests>=2.25.0",
    "ecosystem": "PyPI",
    "filename": "requirements.txt"
  }'
```

## Analyze a GitHub Repository

Analyze dependencies from a GitHub repository:

```bash
curl -X POST http://localhost:3000/api/v1/analyze/repository \
  -H "Content-Type: application/json" \
  -d '{
    "repository_url": "https://github.com/rust-lang/cargo",
    "ref": "main"
  }'
```

## Unified Multi-Module Analysis

The orchestrator endpoint (`/api/v1/analyze/job`) enables comprehensive analysis across multiple security modules.

### Analyze a Git Repository (Full Analysis)

This will automatically execute:

- Dependency Analysis (if dependency files are detected)
- SAST (static code analysis for supported languages)
- Secrets Detection (regex and entropy-based scanning)
- API Security (if OpenAPI specifications are found)

```bash
curl -X POST http://localhost:3000/api/v1/analyze/job \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{
    "source_type": "git",
    "source_uri": "https://github.com/my-org/my-project.git",
    "analysis_depth": "full"
  }'
```

### Analyze a Local Directory (Standard Analysis)

```bash
curl -X POST http://localhost:3000/api/v1/analyze/job \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{
    "source_type": "directory",
    "source_uri": "/path/to/project",
    "analysis_depth": "standard"
  }'
```

### Analyze an S3 Bucket

Analyze code stored in an AWS S3 bucket. Requires AWS credentials passed via the `X-AWS-Credentials` header as Base64-encoded JSON.

#### Credential Format

The `X-AWS-Credentials` header expects Base64-encoded JSON with the following structure:

```json
{
  "access_key_id": "AKIAIOSFODNN7EXAMPLE",
  "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "session_token": "optional-sts-session-token",
  "region": "us-east-1"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `access_key_id` | Yes | AWS access key ID |
| `secret_access_key` | Yes | AWS secret access key |
| `session_token` | No | STS session token for temporary credentials |
| `region` | No | AWS region (defaults to `us-east-1` if not provided) |

#### Supported S3 URI Formats

- `s3://bucket-name` - Analyze entire bucket
- `s3://bucket-name/prefix/path` - Analyze specific prefix
- `https://bucket-name.s3.amazonaws.com/prefix` - Virtual-hosted style URL
- `https://bucket-name.s3.us-west-2.amazonaws.com/prefix` - With region
- `https://s3.us-east-1.amazonaws.com/bucket-name/prefix` - Path-style URL

#### Example: Basic S3 Analysis

```bash
# Encode credentials as Base64
AWS_CREDS=$(echo -n '{"access_key_id":"AKIAIOSFODNN7EXAMPLE","secret_access_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","region":"us-east-1"}' | base64)

curl -X POST http://localhost:3000/api/v1/analyze/job \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -H "X-AWS-Credentials: $AWS_CREDS" \
  -d '{
    "source_type": "s3_bucket",
    "source_uri": "s3://my-code-bucket/project-v1",
    "analysis_depth": "full"
  }'
```

#### Example: Using STS Temporary Credentials

For enhanced security, use AWS STS to generate temporary credentials:

```bash
# Get temporary credentials from STS
TEMP_CREDS=$(aws sts get-session-token --duration-seconds 3600)

# Extract and encode for header
AWS_CREDS=$(echo -n "{
  \"access_key_id\": \"$(echo $TEMP_CREDS | jq -r '.Credentials.AccessKeyId')\",
  \"secret_access_key\": \"$(echo $TEMP_CREDS | jq -r '.Credentials.SecretAccessKey')\",
  \"session_token\": \"$(echo $TEMP_CREDS | jq -r '.Credentials.SessionToken')\",
  \"region\": \"us-east-1\"
}" | base64 -w 0)

curl -X POST http://localhost:3000/api/v1/analyze/job \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -H "X-AWS-Credentials: $AWS_CREDS" \
  -d '{
    "source_type": "s3_bucket",
    "source_uri": "s3://my-secure-bucket/source-code",
    "analysis_depth": "full"
  }'
```

#### S3 Analysis Limits

To prevent abuse, S3 bucket analysis has the following limits:

- Maximum 10,000 objects per analysis
- Maximum 1 GB total download size
- Objects exceeding limits are skipped with warnings

### Analysis Depth Levels

- `minimal`: Fast analysis with essential checks only
- `standard`: Balanced analysis with comprehensive checks (default)
- `full`: Deep analysis including optional checks and extended scanning

### Response Format

The unified analysis response includes:

- `job_id`: Unique identifier for the analysis job
- `status`: Job execution status
- `summary`: Aggregated summary of findings across all modules
- `findings`: Array of findings from all executed modules, each tagged with module type

## Dependency Analysis Endpoint

Direct dependency analysis endpoint:

```bash
curl -X POST http://localhost:3000/api/v1/dependencies/analyze \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{
    "file_content": "express@4.17.1\nlodash@4.17.20",
    "ecosystem": "npm",
    "filename": "package.json"
  }'
```

## API Documentation

Interactive API documentation is available at:

- Swagger UI: <http://localhost:3000/docs>
- OpenAPI Spec: <http://localhost:3000/docs/openapi.json>
