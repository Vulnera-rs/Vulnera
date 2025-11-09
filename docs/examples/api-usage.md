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
- Swagger UI: http://localhost:3000/docs
- OpenAPI Spec: http://localhost:3000/docs/openapi.json

