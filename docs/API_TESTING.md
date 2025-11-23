# API Testing Guide

This guide covers testing the Vulnera API, including authentication, endpoints, and integration testing.

## Prerequisites

- Vulnera API running (see [Quick Start Guide](QUICK_START.md))
- `curl` or similar HTTP client
- Optional: API testing tools like Postman, Insomnia, or HTTPie

## Base URL

All examples assume the API is running at `http://localhost:3000`. Adjust for your deployment.

## Health Check

First, verify the API is running:

```bash
curl http://localhost:3000/health
```

Expected response:

```json
{
  "status": "healthy",
  "version": "0.3.0",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Authentication Testing

### 1. Register a New User

```bash
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPassword123"
  }'
```

Save the `access_token` and `refresh_token` from the response.

### 2. Login

```bash
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPassword123"
  }'
```

### 3. Refresh Token

```bash
curl -X POST http://localhost:3000/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "your_refresh_token_here"
  }'
```

### 4. Create API Key

```bash
curl -X POST http://localhost:3000/api/v1/auth/api-keys \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test API Key"
  }'
```

Save the `key` value - it cannot be retrieved later!

### 5. List API Keys

```bash
curl -X GET http://localhost:3000/api/v1/auth/api-keys \
  -H "Authorization: Bearer <access_token>"
```

## Dependency Analysis Testing

### Test Dependency File Analysis

```bash
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "file_content": "django==3.2.0\nrequests>=2.25.0",
    "ecosystem": "PyPI",
    "filename": "requirements.txt"
  }'
```

### Test with Authentication

```bash
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "file_content": "express@4.17.1\nlodash@4.17.20",
    "ecosystem": "npm",
    "filename": "package.json"
  }'
```

### Test Repository Analysis

```bash
curl -X POST http://localhost:3000/api/v1/analyze/repository \
  -H "Content-Type: application/json" \
  -d '{
    "repository_url": "https://github.com/rust-lang/cargo",
    "ref": "main"
  }'
```

## Unified Analysis Testing

### Test Full Repository Analysis

```bash
curl -X POST http://localhost:3000/api/v1/analyze/job \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "source_type": "git",
    "source_uri": "https://github.com/my-org/my-project.git",
    "analysis_depth": "full"
  }'
```

### Test Minimal Analysis

```bash
curl -X POST http://localhost:3000/api/v1/analyze/job \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "source_type": "git",
    "source_uri": "https://github.com/my-org/my-project.git",
    "analysis_depth": "minimal"
  }'
```

The `/api/v1/analyze/job` endpoint now responds asynchronously. A `202 Accepted` response looks like this:

```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "callback_url": null,
  "message": "Analysis job accepted for asynchronous execution"
}
```

Use the returned `job_id` to poll job status:

```bash
curl -H "Authorization: Bearer <access_token>" \
  http://localhost:3000/api/v1/jobs/550e8400-e29b-41d4-a716-446655440000
```

When the background workers finish, `GET /api/v1/jobs/{id}` includes the aggregated `summary`, `findings`, and the API key/user metadata used to launch the scan. Provide a `callback_url` in the original request to receive future webhook deliveries once transport code is wired up.

## Error Testing

### Test Invalid Authentication

```bash
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Authorization: Bearer invalid_token" \
  -H "Content-Type: application/json" \
  -d '{
    "ecosystem": "npm",
    "content": "express@4.17.1"
  }'
```

Expected: `401 Unauthorized`

### Test Invalid Request

```bash
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "invalid_field": "value"
  }'
```

Expected: `400 Bad Request` with validation errors

### Test Missing Required Fields

```bash
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com"
  }'
```

Expected: `400 Bad Request` with missing field error

## Using API Keys

### Test with X-API-Key Header

```bash
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "X-API-Key: vuln_your_api_key_here" \
  -H "Content-Type: application/json" \
  -d '{
    "ecosystem": "npm",
    "content": "express@4.17.1"
  }'
```

### Test with Authorization Header

```bash
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Authorization: ApiKey vuln_your_api_key_here" \
  -H "Content-Type: application/json" \
  -d '{
    "ecosystem": "npm",
    "content": "express@4.17.1"
  }'
```

## Testing Different Ecosystems

### Python (PyPI)

```bash
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "file_content": "django==3.2.0\nflask==1.1.0",
    "ecosystem": "PyPI",
    "filename": "requirements.txt"
  }'
```

### Node.js (npm)

```bash
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "file_content": "{\"dependencies\": {\"express\": \"4.17.1\"}}",
    "ecosystem": "npm",
    "filename": "package.json"
  }'
```

### Rust (Cargo)

```bash
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "file_content": "[dependencies]\nserde = \"1.0\"",
    "ecosystem": "Cargo",
    "filename": "Cargo.toml"
  }'
```

## Automated Testing Scripts

### Bash Test Script Example

```bash
#!/bin/bash

BASE_URL="http://localhost:3000"
EMAIL="test@example.com"
PASSWORD="TestPassword123"

# Register
echo "Registering user..."
REGISTER_RESPONSE=$(curl -s -X POST "$BASE_URL/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$EMAIL\", \"password\": \"$PASSWORD\"}")

ACCESS_TOKEN=$(echo $REGISTER_RESPONSE | jq -r '.access_token')

# Test analysis
echo "Testing analysis..."
curl -X POST "$BASE_URL/api/v1/analyze" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "file_content": "django==3.2.0",
    "ecosystem": "PyPI",
    "filename": "requirements.txt"
  }'
```

## Integration Testing

### Test Complete Workflow

1. Register user
2. Create API key
3. Analyze dependencies
4. Run unified analysis
5. Verify results

### Test Rate Limiting

Make multiple rapid requests to test rate limiting:

```bash
for i in {1..10}; do
  curl -X POST http://localhost:3000/api/v1/analyze \
    -H "Content-Type: application/json" \
    -d '{
      "file_content": "django==3.2.0",
      "ecosystem": "PyPI",
      "filename": "requirements.txt"
    }'
  echo "Request $i"
done
```

## OpenAPI Documentation

Interactive API documentation is available at:

- Swagger UI: <http://localhost:3000/docs>
- OpenAPI Spec: <http://localhost:3000/docs/openapi.json>

Use the Swagger UI to:

- Explore all available endpoints
- Test endpoints directly in the browser
- View request/response schemas
- See example requests and responses

## Best Practices

1. **Use environment variables** for tokens and URLs
2. **Test error cases** as well as success cases
3. **Verify response schemas** match expectations
4. **Test authentication** before protected endpoints
5. **Clean up test data** after testing
6. **Use API keys** for automated testing
7. **Check rate limits** in your test scenarios

## Troubleshooting

### Connection Refused

- Verify API is running: `curl http://localhost:3000/health`
- Check port number matches configuration
- Verify firewall settings

### Authentication Errors

- Check token expiration
- Verify token format (Bearer prefix)
- Ensure user exists and credentials are correct

### Validation Errors

- Check request body matches API schema
- Verify required fields are present
- Check data types match expected formats

For more help, see the [Troubleshooting](../README.md#-troubleshooting) section in the main README.
