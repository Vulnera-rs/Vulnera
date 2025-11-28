# API Testing

This guide covers testing the Vulnera API, including authentication, endpoints, and integration testing.

## Prerequisites

- Vulnera API running (see [Quick Start](../getting-started/quick-start.md))
- `curl` or similar HTTP client
- Optional: API testing tools like Postman, Insomnia, or HTTPie

## Base URL

All examples assume the API is running at `http://localhost:3000`. Adjust for your deployment.

## Health Check

Verify the API is running:

```bash
curl http://localhost:3000/health
```

Expected response:

```json
{
  "status": "healthy",
  "version": "0.3.2",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Authentication Testing

### Register a New User

```bash
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPassword123"
  }'
```

Save the `access_token` and `refresh_token` from the response.

### Login

```bash
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPassword123"
  }'
```

### Refresh Token

```bash
curl -X POST http://localhost:3000/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "your_refresh_token_here"
  }'
```

### Create API Key

```bash
curl -X POST http://localhost:3000/api/v1/auth/api-keys \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test API Key"
  }'
```

> **Important:** Save the `key` value immediately — it cannot be retrieved later!

## Dependency Analysis Testing

### Analyze Dependencies

```bash
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "file_content": "django==3.2.0\nrequests>=2.25.0",
    "ecosystem": "PyPI",
    "filename": "requirements.txt"
  }'
```

### With Authentication

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

## Unified Analysis Testing

### Full Repository Analysis

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

The endpoint responds asynchronously with a `202 Accepted`:

```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "callback_url": null,
  "message": "Analysis job accepted for asynchronous execution"
}
```

### Check Job Status

```bash
curl -H "Authorization: Bearer <access_token>" \
  http://localhost:3000/api/v1/jobs/550e8400-e29b-41d4-a716-446655440000
```

When complete, the response includes `summary`, `modules`, and `findings_by_type`.

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

## Using API Keys

### X-API-Key Header

```bash
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "X-API-Key: vuln_your_api_key_here" \
  -H "Content-Type: application/json" \
  -d '{
    "ecosystem": "npm",
    "content": "express@4.17.1"
  }'
```

### Authorization Header

```bash
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Authorization: ApiKey vuln_your_api_key_here" \
  -H "Content-Type: application/json" \
  -d '{
    "ecosystem": "npm",
    "content": "express@4.17.1"
  }'
```

## Error Testing

### Invalid Authentication

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

### Invalid Request

```bash
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "invalid_field": "value"
  }'
```

Expected: `400 Bad Request` with validation errors

## Rate Limiting Test

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

- **Swagger UI:** <http://localhost:3000/docs>
- **OpenAPI Spec:** <http://localhost:3000/docs/openapi.json>

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
