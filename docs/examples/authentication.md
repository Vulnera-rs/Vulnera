# Authentication Examples

Vulnera supports two authentication methods: JWT Bearer tokens for interactive sessions and API keys for service integrations.

## User Registration

Create a new user account. Returns access and refresh tokens immediately:

```bash
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123"
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 86400
}
```

## Login

Login with email and password:

```bash
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123"
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 86400
}
```

## Refresh Token

Refresh an expired access token:

```bash
curl -X POST http://localhost:3000/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

## Method 1: JWT Bearer Token (Interactive Sessions)

Use the access token from login/registration in the Authorization header:

```bash
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "ecosystem": "npm",
    "content": "express@4.17.1"
  }'
```

**Best for:**
- Web applications
- Interactive API clients
- Short-lived sessions (default 24 hours)

## Method 2: API Keys (Service Integration)

### Create an API Key

First, create an API key using your JWT token:

```bash
curl -X POST http://localhost:3000/api/v1/auth/api-keys \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "CI/CD Integration"
  }'
```

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "CI/CD Integration",
  "key": "vuln_a1b2c3d4e5f6...",
  "created_at": "2024-01-15T10:30:00Z",
  "expires_at": "2025-01-15T10:30:00Z"
}
```

**Important:** Save the `key` value immediately - it cannot be retrieved later!

### Use API Key - Option A: X-API-Key Header

```bash
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "X-API-Key: vuln_abc123..." \
  -H "Content-Type: application/json" \
  -d '{
    "ecosystem": "npm",
    "content": "express@4.17.1"
  }'
```

### Use API Key - Option B: Authorization Header

```bash
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Authorization: ApiKey vuln_abc123..." \
  -H "Content-Type: application/json" \
  -d '{
    "ecosystem": "npm",
    "content": "express@4.17.1"
  }'
```

**Best for:**
- CI/CD pipelines
- Automated scripts
- Service-to-service communication
- Long-lived integrations

### List API Keys

List all your API keys (keys are masked for security):

```bash
curl -X GET http://localhost:3000/api/v1/auth/api-keys \
  -H "Authorization: Bearer <access_token>"
```

### Revoke an API Key

Delete an API key:

```bash
curl -X DELETE http://localhost:3000/api/v1/auth/api-keys/{key_id} \
  -H "Authorization: Bearer <access_token>"
```

## Authentication Endpoints Summary

| Endpoint                     | Method | Auth          | Description                  |
| ---------------------------- | ------ | ------------- | ---------------------------- |
| `/api/v1/auth/register`      | POST   | None          | Create new user account      |
| `/api/v1/auth/login`         | POST   | None          | Login with email/password    |
| `/api/v1/auth/refresh`       | POST   | None          | Refresh expired access token |
| `/api/v1/auth/api-keys`      | POST   | Bearer        | Create new API key           |
| `/api/v1/auth/api-keys`      | GET    | Bearer/ApiKey | List your API keys           |
| `/api/v1/auth/api-keys/{id}` | DELETE | Bearer        | Revoke an API key            |

## Security Features

- ✅ Bcrypt password hashing (cost factor 12)
- ✅ API keys hashed before storage (never retrievable)
- ✅ JWT tokens with HMAC-SHA256 signing
- ✅ Configurable token expiration
- ✅ API key masking in list operations
- ✅ Role-based access control support

