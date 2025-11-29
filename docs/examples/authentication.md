# Authentication Examples

Vulnera supports two authentication methods:

1. **HttpOnly Cookie-based Authentication** (recommended for browsers) - Secure, automatic, with CSRF protection
2. **API Keys** (for CLI, CI/CD, and service integrations) - Long-lived, explicit header authentication

## Method 1: HttpOnly Cookie-based Authentication (Browser)

This method uses HttpOnly cookies set automatically by the server. Cookies are only sent with same-origin requests and are protected against CSRF attacks.

### User Registration

Create a new user account. The server responds with HttpOnly cookies:

```bash
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123"
  }'
```

**Response:**

```json
{
  "csrf_token": "K8pQ2xWvY9nZ3hJ4mFoRsT5uApBqCdEfGhIjKlMnOpQr",
  "expires_in": 86400,
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "roles": ["user"]
}
```

**Cookies automatically set by server:**

- `access_token` (HttpOnly, 24 hours)
- `refresh_token` (HttpOnly, 30 days)
- `csrf_token` (readable by JavaScript, 24 hours)

The `-c cookies.txt` flag saves cookies for subsequent requests.

### Login

Login with email and password:

```bash
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123"
  }'
```

**Response:** Same as registration - includes `csrf_token` in response body and sets cookies.

### Making Authenticated Requests

For GET requests (safe methods), cookies are sent automatically:

```bash
curl -X GET http://localhost:3000/api/v1/auth/api-keys \
  -b cookies.txt
```

For POST/PUT/PATCH/DELETE requests (state-changing), you must also include the CSRF token in the `X-CSRF-Token` header:

```bash
# Extract CSRF token from the login response (or from cookies.txt as a JavaScript app would)
CSRF_TOKEN="K8pQ2xWvY9nZ3hJ4mFoRsT5uApBqCdEfGhIjKlMnOpQr"

curl -X POST http://localhost:3000/api/v1/analyze/job \
  -b cookies.txt \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "source": {"type": "directory", "path": "."}
  }'
```

### Refreshing Tokens

When your access token expires (after 24 hours), refresh it:

```bash
# No CSRF token needed - the refresh_token cookie (HttpOnly, SameSite=Strict)
# already provides sufficient CSRF protection
curl -X POST http://localhost:3000/api/v1/auth/refresh \
  -b cookies.txt \
  -c cookies.txt
```

**Response:**

```json
{
  "csrf_token": "NewCsrfTokenHere...",
  "expires_in": 86400
}
```

**Important:** The refresh endpoint implements **token rotation** - each refresh invalidates the old refresh token and issues a new one. This limits the damage if a refresh token is compromised. Always use `-c cookies.txt` to save the new refresh token cookie.

### Logout

```bash
CSRF_TOKEN="K8pQ2xWvY9nZ3hJ4mFoRsT5uApBqCdEfGhIjKlMnOpQr"

curl -X POST http://localhost:3000/api/v1/auth/logout \
  -b cookies.txt \
  -H "X-CSRF-Token: $CSRF_TOKEN"
```

This invalidates your tokens server-side and clears cookies.

**Best for:**

- Web applications (single-page apps, server-rendered apps)
- Browser-based clients
- Automatic token management
- Built-in CSRF protection

---

## Method 2: API Keys (Service Integration)

### Create an API Key

To create an API key, you must first authenticate using cookie-based auth and provide CSRF token:

```bash
CSRF_TOKEN="K8pQ2xWvY9nZ3hJ4mFoRsT5uApBqCdEfGhIjKlMnOpQr"

curl -X POST http://localhost:3000/api/v1/auth/api-keys \
  -b cookies.txt \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
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
curl -X POST http://localhost:3000/api/v1/analyze/job \
  -H "X-API-Key: vuln_abc123..." \
  -H "Content-Type: application/json" \
  -d '{
    "source": {"type": "directory", "path": "."}
  }'
```

### Use API Key - Option B: Authorization Header

```bash
curl -X POST http://localhost:3000/api/v1/analyze/job \
  -H "Authorization: ApiKey vuln_abc123..." \
  -H "Content-Type: application/json" \
  -d '{
    "source": {"type": "directory", "path": "."}
  }'
```

**Important:** API key requests bypass CSRF validation (no need for `X-CSRF-Token` header).

**Best for:**

- CI/CD pipelines
- Automated scripts
- Service-to-service communication
- Long-lived integrations

### List API Keys

List all your API keys (keys are masked for security):

```bash
curl -X GET http://localhost:3000/api/v1/auth/api-keys \
  -b cookies.txt
```

### Revoke an API Key

Delete an API key:

```bash
CSRF_TOKEN="K8pQ2xWvY9nZ3hJ4mFoRsT5uApBqCdEfGhIjKlMnOpQr"

curl -X DELETE http://localhost:3000/api/v1/auth/api-keys/{key_id} \
  -b cookies.txt \
  -H "X-CSRF-Token: $CSRF_TOKEN"
```

## Authentication Endpoints Summary

| Endpoint | Method | Auth | CSRF Required | Description |
|---|---|---|---|---|
| `/api/v1/auth/register` | POST | None | No | Create new user account |
| `/api/v1/auth/login` | POST | None | No | Login with email/password |
| `/api/v1/auth/refresh` | POST | Cookie | No* | Refresh expired access token |
| `/api/v1/auth/logout` | POST | Cookie | Yes | Logout and invalidate tokens |

> *The refresh endpoint does not require CSRF because the `refresh_token` cookie (HttpOnly, SameSite=Strict) already provides sufficient CSRF protection. This simplifies client implementations while maintaining security.
| `/api/v1/auth/api-keys` | POST | Cookie | Yes | Create new API key |
| `/api/v1/auth/api-keys` | GET | Cookie/ApiKey | No | List your API keys |
| `/api/v1/auth/api-keys/{id}` | DELETE | Cookie | Yes | Revoke an API key |

## Security Features

- ✅ **HttpOnly Cookies** - Tokens not accessible to JavaScript, preventing XSS token theft
- ✅ **CSRF Protection** - Double-submit cookie pattern with constant-time validation
- ✅ **SameSite Policy** - Cookies with SameSite=Lax to prevent cross-site request forgery
- ✅ **Bcrypt Password Hashing** - Cost factor 12 with random salts
- ✅ **API Keys** - Long-lived, hashed before storage, never retrievable
- ✅ **JWT Signing** - HMAC-SHA256 for token integrity
- ✅ **Configurable Expiration** - Access tokens (24h), refresh tokens (30d), API keys (1y)
- ✅ **Token Blacklisting** - Invalidated tokens on logout
- ✅ **Brute-Force Protection** - Rate limiting on login endpoints
- ✅ **Role-Based Access Control** - User roles and permissions

## Browser Integration Example

For JavaScript/TypeScript applications:

```javascript
// Login and get CSRF token
const loginResponse = await fetch('http://localhost:3000/api/v1/auth/login', {
  method: 'POST',
  credentials: 'include', // Include cookies
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password })
});

const { csrf_token } = await loginResponse.json();

// Store CSRF token for subsequent requests
localStorage.setItem('csrf_token', csrf_token);

// Make authenticated request with CSRF protection
const response = await fetch('http://localhost:3000/api/v1/analyze/job', {
  method: 'POST',
  credentials: 'include', // Include cookies (automatic)
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': csrf_token  // Required for POST/PUT/PATCH/DELETE
  },
  body: JSON.stringify({ /* analysis request */ })
});
```

**Key points:**

- Set `credentials: 'include'` to send cookies with cross-origin requests
- Extract and store `csrf_token` from login response
- Add `X-CSRF-Token` header to all state-changing requests
- GET requests don't need the CSRF token
