# Configuration

Vulnera can be configured via TOML files in the `config/` directory and environment variables with the `VULNERA__` prefix.

## Configuration Profiles

Configuration profiles are selected via the `ENV` environment variable:

- `development` — Development settings (default)
- `production` — Production settings

## Essential Configuration

```bash
# Database (required)
DATABASE_URL='postgresql://user:password@localhost:5432/vulnera'

# Authentication (required for production)
VULNERA__AUTH__JWT_SECRET='your-secret-minimum-32-characters'

# Cache (optional, recommended)
VULNERA__CACHE__DRAGONFLY_URL="redis://127.0.0.1:6379"
```

## Server Configuration

### Basic Server Settings

```bash
VULNERA__SERVER__PORT=8080
VULNERA__SERVER__HOST=0.0.0.0
VULNERA__SERVER__ENABLE_DOCS=true
VULNERA__SERVER__ALLOWED_ORIGINS='["*"]'  # Use specific origins in production
```

### Security Headers

```bash
VULNERA__SERVER__SECURITY__ENFORCE_HTTPS=false
VULNERA__SERVER__SECURITY__ENABLE_SECURITY_HEADERS=false
VULNERA__SERVER__SECURITY__HSTS_MAX_AGE=31536000
```

## Database Configuration

### Connection Pool Settings

```bash
VULNERA__DATABASE__MAX_CONNECTIONS=10
VULNERA__DATABASE__MIN_IDLE=2
VULNERA__DATABASE__CONNECT_TIMEOUT_SECONDS=30
VULNERA__DATABASE__MAX_LIFETIME_SECONDS=1800
VULNERA__DATABASE__IDLE_TIMEOUT_SECONDS=600
```

## Authentication Configuration

```bash
# JWT secret (minimum 32 characters, required for production)
VULNERA__AUTH__JWT_SECRET='your-secret-minimum-32-characters'

# Token expiration (hours)
VULNERA__AUTH__TOKEN_TTL_HOURS=24

# Refresh token expiration (hours, default: 720 = 30 days)
VULNERA__AUTH__REFRESH_TOKEN_TTL_HOURS=720

# API key length
VULNERA__AUTH__API_KEY_LENGTH=32

# API key expiration (days, null for no expiration)
VULNERA__AUTH__API_KEY_TTL_DAYS=365
```

## Cache Configuration

### Dragonfly DB Cache

```bash
VULNERA__CACHE__DRAGONFLY_URL="redis://127.0.0.1:6379"
VULNERA__CACHE__DRAGONFLY_CONNECTION_TIMEOUT_SECONDS=5
VULNERA__CACHE__TTL_HOURS=24
VULNERA__CACHE__L1_CACHE_SIZE_MB=100
VULNERA__CACHE__ENABLE_CACHE_COMPRESSION=true
```

## Analysis Configuration

### Concurrent Processing

```bash
# Maximum concurrent packages analyzed
VULNERA__ANALYSIS__MAX_CONCURRENT_PACKAGES=3

# Maximum concurrent registry queries
VULNERA__ANALYSIS__MAX_CONCURRENT_REGISTRY_QUERIES=5

# Maximum concurrent API calls
VULNERA__ANALYSIS__MAX_CONCURRENT_API_CALLS=10
```

### Recommendations

```bash
# Exclude prerelease versions from recommendations
VULNERA__RECOMMENDATIONS__EXCLUDE_PRERELEASES=false

# Maximum version queries per request
VULNERA__RECOMMENDATIONS__MAX_VERSION_QUERIES_PER_REQUEST=50
```

## External API Configuration

### NVD (National Vulnerability Database)

```bash
VULNERA__APIS__NVD__API_KEY=your_nvd_api_key
VULNERA__APIS__NVD__BASE_URL="https://services.nvd.nist.gov/rest/json"
VULNERA__APIS__NVD__TIMEOUT_SECONDS=30
```

### GitHub Security Advisories (GHSA)

```bash
VULNERA__APIS__GHSA__TOKEN=your_github_token
VULNERA__APIS__GHSA__GRAPHQL_URL="https://api.github.com/graphql"
VULNERA__APIS__GHSA__TIMEOUT_SECONDS=30
```

### GitHub API

```bash
VULNERA__APIS__GITHUB__TOKEN=your_github_token
VULNERA__APIS__GITHUB__REUSE_GHSA_TOKEN=true
VULNERA__APIS__GITHUB__BASE_URL="https://api.github.com"
VULNERA__APIS__GITHUB__MAX_CONCURRENT_FILE_FETCHES=8
VULNERA__APIS__GITHUB__MAX_FILES_SCANNED=200
VULNERA__APIS__GITHUB__MAX_TOTAL_BYTES=2000000
VULNERA__APIS__GITHUB__MAX_SINGLE_FILE_BYTES=1000000
```

## Module Configuration

### SAST Module

```bash
VULNERA__SAST__MAX_SCAN_DEPTH=10
VULNERA__SAST__EXCLUDE_PATTERNS='["node_modules", ".git", "target", "__pycache__"]'
VULNERA__SAST__RULE_FILE_PATH=/path/to/custom-rules.toml
VULNERA__SAST__ENABLE_LOGGING=true
```

### Secrets Detection Module

```bash
VULNERA__SECRETS__ENTROPY_THRESHOLD_BASE64=4.5
VULNERA__SECRETS__ENTROPY_THRESHOLD_HEX=3.0
VULNERA__SECRETS__MAX_FILE_SIZE_BYTES=1000000
VULNERA__SECRETS__ENABLE_GIT_HISTORY=false
```

## Rate Limiting Configuration

```bash
VULNERA__SERVER__RATE_LIMIT__ENABLED=true
VULNERA__SERVER__RATE_LIMIT__STORAGE_BACKEND=dragonfly

# API Key tier
VULNERA__SERVER__RATE_LIMIT__TIERS__API_KEY__REQUESTS_PER_MINUTE=100
VULNERA__SERVER__RATE_LIMIT__TIERS__API_KEY__REQUESTS_PER_HOUR=2000

# Authenticated tier
VULNERA__SERVER__RATE_LIMIT__TIERS__AUTHENTICATED__REQUESTS_PER_MINUTE=60
VULNERA__SERVER__RATE_LIMIT__TIERS__AUTHENTICATED__REQUESTS_PER_HOUR=1000

# Anonymous tier
VULNERA__SERVER__RATE_LIMIT__TIERS__ANONYMOUS__REQUESTS_PER_MINUTE=20
VULNERA__SERVER__RATE_LIMIT__TIERS__ANONYMOUS__REQUESTS_PER_HOUR=100
```

## TOML Configuration File

Example `config/default.toml`:

```toml
[server]
host = "127.0.0.1"
port = 3000
enable_docs = true
allowed_origins = ["*"]

[server.security]
enforce_https = false
enable_security_headers = false
hsts_max_age = 31536000

[server.rate_limit]
enabled = true
storage_backend = "dragonfly"

[server.rate_limit.tiers.api_key]
requests_per_minute = 100
requests_per_hour = 2000

[server.rate_limit.tiers.authenticated]
requests_per_minute = 60
requests_per_hour = 1000

[server.rate_limit.tiers.anonymous]
requests_per_minute = 20
requests_per_hour = 100

[database]
max_connections = 10
min_idle = 2
connect_timeout_seconds = 30
max_lifetime_seconds = 1800
idle_timeout_seconds = 600

[auth]
token_ttl_hours = 24
refresh_token_ttl_hours = 720
api_key_length = 32
api_key_ttl_days = 365

[cache]
dragonfly_url = "redis://127.0.0.1:6379"
dragonfly_connection_timeout_seconds = 5
ttl_hours = 24
l1_cache_size_mb = 100
enable_cache_compression = true

[analysis]
max_concurrent_packages = 3
max_concurrent_registry_queries = 5
max_concurrent_api_calls = 10

[recommendations]
exclude_prereleases = false
max_version_queries_per_request = 50

[sast]
max_scan_depth = 10
exclude_patterns = ["node_modules", ".git", "target", "__pycache__"]
enable_logging = true
```

## Environment Variable Naming

Environment variables use double underscore (`__`) as a separator:

```
VULNERA__<SECTION>__<KEY>=value
```

Examples:

| TOML Path | Environment Variable |
|-----------|---------------------|
| `server.port` | `VULNERA__SERVER__PORT` |
| `auth.jwt_secret` | `VULNERA__AUTH__JWT_SECRET` |
| `cache.dragonfly_url` | `VULNERA__CACHE__DRAGONFLY_URL` |
| `analysis.max_concurrent_packages` | `VULNERA__ANALYSIS__MAX_CONCURRENT_PACKAGES` |
