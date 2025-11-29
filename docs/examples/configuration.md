# Configuration Examples

Vulnera can be configured via TOML files in the `config/` directory and environment variables (with `VULNERA__` prefix).

## Configuration Profiles

Configuration profiles are selected via the `ENV` environment variable:

- `development` - Development settings (default)
- `production` - Production settings

## Server Configuration

### Basic Server Settings

```bash
# Server port
VULNERA__SERVER__PORT=8080

# Server host
VULNERA__SERVER__HOST=0.0.0.0

# Enable/disable API documentation
VULNERA__SERVER__ENABLE_DOCS=true

# CORS allowed origins (JSON array)
VULNERA__SERVER__ALLOWED_ORIGINS='["*"]'  # Use specific origins in production
```

### Security Headers

```bash
# Enforce HTTPS
VULNERA__SERVER__SECURITY__ENFORCE_HTTPS=false

# Enable security headers
VULNERA__SERVER__SECURITY__ENABLE_SECURITY_HEADERS=false

# HSTS max age (seconds)
VULNERA__SERVER__SECURITY__HSTS_MAX_AGE=31536000
```

## Database Configuration

### Required Database Settings

```bash
# Database connection URL (required)
DATABASE_URL='postgresql://user:password@localhost:5432/vulnera'

# Or via config
VULNERA__DATABASE__URL='postgresql://user:password@localhost:5432/vulnera'
```

### Connection Pool Settings

```bash
VULNERA__DATABASE__MAX_CONNECTIONS=10
VULNERA__DATABASE__MIN_IDLE=2
VULNERA__DATABASE__CONNECT_TIMEOUT_SECONDS=30
VULNERA__DATABASE__MAX_LIFETIME_SECONDS=1800
VULNERA__DATABASE__IDLE_TIMEOUT_SECONDS=600
```

## Authentication Configuration

### Required Authentication Settings

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
# Dragonfly DB connection URL
VULNERA__CACHE__DRAGONFLY_URL="redis://127.0.0.1:6379"

# Connection timeout (seconds)
VULNERA__CACHE__DRAGONFLY_CONNECTION_TIMEOUT_SECONDS=5

# Cache TTL (hours)
VULNERA__CACHE__TTL_HOURS=24

# L1 cache size (MB)
VULNERA__CACHE__L1_CACHE_SIZE_MB=100

# Enable cache compression
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
# NVD API key (optional, increases rate limits)
VULNERA__APIS__NVD__API_KEY=your_nvd_api_key

# NVD base URL
VULNERA__APIS__NVD__BASE_URL="https://services.nvd.nist.gov/rest/json"

# Timeout (seconds)
VULNERA__APIS__NVD__TIMEOUT_SECONDS=30
```

### GitHub Security Advisories (GHSA)

```bash
# GitHub token for GHSA GraphQL API
VULNERA__APIS__GHSA__TOKEN=your_github_token

# GHSA GraphQL URL
VULNERA__APIS__GHSA__GRAPHQL_URL="https://api.github.com/graphql"

# Timeout (seconds)
VULNERA__APIS__GHSA__TIMEOUT_SECONDS=30
```

### GitHub API

```bash
# GitHub token is unified: VULNERA__APIS__GHSA__TOKEN is used for both
# GHSA vulnerability queries and GitHub repository analysis operations
# No separate VULNERA__APIS__GITHUB__TOKEN needed

# Base URL
VULNERA__APIS__GITHUB__BASE_URL="https://api.github.com"

# Base URL
VULNERA__APIS__GITHUB__BASE_URL="https://api.github.com"

# Maximum concurrent file fetches
VULNERA__APIS__GITHUB__MAX_CONCURRENT_FILE_FETCHES=8

# Maximum files scanned per repository
VULNERA__APIS__GITHUB__MAX_FILES_SCANNED=200

# Maximum total bytes
VULNERA__APIS__GITHUB__MAX_TOTAL_BYTES=2000000

# Maximum single file size (bytes)
VULNERA__APIS__GITHUB__MAX_SINGLE_FILE_BYTES=1000000
```

## SAST Module Configuration

```bash
# Maximum scan depth
VULNERA__SAST__MAX_SCAN_DEPTH=10

# Exclude patterns (JSON array)
VULNERA__SAST__EXCLUDE_PATTERNS='["node_modules", ".git", "target", "__pycache__"]'

# Custom rule file path (optional)
VULNERA__SAST__RULE_FILE_PATH=/path/to/custom-rules.toml

# Enable logging
VULNERA__SAST__ENABLE_LOGGING=true
```

## Secrets Detection Module Configuration

```bash
# Maximum scan depth
VULNERA__SECRET_DETECTION__MAX_SCAN_DEPTH=10

# Exclude patterns (JSON array)
VULNERA__SECRET_DETECTION__EXCLUDE_PATTERNS='["node_modules", ".git", "*.lock"]'

# Base64 entropy threshold
VULNERA__SECRET_DETECTION__BASE64_ENTROPY_THRESHOLD=4.5

# Hex entropy threshold
VULNERA__SECRET_DETECTION__HEX_ENTROPY_THRESHOLD=3.0

# Enable entropy detection
VULNERA__SECRET_DETECTION__ENABLE_ENTROPY_DETECTION=true

# Maximum file size (bytes)
VULNERA__SECRET_DETECTION__MAX_FILE_SIZE_BYTES=10485760  # 10MB

# Enable secret verification
VULNERA__SECRET_DETECTION__ENABLE_VERIFICATION=false

# Scan git history
VULNERA__SECRET_DETECTION__SCAN_GIT_HISTORY=false

# Maximum commits to scan (null = unlimited)
VULNERA__SECRET_DETECTION__MAX_COMMITS_TO_SCAN=null
```

## API Security Module Configuration

```bash
# Enabled analyzers (empty array = all enabled)
VULNERA__API_SECURITY__ENABLED_ANALYZERS='[]'

# Available analyzers:
# - authentication
# - authorization
# - input_validation
# - data_exposure
# - design
# - security_headers
# - oauth

# Strict mode (more aggressive checks)
VULNERA__API_SECURITY__STRICT_MODE=false

# Exclude paths (JSON array)
VULNERA__API_SECURITY__EXCLUDE_PATHS='[]'
```

## Logging Configuration

```bash
# Log level: trace, debug, info, warn, error
VULNERA__LOGGING__LEVEL=info

# Log format: json, pretty
VULNERA__LOGGING__FORMAT=json
```

## Complete Example Configuration File

Create a `.env` file in the project root:

```bash
# Environment
ENV=development

# Database
DATABASE_URL='postgresql://user:password@localhost:5432/vulnera'

# Authentication
VULNERA__AUTH__JWT_SECRET='your-secret-minimum-32-characters'
VULNERA__AUTH__TOKEN_TTL_HOURS=24
VULNERA__AUTH__REFRESH_TOKEN_TTL_HOURS=720

# Server
VULNERA__SERVER__PORT=3000
VULNERA__SERVER__ENABLE_DOCS=true

# Cache
VULNERA__CACHE__DRAGONFLY_URL="redis://127.0.0.1:6379"
VULNERA__CACHE__TTL_HOURS=24

# External APIs
VULNERA__APIS__NVD__API_KEY=your_nvd_api_key
# GitHub Personal Access Token (ghp_*) - used for both GHSA and GitHub API
VULNERA__APIS__GHSA__TOKEN=your_github_token

# Analysis
VULNERA__ANALYSIS__MAX_CONCURRENT_PACKAGES=3
```

## TOML Configuration Files

Configuration can also be set in TOML files in the `config/` directory:

- `config/default.toml` - Default configuration
- `config/development.toml` - Development overrides
- `config/production.toml` - Production overrides

Environment variables take precedence over TOML files.
