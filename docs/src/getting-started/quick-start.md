# Quick Start

Get up and running with Vulnera in minutes.

## Prerequisites

- **Rust 1.82+** — [Install Rust](https://www.rust-lang.org/tools/install)
- **PostgreSQL 12+** — [Install PostgreSQL](https://www.postgresql.org/download/) or use Docker
- **SQLx CLI** — For database migrations
- **Dragonfly DB** (optional) — For high-performance caching

## Installation

### Option 1: From Source

```bash
# Clone the repository
git clone https://github.com/k5602/Vulnera.git
cd Vulnera

# Install SQLx CLI
cargo install sqlx-cli --no-default-features --features postgres

# Set up the database
export DATABASE_URL='postgresql://user:password@localhost:5432/vulnera'
sqlx migrate run --source migrations

# Build and run
cargo build --release
cargo run
```

### Option 2: Using Docker

```bash
# Build the image
DOCKER_BUILDKIT=1 docker build -t vulnera-rust .

# Run the container
docker run -p 3000:3000 \
  -e DATABASE_URL='postgresql://user:password@host:5432/vulnera' \
  vulnera-rust
```

### Optional: Start Dragonfly DB for Caching

```bash
docker run -d --name dragonfly -p 6379:6379 docker.dragonflydb.io/dragonflydb/dragonfly
```

## Configuration

Create a `.env` file in the project root:

```bash
# Database (required)
DATABASE_URL='postgresql://user:password@localhost:5432/vulnera'

# Authentication (required for production)
VULNERA__AUTH__JWT_SECRET='your-secret-minimum-32-characters'

# Cache (optional, recommended)
VULNERA__CACHE__DRAGONFLY_URL="redis://127.0.0.1:6379"
```

See the [Configuration Guide](../guide/configuration.md) for all available options.

## Verify Installation

1. **Check health endpoint:**

   ```bash
   curl http://localhost:3000/health
   ```

2. **Access API documentation:**
   Open <http://localhost:3000/docs> in your browser

## First Analysis

### 1. Register a User

```bash
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123"
  }'
```

### 2. Analyze Dependencies

```bash
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "file_content": "django==3.2.0\nrequests>=2.25.0",
    "ecosystem": "PyPI",
    "filename": "requirements.txt"
  }'
```

## Next Steps

- Read the [CLI Reference](../guide/cli-reference.md) for command-line usage
- Explore [API Testing](../guide/api-testing.md) for comprehensive examples
- Learn about [Authentication](../guide/authentication.md) for JWT and API keys
- Check the [Analysis Modules](../modules/overview.md) for module-specific documentation

## Troubleshooting

### Build Errors

- Ensure Rust 1.82+ is installed: `rustc --version`
- Install system dependencies: `pkg-config` and `libssl-dev`

### Database Connection Issues

- Verify PostgreSQL is running: `pg_isready`
- Check `DATABASE_URL` environment variable
- Ensure database exists: `createdb vulnera`

### Cache Issues

- Verify Dragonfly DB is running: `docker ps | grep dragonfly`
- Check connection URL: `VULNERA__CACHE__DRAGONFLY_URL`

### API Rate Limits

Get API keys for better rate limits:

- [NVD API Key](https://nvd.nist.gov/developers/request-an-api-key)
- [GitHub Token](https://github.com/settings/tokens)
