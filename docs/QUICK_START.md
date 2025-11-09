# Quick Start Guide

Get up and running with Vulnera in minutes.

## Prerequisites

- **Rust 1.82+** - [Install Rust](https://www.rust-lang.org/tools/install)
- **PostgreSQL 12+** - [Install PostgreSQL](https://www.postgresql.org/download/) or use Docker
- **SQLx CLI** - For database migrations:
  ```bash
  cargo install sqlx-cli --no-default-features --features postgres
  ```
- **Dragonfly DB** (optional but recommended) - For caching:
  ```bash
  docker run -d --name dragonfly -p 6379:6379 docker.dragonflydb.io/dragonflydb/dragonfly
  ```

## Installation

### Option 1: From Source

1. **Clone the repository:**
   ```bash
   git clone https://github.com/k5602/Vulnera.git
   cd Vulnera
   ```

2. **Install Rust (if needed):**
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source ~/.cargo/env
   ```

3. **Install system dependencies (Ubuntu/Debian):**
   ```bash
   sudo apt-get install -y pkg-config libssl-dev
   ```

4. **Set up the database:**
   ```bash
   export DATABASE_URL='postgresql://user:password@localhost:5432/vulnera'
   sqlx migrate run --source migrations
   ```

5. **Build and run:**
   ```bash
   cargo build --release
   cargo run
   ```

### Option 2: Using Docker

1. **Build the image:**
   ```bash
   DOCKER_BUILDKIT=1 docker build -t vulnera-rust .
   ```

2. **Run the container:**
   ```bash
   docker run -p 3000:3000 \
     -e DATABASE_URL='postgresql://user:password@host:5432/vulnera' \
     vulnera-rust
   ```

3. **Run migrations (recommended for production):**
   ```bash
   docker run --rm \
     -e DATABASE_URL='postgresql://user:password@host:5432/vulnera' \
     vulnera-rust sqlx migrate run --source /app/migrations
   ```

## Configuration

Create a `.env` file in the project root:

```bash
# Database (required)
DATABASE_URL='postgresql://user:password@localhost:5432/vulnera'

# Authentication (required for production)
VULNERA__AUTH__JWT_SECRET='your-secret-minimum-32-characters'

# Cache (optional, but recommended)
VULNERA__CACHE__DRAGONFLY_URL="redis://127.0.0.1:6379"
```

See [Configuration Examples](examples/configuration.md) for all available options.

## Verify Installation

1. **Check health endpoint:**
   ```bash
   curl http://localhost:3000/health
   ```

2. **Access API documentation:**
   Open http://localhost:3000/docs in your browser

## First Steps

1. **Register a user:**
   ```bash
   curl -X POST http://localhost:3000/api/v1/auth/register \
     -H "Content-Type: application/json" \
     -d '{
       "email": "user@example.com",
       "password": "SecurePassword123"
     }'
   ```

2. **Analyze a dependency file:**
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

- Read the [API Usage Examples](examples/api-usage.md)
- Learn about [Authentication](examples/authentication.md)
- Explore [Analysis Modules](examples/analysis-modules.md)
- Check the [Configuration Guide](examples/configuration.md)
- Review the [Database Setup Guide](SQLX_SETUP.md)

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

- Get API keys for better rate limits:
  - [NVD API Key](https://nvd.nist.gov/developers/request-an-api-key)
  - [GitHub Token](https://github.com/settings/tokens)

For more help, see the [Troubleshooting](../README.md#-troubleshooting) section in the main README.

