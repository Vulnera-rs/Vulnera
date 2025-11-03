# SQLx Setup Guide

## Overview

This project uses SQLx with compile-time verification of SQL queries. This ensures type safety and catches SQL errors at compile time rather than runtime. However, this requires special setup during development.

## The Problem

When you run `cargo check` or `cargo build`, you may encounter errors like:

```
error: set `DATABASE_URL` to use query macros online, or run `cargo sqlx prepare` to update the query cache
```

This happens because SQLx's `query!` macro needs to verify SQL queries against an actual database schema at compile time.

## Solutions

There are three ways to resolve this issue:

### Option 1: Docker-Based Setup (Recommended)

**Best for:** Developers who want a quick, isolated setup without installing PostgreSQL locally.

```bash
# Make the script executable (first time only)
chmod +x scripts/prepare-sqlx-docker.sh

# Run the script
./scripts/prepare-sqlx-docker.sh
```

This script will:
1. Start a temporary PostgreSQL container
2. Run all database migrations
3. Generate `sqlx-data.json` for offline compilation
4. Clean up the container automatically

**No PostgreSQL installation required!** You only need Docker.

### Option 2: Local PostgreSQL Setup

**Best for:** Developers with PostgreSQL already installed locally.

#### Prerequisites
- PostgreSQL 12+ installed and running
- SQLx CLI installed: `cargo install sqlx-cli --no-default-features --features postgres`

#### Steps

```bash
# 1. Make the script executable (first time only)
chmod +x scripts/prepare-sqlx.sh

# 2. Edit the script if your PostgreSQL credentials differ
# Default: postgresql://postgres:postgres@localhost:5432/vulnera_sqlx_prepare

# 3. Run the script
./scripts/prepare-sqlx.sh
```

The script will:
1. Create a temporary database
2. Run migrations
3. Generate `sqlx-data.json`
4. Optionally clean up the temporary database

### Option 3: Use a Development Database

**Best for:** Developers who want to keep a persistent development database.

```bash
# 1. Install SQLx CLI
cargo install sqlx-cli --no-default-features --features postgres

# 2. Set up your database URL
export DATABASE_URL="postgresql://user:password@localhost:5432/vulnera_dev"

# 3. Create the database
sqlx database create

# 4. Run migrations
sqlx migrate run --source migrations

# 5. Generate offline cache
cargo sqlx prepare --workspace

# 6. (Optional) Add to your shell profile for persistence
echo 'export DATABASE_URL="postgresql://user:password@localhost:5432/vulnera_dev"' >> ~/.bashrc
```

## What is sqlx-data.json?

The `sqlx-data.json` file contains metadata about your SQL queries:
- Query text
- Expected parameter types
- Result column types and names

This allows SQLx to perform compile-time verification **without** needing a database connection during compilation.

### Should you commit sqlx-data.json?

**Yes!** Committing this file to version control:
- ✅ Allows CI/CD to build without database setup
- ✅ Enables other developers to compile immediately
- ✅ Provides a snapshot of your database schema
- ✅ Makes builds faster and more reliable

**Important:** Regenerate this file whenever you:
- Modify SQL queries in the code
- Add new queries
- Change the database schema (migrations)

## CI/CD Integration

For continuous integration, `sqlx-data.json` allows building without database access:

```yaml
# .github/workflows/ci.yml example
- name: Check compilation
  run: cargo check
  env:
    SQLX_OFFLINE: true  # Use cached query metadata
```

## Environment Variables

### `DATABASE_URL`
- **Purpose:** Connects to database for live query verification
- **Format:** `postgresql://user:password@host:port/database`
- **When needed:** Running migrations, generating sqlx-data.json, or runtime database operations

### `SQLX_OFFLINE`
- **Purpose:** Forces SQLx to use cached metadata instead of connecting to database
- **Values:** `true` or `false`
- **When to use:** CI/CD environments without database access

## Troubleshooting

### Error: "Docker daemon is not running"

**Solution:**
- Start Docker Desktop (macOS/Windows)
- Start Docker service: `sudo systemctl start docker` (Linux)
- Or use Option 2 (Local PostgreSQL) instead

### Error: "PostgreSQL server is not running"

**Solution:**
```bash
# macOS (Homebrew)
brew services start postgresql

# Linux (systemd)
sudo systemctl start postgresql

# Check status
pg_isready
```

### Error: "sqlx-cli not found"

**Solution:**
```bash
cargo install sqlx-cli --no-default-features --features postgres
```

### Error: "permission denied: scripts/prepare-sqlx-docker.sh"

**Solution:**
```bash
chmod +x scripts/prepare-sqlx-docker.sh scripts/prepare-sqlx.sh
```

### Queries still failing after generating sqlx-data.json

**Causes:**
1. SQL query was modified after generation
2. Database schema changed (new migration added)
3. sqlx-data.json is corrupted or incomplete

**Solution:**
```bash
# Regenerate the cache
rm sqlx-data.json
./scripts/prepare-sqlx-docker.sh
```

### Old sqlx-data.json causing type mismatches

**Solution:**
```bash
# Clean and regenerate
rm -f sqlx-data.json
cargo clean
./scripts/prepare-sqlx-docker.sh
cargo check
```

## Development Workflow

### Daily Development
```bash
# Option A: With development database
export DATABASE_URL="postgresql://..."
cargo run

# Option B: Without database (uses cached metadata)
cargo build
```

### After Modifying SQL Queries
```bash
# Regenerate metadata
./scripts/prepare-sqlx-docker.sh

# Commit the updated file
git add sqlx-data.json
git commit -m "Update SQLx query cache"
```

### After Adding Migrations
```bash
# Run migrations on dev database
export DATABASE_URL="postgresql://..."
sqlx migrate run

# Regenerate metadata
./scripts/prepare-sqlx-docker.sh

# Commit both migration and updated cache
git add migrations/ sqlx-data.json
git commit -m "Add new migration and update query cache"
```

## Best Practices

1. **Always regenerate after schema changes:** Keep `sqlx-data.json` in sync with your migrations
2. **Commit sqlx-data.json:** Makes builds reproducible and CI/CD friendly
3. **Review sqlx-data.json diffs:** They show what queries changed
4. **Use Docker script for simplicity:** No local PostgreSQL setup needed
5. **Keep DATABASE_URL secret:** Never commit connection strings with real credentials

## Advanced: Manual Generation

If the scripts don't work for your environment:

```bash
# 1. Set up database manually
createdb vulnera_temp
export DATABASE_URL="postgresql://localhost/vulnera_temp"

# 2. Run migrations
sqlx migrate run --source migrations

# 3. Generate cache
cargo sqlx prepare --workspace

# 4. Cleanup
dropdb vulnera_temp
```

## Additional Resources

- [SQLx Documentation](https://github.com/launchbadge/sqlx)
- [SQLx CLI Guide](https://github.com/launchbadge/sqlx/tree/main/sqlx-cli)
- [Offline Mode Documentation](https://github.com/launchbadge/sqlx/blob/main/sqlx-cli/README.md#enable-building-in-offline-mode)

## Quick Reference

```bash
# Generate query cache (Docker)
./scripts/prepare-sqlx-docker.sh

# Generate query cache (Local PostgreSQL)
./scripts/prepare-sqlx.sh

# Manual generation
export DATABASE_URL="postgresql://..."
cargo sqlx prepare --workspace

# Build with offline mode
SQLX_OFFLINE=true cargo build

# Install SQLx CLI
cargo install sqlx-cli --no-default-features --features postgres
```

## Support

If you encounter issues not covered here:
1. Check the [project issues](https://github.com/your-org/vulnera/issues)
2. Review SQLx's [troubleshooting guide](https://github.com/launchbadge/sqlx/blob/main/FAQ.md)
3. Open a new issue with details about your environment
