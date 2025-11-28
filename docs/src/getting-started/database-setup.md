# Database Setup

This guide covers setting up PostgreSQL and running database migrations for Vulnera.

## Prerequisites

- PostgreSQL 12 or higher
- SQLx CLI installed

## Install SQLx CLI

```bash
cargo install sqlx-cli --no-default-features --features postgres
```

## Database Setup Options

### Option 1: Local PostgreSQL

```bash
# Create the database
createdb vulnera

# Set the connection URL
export DATABASE_URL='postgresql://username:password@localhost:5432/vulnera'

# Run migrations
sqlx migrate run --source migrations
```

### Option 2: Docker PostgreSQL

```bash
# Start PostgreSQL container
docker run -d \
  --name vulnera-postgres \
  -e POSTGRES_USER=vulnera \
  -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=vulnera \
  -p 5432:5432 \
  postgres:15

# Set the connection URL
export DATABASE_URL='postgresql://vulnera:password@localhost:5432/vulnera'

# Run migrations
sqlx migrate run --source migrations
```

### Option 3: Docker Compose

Create a `docker-compose.yml`:

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_USER: vulnera
      POSTGRES_PASSWORD: password
      POSTGRES_DB: vulnera
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

Start services:

```bash
docker-compose up -d
export DATABASE_URL='postgresql://vulnera:password@localhost:5432/vulnera'
sqlx migrate run --source migrations
```

## Verify Setup

Check that migrations ran successfully:

```bash
sqlx migrate info --source migrations
```

## Migration Files

Migrations are located in the `migrations/` directory:

| Migration | Description |
|-----------|-------------|
| `20240101000001_create_users_table.sql` | Creates users table |
| `20240101000002_create_api_keys_table.sql` | Creates API keys table |
| `20240101000003_create_updated_at_trigger.sql` | Creates update timestamp trigger |
| `20250101000004_create_organizations_table.sql` | Creates organizations table |
| `20250101000005_create_organization_members_table.sql` | Creates organization members table |
| `20250101000006_create_persisted_job_results_table.sql` | Creates job results table |
| `20250101000007_create_analysis_events_table.sql` | Creates analysis events table |
| `20250101000008_create_user_stats_monthly_table.sql` | Creates user statistics table |
| `20250101000009_create_subscription_limits_table.sql` | Creates subscription limits table |
| `20250101000010_create_personal_stats_monthly_table.sql` | Creates personal statistics table |

## Development Workflow

### Create a New Migration

```bash
sqlx migrate add --source migrations migration_name
```

### Run Migrations

```bash
sqlx migrate run --source migrations
```

### Revert Last Migration

```bash
sqlx migrate revert --source migrations
```

### Check Migration Status

```bash
sqlx migrate info --source migrations
```

## Production Considerations

1. **Backup before migrations** — Always backup your database before running migrations in production
2. **Test migrations** — Test migrations in a staging environment first
3. **Migration order** — Migrations run in order based on timestamp
4. **Rollback plan** — Have a rollback plan for each migration
5. **Connection pooling** — Use connection pooling for production workloads

## Environment Variables

The `DATABASE_URL` can be set via:

```bash
# Environment variable
export DATABASE_URL='postgresql://user:password@localhost:5432/vulnera'

# .env file
DATABASE_URL='postgresql://user:password@localhost:5432/vulnera'

# Configuration file (config/default.toml)
[database]
url = "postgresql://user:password@localhost:5432/vulnera"
```

## Troubleshooting

### Migration Errors

```bash
# Check database connection
psql $DATABASE_URL -c "SELECT version();"

# Verify migration files
ls -la migrations/

# Check migration status
sqlx migrate info --source migrations
```

### Connection Issues

- Verify PostgreSQL is running: `pg_isready`
- Check connection string format: `postgresql://user:password@host:port/database`
- Ensure database exists: `psql -l | grep vulnera`
- Check firewall/network settings

### Permission Issues

```sql
-- Grant necessary permissions
GRANT ALL PRIVILEGES ON DATABASE vulnera TO vulnera_user;
```
