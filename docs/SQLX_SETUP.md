# SQLx Database Setup Guide

This guide covers setting up PostgreSQL and running database migrations for Vulnera.

## Prerequisites

- PostgreSQL 12 or higher
- SQLx CLI installed

## Install SQLx CLI

```bash
cargo install sqlx-cli --no-default-features --features postgres
```

## Database Setup

### Option 1: Local PostgreSQL

1. **Create the database:**
   ```bash
   createdb vulnera
   ```

2. **Set the connection URL:**
   ```bash
   export DATABASE_URL='postgresql://username:password@localhost:5432/vulnera'
   ```

3. **Run migrations:**
   ```bash
   sqlx migrate run --source migrations
   ```

### Option 2: Docker PostgreSQL

1. **Start PostgreSQL container:**
   ```bash
   docker run -d \
     --name vulnera-postgres \
     -e POSTGRES_USER=vulnera \
     -e POSTGRES_PASSWORD=password \
     -e POSTGRES_DB=vulnera \
     -p 5432:5432 \
     postgres:15
   ```

2. **Set the connection URL:**
   ```bash
   export DATABASE_URL='postgresql://vulnera:password@localhost:5432/vulnera'
   ```

3. **Run migrations:**
   ```bash
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

You should see all migrations listed with their status.

## Migration Files

Migrations are located in the `migrations/` directory:

- `20240101000001_create_users_table.sql` - Creates users table
- `20240101000002_create_api_keys_table.sql` - Creates API keys table
- `20240101000003_create_updated_at_trigger.sql` - Creates update timestamp trigger

## Development Workflow

### Create a New Migration

```bash
sqlx migrate add --source migrations migration_name
```

This creates a new migration file with timestamp prefix.

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

1. **Backup before migrations:** Always backup your database before running migrations in production
2. **Test migrations:** Test migrations in a staging environment first
3. **Migration order:** Migrations run in order based on timestamp
4. **Rollback plan:** Have a rollback plan for each migration
5. **Connection pooling:** Use connection pooling for production workloads

## Troubleshooting

### Migration Errors

If migrations fail:

1. Check database connection:
   ```bash
   psql $DATABASE_URL -c "SELECT version();"
   ```

2. Verify migration files are present:
   ```bash
   ls -la migrations/
   ```

3. Check migration status:
   ```bash
   sqlx migrate info --source migrations
   ```

### Connection Issues

- Verify PostgreSQL is running: `pg_isready`
- Check connection string format: `postgresql://user:password@host:port/database`
- Ensure database exists: `psql -l | grep vulnera`
- Check firewall/network settings

### Permission Issues

- Ensure database user has CREATE privileges
- Grant necessary permissions:
  ```sql
  GRANT ALL PRIVILEGES ON DATABASE vulnera TO vulnera_user;
  ```

## Environment Variables

The `DATABASE_URL` can be set via:

1. Environment variable:
   ```bash
   export DATABASE_URL='postgresql://user:password@localhost:5432/vulnera'
   ```

2. `.env` file:
   ```bash
   DATABASE_URL='postgresql://user:password@localhost:5432/vulnera'
   ```

3. Configuration file:
   ```toml
   [database]
   url = "postgresql://user:password@localhost:5432/vulnera"
   ```

## Additional Resources

- [SQLx Documentation](https://github.com/launchbadge/sqlx)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Database Configuration Examples](examples/configuration.md#database-configuration)

