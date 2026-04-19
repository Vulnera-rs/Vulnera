#!/bin/sh
set -e

if [ -z "$SKIP_MIGRATIONS" ] && [ -n "$DATABASE_URL" ]; then
    sqlx migrate run --source /app/migrations
fi

exec "$@"
