#!/bin/bash
set -e

# Optional: Run database migrations before starting the application
# Set RUN_MIGRATIONS=true to enable (requires sqlx-cli to be installed in the image)
# 
if [ "${RUN_MIGRATIONS:-false}" = "true" ]; then
    echo "Running database migrations..."
    
    # Check if sqlx-cli is available
    if ! command -v sqlx &> /dev/null; then
        echo "Warning: sqlx-cli not found. Skipping migrations."
        echo "To enable migrations, install sqlx-cli in the Dockerfile or run migrations separately."
        echo "For separate migration job: docker run --rm -e DATABASE_URL=... vulnera-rust sqlx migrate run"
    else
        # Check if DATABASE_URL is set
        if [ -z "${DATABASE_URL}" ]; then
            echo "Error: DATABASE_URL environment variable is not set"
            exit 1
        fi
        
        # Run migrations
        sqlx migrate run --source /app/migrations
        
        echo "Migrations completed successfully"
    fi
fi

# Execute the main command
exec "$@"

