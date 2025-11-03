#!/bin/bash
# SQLx Offline Mode Preparation Script
# This script sets up a temporary PostgreSQL database, runs migrations,
# and generates sqlx-data.json for offline compilation

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DATABASE_NAME="vulnera_sqlx_prepare"
DATABASE_URL="postgresql://postgres:postgres@localhost:5432/${DATABASE_NAME}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== SQLx Offline Mode Preparation ===${NC}"

# Check if PostgreSQL is available
if ! command -v psql &> /dev/null; then
    echo -e "${RED}Error: PostgreSQL client (psql) not found${NC}"
    echo "Please install PostgreSQL or ensure it's in your PATH"
    exit 1
fi

# Check if sqlx-cli is installed
if ! command -v sqlx &> /dev/null; then
    echo -e "${YELLOW}Installing sqlx-cli...${NC}"
    cargo install sqlx-cli --no-default-features --features postgres
fi

# Function to check if PostgreSQL server is running
check_postgres() {
    if ! pg_isready -h localhost -p 5432 &> /dev/null; then
        echo -e "${RED}Error: PostgreSQL server is not running on localhost:5432${NC}"
        echo "Please start PostgreSQL server or update DATABASE_URL in this script"
        exit 1
    fi
}

# Function to create database
create_database() {
    echo -e "${YELLOW}Creating temporary database: ${DATABASE_NAME}${NC}"

    # Drop if exists and create fresh
    psql -h localhost -U postgres -c "DROP DATABASE IF EXISTS ${DATABASE_NAME};" 2>/dev/null || true
    psql -h localhost -U postgres -c "CREATE DATABASE ${DATABASE_NAME};"

    echo -e "${GREEN}Database created successfully${NC}"
}

# Function to run migrations
run_migrations() {
    echo -e "${YELLOW}Running database migrations...${NC}"
    cd "$PROJECT_ROOT"

    export DATABASE_URL
    sqlx migrate run --source migrations

    echo -e "${GREEN}Migrations completed successfully${NC}"
}

# Function to prepare SQLx offline mode
prepare_sqlx() {
    echo -e "${YELLOW}Generating sqlx-data.json for offline compilation...${NC}"
    cd "$PROJECT_ROOT"

    export DATABASE_URL
    cargo sqlx prepare --workspace

    echo -e "${GREEN}sqlx-data.json generated successfully${NC}"
}

# Function to cleanup
cleanup() {
    echo -e "${YELLOW}Cleaning up temporary database...${NC}"
    psql -h localhost -U postgres -c "DROP DATABASE IF EXISTS ${DATABASE_NAME};" 2>/dev/null || true
    echo -e "${GREEN}Cleanup completed${NC}"
}

# Main execution
main() {
    echo -e "${YELLOW}Checking PostgreSQL availability...${NC}"
    check_postgres

    create_database
    run_migrations
    prepare_sqlx

    echo ""
    echo -e "${GREEN}=== SQLx preparation completed successfully! ===${NC}"
    echo -e "${GREEN}You can now compile the project without DATABASE_URL set${NC}"
    echo ""
    echo -e "${YELLOW}Note: If you modify any SQL queries, you'll need to run this script again${NC}"

    # Ask user if they want to cleanup
    read -p "Do you want to drop the temporary database? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cleanup
    else
        echo -e "${YELLOW}Keeping database ${DATABASE_NAME} for reference${NC}"
    fi
}

# Trap errors and cleanup
trap 'echo -e "${RED}An error occurred. You may need to manually drop the database: DROP DATABASE ${DATABASE_NAME};${NC}"' ERR

# Run main function
main
