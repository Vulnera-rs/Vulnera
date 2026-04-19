#!/usr/bin/env bash
set -e

echo "Running post-create setup..."

cd /workspaces/vulnera

echo "Installing lefthook..."
if ! command -v lefthook &> /dev/null; then
    curl -sSf https://get.lefthook.dev/ | sh
    echo "Lefthook installed."
else
    echo "Lefthook already installed."
fi

echo "Running database migrations..."
if [ -n "$DATABASE_URL" ]; then
    sqlx migrate run --source /workspaces/vulnera/migrations || echo "Migration skipped (may already be applied)."
else
    echo "DATABASE_URL not set, skipping migrations."
fi

echo "Installing lefthook hooks..."
lefthook install 2>/dev/null || echo "Lefthook install skipped."

echo "Verifying Rust toolchain..."
rustc --version
cargo --version

echo "Post-create setup complete."
