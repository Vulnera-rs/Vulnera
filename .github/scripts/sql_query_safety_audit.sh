#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

echo "[sql-safety] Scanning for non-macro SQLx query APIs in production code..."

# Policy: only SQLx checked macros are allowed in production paths.
# Block direct function forms that are easier to misuse with dynamic SQL.
violations="$(rg --no-heading --line-number --glob '!**/tests/**' --glob '!**/benches/**' --glob '!**/*_test.rs' --glob '**/*.rs' 'sqlx::query\s*\(|sqlx::query_as\s*\(|sqlx::query_scalar\s*\(' || true)"

if [[ -n "$violations" ]]; then
  echo
  echo "[sql-safety] ❌ Policy violation detected: use SQLx checked macros (query!, query_as!, query_scalar!) instead of function forms."
  echo "$violations"
  exit 1
fi

echo "[sql-safety] ✅ No unsafe SQLx query function forms found."
