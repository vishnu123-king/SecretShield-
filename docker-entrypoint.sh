#!/bin/sh
set -e

# Ensure sample git repository fixture exists for zero-config demonstration and scanning
if [ ! -d "tests/fixtures/sample-repository/.git" ]; then
  echo "[SecretShield Docker] Preparing sample git repository fixture..."
  python3 scripts/setup_sample_repo.py >/dev/null 2>&1 || true
fi

# If DATABASE_URL is provided, attempt to push any schema migrations with retry
if [ -n "$DATABASE_URL" ]; then
  echo "[SecretShield Docker] PostgreSQL connection detected."
  echo "[SecretShield Docker] Syncing database schema with Drizzle..."
  RETRY_COUNT=0
  MAX_RETRIES=5
  until npm run db:push || [ $RETRY_COUNT -ge $MAX_RETRIES ]; do
    RETRY_COUNT=$((RETRY_COUNT+1))
    echo "[SecretShield Docker] Waiting for database to accept connections... attempt $RETRY_COUNT of $MAX_RETRIES"
    sleep 3
  done
  if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
    echo "[SecretShield Docker] Notice: Database push timed out or will initialize on demand. Proceeding with service boot."
  else
    echo "[SecretShield Docker] Database schema synced successfully."
  fi
fi

# Hand over to CMD (npm start)
exec "$@"
