#!/usr/bin/env bash
# Back up the ACT database.
#
#   scripts/backup.sh                       # -> backups/act-<UTC>.{sql.gz|db}
#   BACKUP_DIR=/var/backups/act scripts/backup.sh
#   RETENTION_DAYS=14 scripts/backup.sh     # prune backups older than N days
#
# Reads DATABASE_URL (from the environment, or backend/.env if present).
#   postgres  -> pg_dump  (custom format, gzip'd)
#   sqlite    -> a consistent file copy via `sqlite3 .backup` (or cp fallback)
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
BACKUP_DIR="${BACKUP_DIR:-$HERE/backups}"
RETENTION_DAYS="${RETENTION_DAYS:-0}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BACKUP_DIR"

# load DATABASE_URL from backend/.env if not already set
if [ -z "${DATABASE_URL:-}" ] && [ -f "$HERE/backend/.env" ]; then
    DATABASE_URL="$(grep -E '^DATABASE_URL=' "$HERE/backend/.env" | tail -1 | cut -d= -f2- || true)"
fi
DATABASE_URL="${DATABASE_URL:-sqlite:///$HERE/backend/data/act.db}"

case "$DATABASE_URL" in
  postgres*|postgresql*)
    command -v pg_dump >/dev/null || { echo "pg_dump not found" >&2; exit 1; }
    out="$BACKUP_DIR/act-$STAMP.dump"
    # pg_dump understands the URL directly (strip the +driver marker)
    url="$(printf '%s' "$DATABASE_URL" | sed 's/+[a-z0-9]*:/:/')"
    pg_dump --format=custom --no-owner --dbname="$url" --file="$out"
    gzip -f "$out"
    echo "wrote $out.gz"
    ;;
  sqlite*)
    src="${DATABASE_URL#sqlite:///}"
    [ -f "$src" ] || { echo "sqlite file not found: $src" >&2; exit 1; }
    out="$BACKUP_DIR/act-$STAMP.db"
    if command -v sqlite3 >/dev/null; then
        sqlite3 "$src" ".backup '$out'"
    else
        cp "$src" "$out"
    fi
    gzip -f "$out"
    echo "wrote $out.gz"
    ;;
  *)
    echo "unsupported DATABASE_URL: $DATABASE_URL" >&2; exit 1 ;;
esac

if [ "$RETENTION_DAYS" -gt 0 ]; then
    find "$BACKUP_DIR" -name 'act-*.gz' -type f -mtime "+$RETENTION_DAYS" -print -delete
fi
