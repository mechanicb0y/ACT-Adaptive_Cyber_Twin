#!/usr/bin/env bash
# Restore an ACT database backup made by scripts/backup.sh.
#
#   scripts/restore.sh backups/act-20260904T120000Z.dump.gz
#   scripts/restore.sh backups/act-20260904T120000Z.db.gz
#
# DESTRUCTIVE: overwrites the current database. Stop ACT first
# (systemctl stop act  /  docker compose stop act-backend).
set -euo pipefail

FILE="${1:?usage: restore.sh <backup file (.dump.gz | .db.gz)>}"
[ -f "$FILE" ] || { echo "no such file: $FILE" >&2; exit 1; }

HERE="$(cd "$(dirname "$0")/.." && pwd)"
if [ -z "${DATABASE_URL:-}" ] && [ -f "$HERE/backend/.env" ]; then
    DATABASE_URL="$(grep -E '^DATABASE_URL=' "$HERE/backend/.env" | tail -1 | cut -d= -f2- || true)"
fi
DATABASE_URL="${DATABASE_URL:-sqlite:///$HERE/backend/data/act.db}"

printf 'This overwrites %s\nType YES to continue: ' "$DATABASE_URL"
read -r ans; [ "$ans" = "YES" ] || { echo "aborted"; exit 1; }

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
case "$FILE" in
  *.gz) gunzip -c "$FILE" > "$tmp" ;;
  *)    cp "$FILE" "$tmp" ;;
esac

case "$DATABASE_URL" in
  postgres*|postgresql*)
    command -v pg_restore >/dev/null || { echo "pg_restore not found" >&2; exit 1; }
    url="$(printf '%s' "$DATABASE_URL" | sed 's/+[a-z0-9]*:/:/')"
    pg_restore --clean --if-exists --no-owner --dbname="$url" "$tmp"
    echo "restored into $url"
    ;;
  sqlite*)
    dst="${DATABASE_URL#sqlite:///}"
    mkdir -p "$(dirname "$dst")"
    [ -f "$dst" ] && cp "$dst" "$dst.pre-restore.$(date -u +%s)"
    cp "$tmp" "$dst"
    echo "restored $dst (previous file kept as $dst.pre-restore.*)"
    ;;
  *)
    echo "unsupported DATABASE_URL: $DATABASE_URL" >&2; exit 1 ;;
esac

echo "done. Run 'alembic upgrade head' if the backup predates the current schema, then start ACT."
