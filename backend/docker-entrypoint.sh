#!/bin/sh
set -e

echo "[entrypoint] waiting for the database ..."
python - <<'PY'
import os, sys, time
from sqlalchemy import create_engine, text
url = os.environ["DATABASE_URL"]
for attempt in range(1, 61):
    try:
        create_engine(url).connect().execute(text("SELECT 1"))
        print(f"[entrypoint] database reachable (attempt {attempt})")
        sys.exit(0)
    except Exception as exc:
        print(f"[entrypoint] not ready ({exc.__class__.__name__}); retrying")
        time.sleep(2)
print("[entrypoint] database never became reachable", file=sys.stderr)
sys.exit(1)
PY

echo "[entrypoint] running migrations (alembic upgrade head) ..."
python -m alembic upgrade head

echo "[entrypoint] starting ACT backend ..."
exec "$@"
