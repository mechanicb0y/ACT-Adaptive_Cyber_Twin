# ACT backend — API, dashboard, pipeline.
#
#   docker build -t act-backend backend/
#   docker run --rm -p 8000:8000 --env-file backend/.env act-backend
#
# Normally started via docker-compose.yml at the repo root.

FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    ACT_HOST=0.0.0.0 \
    ACT_PORT=8000 \
    ACT_LOG_FORMAT=json

# openssl: dev TLS cert generation.  curl: container HEALTHCHECK.
# libpq5: runtime for psycopg (Postgres driver).
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl curl libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependencies first for layer caching. psycopg is only needed in the image
# (compose points DATABASE_URL at Postgres); it stays out of requirements.txt.
COPY backend/requirements.txt ./requirements.txt
RUN pip install -r requirements.txt "psycopg[binary]==3.2.3"

COPY backend/ ./
# The pipeline reads ../frontend/index.html relative to the backend tree.
COPY frontend/ ../frontend/

RUN useradd --system --create-home --uid 10001 act \
    && mkdir -p /app/data /app/logs \
    && chown -R act:act /app /frontend
USER act

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${ACT_PORT}/api/health" || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["python", "-m", "app.main", "--mode", "service"]
