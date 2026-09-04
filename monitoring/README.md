# Monitoring ACT

ACT exposes Prometheus metrics at `GET /api/metrics` (see the API section of the
main README). This directory wires up a ready-to-run Prometheus + Grafana.

## Quick start (alongside the Docker stack)

```bash
# main stack first (creates the "act_default" network)
docker compose up -d

docker compose -f monitoring/docker-compose.monitoring.yml up -d
```

- Prometheus: <http://localhost:9090> — target `act-backend:8000/api/metrics`
- Grafana: <http://localhost:3000> (`admin` / `admin` — override with
  `GRAFANA_PASSWORD` in your environment before `up`) — the **ACT Overview**
  dashboard and the Prometheus datasource are provisioned automatically.

If `ACT_METRICS_TOKEN` is set on the backend, add it to `prometheus.yml`
(`params.token` or a Bearer `authorization`).

## Standalone Prometheus

Point any Prometheus at `http(s)://<act-host>/api/metrics`. Import
`grafana/act-overview.json` into an existing Grafana by hand.

## Panels

Request rate & status, rolling p50/p95/p99 latency (and a per-route histogram
quantile), attacks detected, block success/failure, alert rate by platform,
login attempts, live engine gauges (events, behaviours, active/compromised
attack paths), and service-up.

## Tracing

Set `ACT_OTEL_ENABLED=true` and `OTEL_EXPORTER_OTLP_ENDPOINT=http://<collector>:4318`
(and install `backend/requirements-observability.txt`) to export spans to an
OpenTelemetry collector / Tempo / Jaeger. `ACT_OTEL_CONSOLE=true` prints spans
to the log for a quick check.
