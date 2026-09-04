"""Phase 5: backup/restore scripts + Grafana/Prometheus assets exist and fit."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _read(rel: str) -> str:
    p = ROOT / rel
    assert p.exists(), f"missing: {rel}"
    return p.read_text(encoding="utf-8")


@pytest.mark.parametrize("rel", [
    "scripts/backup.sh",
    "scripts/restore.sh",
    "monitoring/prometheus.yml",
    "monitoring/docker-compose.monitoring.yml",
    "monitoring/grafana/act-overview.json",
    "monitoring/grafana/provisioning/datasources/prometheus.yml",
    "monitoring/grafana/provisioning/dashboards/act.yml",
    "monitoring/README.md",
    "backend/requirements-observability.txt",
])
def test_present(rel):
    assert _read(rel).strip()


def test_backup_handles_both_engines():
    sh = _read("scripts/backup.sh")
    assert "pg_dump" in sh and "sqlite" in sh
    assert "RETENTION_DAYS" in sh


def test_restore_is_guarded():
    sh = _read("scripts/restore.sh")
    assert "pg_restore" in sh
    assert "YES" in sh                       # confirmation prompt
    assert "pre-restore" in sh               # keeps the previous sqlite file


def test_prometheus_scrapes_the_metrics_path():
    y = _read("monitoring/prometheus.yml")
    assert "/api/metrics" in y and "act-backend:8000" in y


def test_grafana_dashboard_is_valid_json_and_targets_act_metrics():
    dash = json.loads(_read("monitoring/grafana/act-overview.json"))
    assert dash["title"] == "ACT Overview"
    exprs = " ".join(
        t.get("expr", "")
        for p in dash["panels"] for t in p.get("targets", [])
    )
    for metric in ("act_up", "act_http_requests_total", "act_blocks_total",
                   "act_active_attack_paths", "act_login_attempts_total"):
        assert metric in exprs, metric


def test_observability_extras_pin_versions():
    reqs = _read("backend/requirements-observability.txt")
    assert "opentelemetry-sdk==" in reqs
    assert "sentry-sdk==" in reqs
