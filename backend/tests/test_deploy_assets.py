"""Phase 4: the deployment assets exist and say what the docs claim.

Text-level checks only (no docker / systemd on the test host) - enough to catch
a renamed service, a dropped healthcheck or a broken reference.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _read(rel: str) -> str:
    path = ROOT / rel
    assert path.exists(), f"missing deployment asset: {rel}"
    return path.read_text(encoding="utf-8")


@pytest.mark.parametrize("rel", [
    "docker-compose.yml",
    "backend/Dockerfile",
    "backend/docker-entrypoint.sh",
    "backend/.dockerignore",
    "frontend/Dockerfile",
    "frontend/nginx.conf",
    "frontend/.dockerignore",
    ".dockerignore",
    ".env.docker.example",
    "systemd/act.service",
    "windows/Install-ActService.ps1",
    "scripts/letsencrypt.sh",
    "scripts/gen-dev-cert.sh",
    "backend/pyproject.toml",
])
def test_asset_present(rel):
    assert _read(rel).strip()


def test_compose_defines_the_four_core_services():
    compose = _read("docker-compose.yml")
    for name in ("postgres:", "act-backend:", "act-frontend:", "ollama:"):
        assert name in compose
    assert "pg_isready" in compose
    assert "/api/health" in compose                 # backend healthcheck
    assert "profiles:" in compose                   # optional pgadmin / ollama


def test_backend_dockerfile_runs_service_mode():
    df = _read("backend/Dockerfile")
    assert "python:3.11-slim" in df
    assert '"--mode", "service"' in df
    assert "HEALTHCHECK" in df
    assert "USER act" in df                         # non-root


def test_entrypoint_migrates_before_serving():
    sh = _read("backend/docker-entrypoint.sh")
    assert "alembic upgrade head" in sh
    assert 'exec "$@"' in sh


def test_systemd_unit_restarts_and_uses_service_mode():
    unit = _read("systemd/act.service")
    assert "Restart=on-failure" in unit
    assert "--mode service" in unit
    assert "alembic upgrade head" in unit           # ExecStartPre
    assert "WantedBy=multi-user.target" in unit


def test_nginx_proxies_api_and_upgrades_websockets():
    conf = _read("frontend/nginx.conf")
    assert "proxy_pass" in conf and "${ACT_BACKEND_URL}" in conf
    assert "$connection_upgrade" in conf
    assert "/healthz" in conf


def test_pyproject_exposes_the_act_command():
    assert 'act = "app.main:main"' in _read("backend/pyproject.toml")
